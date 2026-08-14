"""Tests for Aikido supplemental root-CA support.

Aikido Endpoint Protection performs *selective* TLS interception on top of a
primary provider (WARP/Netskope). fumitm detects it and adds the Aikido root to
every managed bundle/keystore/VM alongside the primary root, never replacing it.
These tests cover detection, root extraction (root kept, ephemeral intermediate
rejected), additive bundle assembly, idempotency, and the absent-Aikido no-op.
"""

import contextlib
import os
import stat
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

import mock_data
from helpers import FumitmTestCase


class TestAikidoDetection(FumitmTestCase):
    """Tests for _detect_aikido() across each signal and the all-absent case."""

    def _instance(self):
        # no_aikido=True keeps construction from touching the host; we call the
        # detection method directly under explicit patches below.
        return self.create_fumitm_instance(provider='warp', no_aikido=True)

    def test_detected_via_support_dir(self):
        inst = self._instance()
        with patch('fumitm.os.path.isdir', return_value=True):
            assert inst._detect_aikido() is True

    def test_detected_via_combined_pem(self):
        inst = self._instance()
        with patch('fumitm.os.path.isdir', return_value=False), \
             patch('fumitm.os.path.exists',
                   side_effect=lambda p: p == mock_data.AIKIDO_COMBINED_PEM):
            assert inst._detect_aikido() is True

    def test_detected_via_keychain(self):
        inst = self._instance()
        hit = MagicMock(returncode=0, stdout='cert')
        with patch('fumitm.os.path.isdir', return_value=False), \
             patch('fumitm.os.path.exists', return_value=False), \
             patch('fumitm.platform.system', return_value='Darwin'), \
             patch('fumitm.subprocess.run', return_value=hit):
            assert inst._detect_aikido() is True

    def test_not_detected_when_all_absent(self):
        inst = self._instance()
        miss = MagicMock(returncode=1, stdout='')
        with patch('fumitm.os.path.isdir', return_value=False), \
             patch('fumitm.os.path.exists', return_value=False), \
             patch('fumitm.platform.system', return_value='Darwin'), \
             patch('fumitm.subprocess.run', return_value=miss):
            assert inst._detect_aikido() is False

    def test_linux_skips_keychain(self):
        """On Linux only the filesystem signals are consulted (no keychain)."""
        inst = self._instance()
        with patch('fumitm.os.path.isdir', return_value=False), \
             patch('fumitm.os.path.exists', return_value=False), \
             patch('fumitm.platform.system', return_value='Linux'), \
             patch('fumitm.subprocess.run') as mock_run:
            assert inst._detect_aikido() is False
            mock_run.assert_not_called()


def _fake_subject(block):
    """Map a mock PEM block to its openssl subject line by body marker."""
    if 'AIKIDOROOT' in block:
        return f'subject=CN={mock_data.AIKIDO_ROOT_CN}'
    if 'AIKIDOINTERMEDIATE' in block:
        return f'subject=CN={mock_data.AIKIDO_INTERMEDIATE_CN}'
    return None


class TestAikidoCnFilter(FumitmTestCase):
    """Tests that the CN-prefix filter keeps the root and rejects the intermediate."""

    def test_keeps_root_rejects_intermediate(self):
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        with patch.object(inst, '_openssl_subject', side_effect=_fake_subject):
            kept = inst._filter_certs_by_cn_prefix(
                mock_data.MOCK_AIKIDO_KEYCHAIN_OUTPUT,
                'Aikido Endpoint Protection Root CA',
            )
        assert len(kept) == 1
        assert 'AIKIDOROOT' in kept[0]
        assert 'AIKIDOINTERMEDIATE' not in kept[0]

    def test_subject_common_name_parses_all_forms(self):
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        # RFC 2253, OpenSSL 3 spaced, and LibreSSL slash forms all parse.
        assert inst._subject_common_name('subject=CN=Foo Bar,O=Org') == 'Foo Bar'
        assert inst._subject_common_name('subject=CN = Foo Bar, O = Org') == 'Foo Bar'
        assert inst._subject_common_name('subject= /CN=Foo Bar/O=Org') == 'Foo Bar'
        assert inst._subject_common_name('subject=O=Org') is None


class TestAikidoRootExtraction(FumitmTestCase):
    """Tests for _get_aikido_root_cert() keychain and combined-PEM paths."""

    def test_keychain_returns_only_root(self):
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        keychain = MagicMock(returncode=0, stdout=mock_data.MOCK_AIKIDO_KEYCHAIN_OUTPUT)
        with patch('fumitm.platform.system', return_value='Darwin'), \
             patch('fumitm.subprocess.run', return_value=keychain), \
             patch.object(inst, '_openssl_subject', side_effect=_fake_subject):
            result = inst._get_aikido_root_cert()
        assert result is not None
        assert 'AIKIDOROOT' in result
        assert 'AIKIDOINTERMEDIATE' not in result

    def test_combined_pem_fallback(self):
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        # Keychain misses; the combined PEM on disk provides the root.
        miss = MagicMock(returncode=1, stdout='')
        with patch('fumitm.platform.system', return_value='Darwin'), \
             patch('fumitm.subprocess.run', return_value=miss), \
             patch('fumitm.os.path.exists', return_value=True), \
             patch('builtins.open',
                   mock_open(read_data=mock_data.MOCK_AIKIDO_KEYCHAIN_OUTPUT)), \
             patch.object(inst, '_openssl_subject', side_effect=_fake_subject):
            result = inst._get_aikido_root_cert()
        assert result is not None
        assert 'AIKIDOROOT' in result
        assert 'AIKIDOINTERMEDIATE' not in result

    def test_returns_none_when_unavailable(self):
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        miss = MagicMock(returncode=1, stdout='')
        with patch('fumitm.platform.system', return_value='Darwin'), \
             patch('fumitm.subprocess.run', return_value=miss), \
             patch('fumitm.os.path.exists', return_value=False):
            assert inst._get_aikido_root_cert() is None


def _aikido_instance_with_root(root_path):
    """Build a WARP instance carrying a materialized Aikido supplemental root."""
    inst = FumitmTestCase.create_fumitm_instance(provider='warp', no_aikido=True)
    inst.extra_roots = [{
        'key': 'aikido',
        'name': 'Aikido Endpoint Protection',
        'short_name': 'Aikido',
        'keytool_alias': 'aikido-root',
        'container_cert_name': 'aikido',
        'path': str(root_path),
    }]
    return inst


class TestAikidoBundleAssembly(FumitmTestCase):
    """Bundle/keystore/container accessors include both roots, additively."""

    def test_all_proxy_roots_appended_without_duplicates(self, tmp_path):
        primary = tmp_path / 'primary.pem'
        primary.write_text(mock_data.MOCK_CERTIFICATE)
        aikido = tmp_path / 'aikido.pem'
        aikido.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)
        target = tmp_path / 'bundle.pem'
        target.write_text('')

        inst = _aikido_instance_with_root(aikido)
        inst.cert_path = str(primary)

        assert inst._append_all_proxy_roots(str(target)) is True
        body = target.read_text()
        assert mock_data.MOCK_CERTIFICATE.strip() in body
        assert mock_data.MOCK_AIKIDO_ROOT_CERT.strip() in body
        # Exactly two certificate blocks: primary + Aikido, no public roots here.
        assert body.count('-----BEGIN CERTIFICATE-----') == 2

        # Second pass is idempotent: no duplicate appends.
        inst._append_all_proxy_roots(str(target))
        assert target.read_text().count('-----BEGIN CERTIFICATE-----') == 2

    def test_all_proxy_root_paths_includes_both(self, tmp_path):
        aikido = tmp_path / 'aikido.pem'
        aikido.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)
        inst = _aikido_instance_with_root(aikido)
        inst.cert_path = '/home/user/.cloudflare-ca.pem'
        paths = inst._all_proxy_root_paths()
        assert paths == ['/home/user/.cloudflare-ca.pem', str(aikido)]

    def test_root_aliases_and_container_certs(self, tmp_path):
        aikido = tmp_path / 'aikido.pem'
        aikido.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)
        inst = _aikido_instance_with_root(aikido)
        aliases = dict(inst._all_root_aliases())
        assert aliases['cloudflare-zerotrust'] == inst.cert_path
        assert aliases['aikido-root'] == str(aikido)
        names = dict(inst._all_container_certs())
        assert names['cloudflare-warp'] == inst.cert_path
        assert names['aikido'] == str(aikido)


class TestAikidoIdempotency(FumitmTestCase):
    """A bundle missing the Aikido root is incomplete; with both it is healthy."""

    def test_missing_aikido_flagged_incomplete(self, tmp_path):
        primary = tmp_path / 'primary.pem'
        primary.write_text(mock_data.MOCK_CERTIFICATE)
        aikido = tmp_path / 'aikido.pem'
        aikido.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)

        only_primary = tmp_path / 'only_primary.pem'
        only_primary.write_text(mock_data.MOCK_CERTIFICATE)
        both = tmp_path / 'both.pem'
        both.write_text(mock_data.MOCK_CERTIFICATE + '\n' + mock_data.MOCK_AIKIDO_ROOT_CERT)

        inst = _aikido_instance_with_root(aikido)
        inst.cert_path = str(primary)

        assert inst._all_roots_present_in_file(str(only_primary)) is False
        assert inst._all_roots_present_in_file(str(both)) is True


class TestAikidoAbsentNoOp(FumitmTestCase):
    """With Aikido absent, accessors reduce to the single primary root."""

    def test_no_extra_roots(self):
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        assert inst.extra_roots == []
        assert inst._all_proxy_root_paths() == [inst.cert_path]
        assert inst._all_root_aliases() == [('cloudflare-zerotrust', inst.cert_path)]
        assert inst._all_container_certs() == [('cloudflare-warp', inst.cert_path)]

    def test_append_matches_single_root(self, tmp_path):
        primary = tmp_path / 'primary.pem'
        primary.write_text(mock_data.MOCK_CERTIFICATE)
        target = tmp_path / 'bundle.pem'
        target.write_text('')
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        inst.cert_path = str(primary)
        inst._append_all_proxy_roots(str(target))
        assert target.read_text().count('BEGIN CERTIFICATE') == 1


class TestVendorInjectedBundle(FumitmTestCase):
    """fumitm ignores a vendor-injected REQUESTS_CA_BUNDLE and builds its own."""

    def test_is_vendor_injected_bundle(self):
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        assert inst._is_vendor_injected_bundle(mock_data.AIKIDO_COMBINED_PEM) is True
        assert inst._is_vendor_injected_bundle(
            mock_data.AIKIDO_SUPPORT_DIR + 'anything.pem') is True
        assert inst._is_vendor_injected_bundle('/Users/x/.python-ca-bundle.pem') is False

    def test_setup_python_ignores_vendor_bundle_and_includes_all_roots(
            self, tmp_path, monkeypatch):
        primary = tmp_path / 'primary.pem'
        primary.write_text(mock_data.MOCK_CERTIFICATE)
        aikido = tmp_path / 'aikido.pem'
        aikido.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)
        home = tmp_path / 'home'
        home.mkdir()

        monkeypatch.setenv('HOME', str(home))
        # Aikido injects its own unwritable combined PEM at runtime.
        monkeypatch.setenv('REQUESTS_CA_BUNDLE', mock_data.AIKIDO_COMBINED_PEM)
        monkeypatch.delenv('SSL_CERT_FILE', raising=False)
        monkeypatch.delenv('CURL_CA_BUNDLE', raising=False)

        inst = _aikido_instance_with_root(aikido)
        inst.mode = 'install'
        inst.cert_path = str(primary)

        def seed_system_certs(path):
            with open(path, 'w') as f:
                f.write('-----BEGIN CERTIFICATE-----\nSYSTEMROOT\n-----END CERTIFICATE-----\n')
            return True

        with patch.object(inst, 'command_exists',
                          side_effect=lambda c: c == 'python3'), \
             patch.object(inst, 'detect_shell', return_value='zsh'), \
             patch.object(inst, 'get_shell_config', return_value=str(home / '.zshrc')), \
             patch.object(inst, 'add_to_shell_config'), \
             patch.object(inst, 'create_bundle_with_system_certs',
                          side_effect=seed_system_certs):
            result = inst.setup_python_cert()

        bundle = home / '.python-ca-bundle.pem'
        assert bundle.exists(), "fumitm-managed bundle was not created"
        body = bundle.read_text()
        # Public roots (seeded), primary provider root, and Aikido root all present.
        assert 'SYSTEMROOT' in body
        assert mock_data.MOCK_CERTIFICATE.strip() in body
        assert mock_data.MOCK_AIKIDO_ROOT_CERT.strip() in body
        assert result.status == 'configured'


class TestAikidoResolution(FumitmTestCase):
    """--with-aikido forces on; --no-aikido forces off; detection gates the rest."""

    def test_with_aikido_forces_on_without_detection(self):
        inst = self.create_fumitm_instance(provider='warp', no_aikido=False,
                                           with_aikido=True)
        assert any(e['key'] == 'aikido' for e in inst.extra_roots)

    def test_no_aikido_forces_off_even_when_detected(self):
        # Construct with no_aikido=True; detection must not be consulted.
        with patch('fumitm.FumitmPython._detect_aikido', return_value=True):
            inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        assert inst.extra_roots == []

    def test_auto_detect_populates_extra_roots(self):
        with patch('fumitm.FumitmPython._detect_aikido', return_value=True):
            inst = self.create_fumitm_instance(provider='warp', no_aikido=False)
        assert any(e['key'] == 'aikido' for e in inst.extra_roots)

    def test_explicit_cert_file_implies_aikido_active(self, tmp_path):
        """--aikido-cert forces Aikido on without auto-detection."""
        cert = tmp_path / 'aikido-root.pem'
        cert.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)
        with patch('fumitm.FumitmPython._detect_aikido', return_value=False):
            inst = self.create_fumitm_instance(provider='warp', no_aikido=False,
                                               aikido_cert_file=str(cert))
        assert any(e['key'] == 'aikido' for e in inst.extra_roots)


class TestAikidoForcedSources(FumitmTestCase):
    """--with-aikido must work without a live agent: explicit file or persisted root."""

    def test_explicit_cert_file_used_when_agent_absent(self, tmp_path):
        """An operator-supplied PEM is the preferred source and bypasses the agent."""
        cert = tmp_path / 'aikido-root.pem'
        cert.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True,
                                           aikido_cert_file=str(cert))
        # Explicit source is consulted before keychain/PEM, so the no-agent host
        # (Linux, no keychain) still yields the root.
        with patch('fumitm.platform.system', return_value='Linux'), \
             patch.object(inst, '_openssl_subject', side_effect=_fake_subject):
            result = inst._get_aikido_root_cert()
        assert result is not None
        assert 'AIKIDOROOT' in result
        assert 'AIKIDOINTERMEDIATE' not in result

    def test_persisted_root_used_when_agent_absent(self, tmp_path, monkeypatch):
        """A root saved by an earlier run is used when keychain and PEM are gone."""
        monkeypatch.setenv('HOME', str(tmp_path))
        persisted = tmp_path / '.aikido-ca.pem'
        persisted.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        miss = MagicMock(returncode=1, stdout='')
        # Keychain misses and the combined PEM is treated as absent; only the
        # persisted ~/.aikido-ca.pem remains.
        with patch('fumitm.platform.system', return_value='Darwin'), \
             patch('fumitm.subprocess.run', return_value=miss), \
             patch('fumitm.os.path.exists', side_effect=lambda p: p == str(persisted)), \
             patch.object(inst, '_openssl_subject', side_effect=_fake_subject):
            result = inst._get_aikido_root_cert()
        assert result is not None
        assert 'AIKIDOROOT' in result

    def test_explicit_cert_with_no_matching_root_falls_through(self, tmp_path, monkeypatch):
        """An explicit file lacking an Aikido root warns and yields nothing usable."""
        monkeypatch.setenv('HOME', str(tmp_path))
        cert = tmp_path / 'unrelated.pem'
        cert.write_text(mock_data.MOCK_CERTIFICATE)
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True,
                                           aikido_cert_file=str(cert))
        miss = MagicMock(returncode=1, stdout='')
        with patch('fumitm.platform.system', return_value='Darwin'), \
             patch('fumitm.subprocess.run', return_value=miss), \
             patch('fumitm.os.path.exists', side_effect=lambda p: p == str(cert)), \
             patch.object(inst, '_openssl_subject', side_effect=_fake_subject):
            # The primary cert's CN does not start with the Aikido prefix, so the
            # filter drops it and no other source is available.
            assert inst._get_aikido_root_cert() is None


class TestAikidoContainerStatus(FumitmTestCase):
    """Container status checks each root in its own split file, not all in one."""

    def test_split_files_checked_separately(self, tmp_path):
        certs_dir = tmp_path / 'certs.d'
        certs_dir.mkdir()
        primary_temp = tmp_path / 'primary_temp.pem'
        primary_temp.write_text(mock_data.MOCK_CERTIFICATE)
        aikido = tmp_path / 'aikido.pem'
        aikido.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)
        inst = _aikido_instance_with_root(aikido)

        # Only the primary split file is present: the supplemental root is still
        # missing, so the persistent location is incomplete.
        (certs_dir / 'cloudflare-warp.crt').write_text(mock_data.MOCK_CERTIFICATE)
        assert inst._status_container_certs_present(
            str(primary_temp), str(certs_dir)) is False

        # Adding the Aikido split file completes it.
        (certs_dir / 'aikido.crt').write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)
        assert inst._status_container_certs_present(
            str(primary_temp), str(certs_dir)) is True

    def test_reduces_to_single_root_without_aikido(self, tmp_path):
        certs_dir = tmp_path / 'certs.d'
        certs_dir.mkdir()
        primary_temp = tmp_path / 'primary_temp.pem'
        primary_temp.write_text(mock_data.MOCK_CERTIFICATE)
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)

        assert inst._status_container_certs_present(
            str(primary_temp), str(certs_dir)) is False
        (certs_dir / 'cloudflare-warp.crt').write_text(mock_data.MOCK_CERTIFICATE)
        assert inst._status_container_certs_present(
            str(primary_temp), str(certs_dir)) is True


class TestAikidoBrewPostinstall(FumitmTestCase):
    """brew regenerates from the keychain; supplemental roots are appended directly."""

    def test_appends_supplemental_root_brew_omitted(self, tmp_path):
        primary = tmp_path / 'primary.pem'
        primary.write_text(mock_data.MOCK_CERTIFICATE)
        aikido = tmp_path / 'aikido.pem'
        aikido.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)
        # brew rebuilds the bundle from the keychain and includes only the
        # primary provider root (Aikido lives in the combined PEM, not the keychain).
        bundle = tmp_path / 'cert.pem'
        bundle.write_text(mock_data.MOCK_CERTIFICATE + '\n')

        inst = _aikido_instance_with_root(aikido)
        inst.cert_path = str(primary)
        inst.mode = 'install'

        ok = MagicMock(returncode=0, stdout='', stderr='')
        with patch('fumitm.subprocess.run', return_value=ok):
            result = inst._run_brew_postinstall(str(bundle))

        assert result.status == 'configured'
        body = bundle.read_text()
        assert mock_data.MOCK_CERTIFICATE.strip() in body
        assert mock_data.MOCK_AIKIDO_ROOT_CERT.strip() in body

    def test_fails_when_primary_root_absent(self, tmp_path):
        primary = tmp_path / 'primary.pem'
        primary.write_text(mock_data.MOCK_CERTIFICATE)
        # brew succeeds but the proxy CA is not in the keychain, so the bundle
        # never gains the primary root.
        bundle = tmp_path / 'cert.pem'
        bundle.write_text('-----BEGIN CERTIFICATE-----\nOTHER\n-----END CERTIFICATE-----\n')

        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        inst.cert_path = str(primary)
        inst.mode = 'install'

        ok = MagicMock(returncode=0, stdout='', stderr='')
        with patch('fumitm.subprocess.run', return_value=ok):
            result = inst._run_brew_postinstall(str(bundle))
        assert result.status == 'failed'

    def test_appends_provider_intermediate_brew_omitted(self, tmp_path):
        # Netskope's cert_path is a combined root+intermediate PEM. brew rebuilds
        # the bundle from the keychain, which holds only the root, so the
        # intermediate is dropped. Because the root *was* sourced, this is not a
        # keychain failure: the intermediate must be topped up, not reported as
        # failed. The second block stands in for a provider intermediate.
        combined = tmp_path / 'combined.pem'
        combined.write_text(
            mock_data.MOCK_CERTIFICATE + '\n'
            + mock_data.MOCK_AIKIDO_INTERMEDIATE_CERT
        )
        bundle = tmp_path / 'cert.pem'
        bundle.write_text(mock_data.MOCK_CERTIFICATE + '\n')

        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        inst.cert_path = str(combined)
        inst.mode = 'install'

        ok = MagicMock(returncode=0, stdout='', stderr='')
        with patch('fumitm.subprocess.run', return_value=ok):
            result = inst._run_brew_postinstall(str(bundle))

        assert result.status == 'configured'
        body = bundle.read_text()
        assert mock_data.MOCK_CERTIFICATE.strip() in body
        assert mock_data.MOCK_AIKIDO_INTERMEDIATE_CERT.strip() in body


def _seed_system_certs(path):
    """Stand-in for create_bundle_with_system_certs: seed a public-root marker."""
    with open(path, 'w') as f:
        f.write('-----BEGIN CERTIFICATE-----\nSYSTEMROOT\n-----END CERTIFICATE-----\n')
    return True


class TestAikidoPythonTrustVars(FumitmTestCase):
    """With Aikido active, setup_python_cert reclaims the vendor-set Python vars."""

    def test_vendor_vars_exported_to_both_roots_bundle(self, tmp_path, monkeypatch):
        home = tmp_path / 'home'
        home.mkdir()
        monkeypatch.setenv('HOME', str(home))
        for var in ('REQUESTS_CA_BUNDLE', 'SSL_CERT_FILE', 'CURL_CA_BUNDLE',
                    'PIP_CERT', 'POETRY_CERTIFICATES_PYPI_CERT', 'BUNDLE_SSL_CA_CERT'):
            monkeypatch.delenv(var, raising=False)

        primary = tmp_path / 'primary.pem'
        primary.write_text(mock_data.MOCK_CERTIFICATE)
        aikido = tmp_path / 'aikido.pem'
        aikido.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)
        shell_config = home / '.zshrc'

        inst = _aikido_instance_with_root(aikido)
        inst.mode = 'install'
        inst.cert_path = str(primary)

        with patch.object(inst, 'command_exists', side_effect=lambda c: c == 'python3'), \
             patch.object(inst, 'detect_shell', return_value='zsh'), \
             patch.object(inst, 'get_shell_config', return_value=str(shell_config)), \
             patch.object(inst, 'create_bundle_with_system_certs',
                          side_effect=_seed_system_certs):
            result = inst.setup_python_cert()

        python_bundle = str(home / '.python-ca-bundle.pem')
        env = Path(inst._env_file_path()).read_text()
        for var in ('SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
                    'PIP_CERT', 'POETRY_CERTIFICATES_PYPI_CERT', 'BUNDLE_SSL_CA_CERT'):
            assert f'export {var}="{python_bundle}"' in env
        # All six live in the single sourced env file, behind one stub.
        assert shell_config.read_text().count(inst._FUMITM_BLOCK_BEGIN) == 1
        assert result.status == 'configured'

    def test_suspicious_requests_bundle_still_reclaims_vendor_vars(
            self, tmp_path, monkeypatch):
        # A writable but suspicious REQUESTS_CA_BUNDLE used to return early after
        # repointing only the three core vars, leaving PIP_CERT/Poetry/Bundler at
        # the vendor bundle. The suspicious path must now fall through to the
        # trust-var post-pass so every Python var lands on the both-roots bundle.
        home = tmp_path / 'home'
        home.mkdir()
        monkeypatch.setenv('HOME', str(home))

        suspicious = tmp_path / 'vendor-only.pem'
        suspicious.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)  # single cert -> suspicious
        monkeypatch.setenv('REQUESTS_CA_BUNDLE', str(suspicious))
        monkeypatch.setenv('PIP_CERT', str(suspicious))
        for var in ('SSL_CERT_FILE', 'CURL_CA_BUNDLE',
                    'POETRY_CERTIFICATES_PYPI_CERT', 'BUNDLE_SSL_CA_CERT'):
            monkeypatch.delenv(var, raising=False)

        primary = tmp_path / 'primary.pem'
        primary.write_text(mock_data.MOCK_CERTIFICATE)
        aikido = tmp_path / 'aikido.pem'
        aikido.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)
        shell_config = home / '.zshrc'

        inst = _aikido_instance_with_root(aikido)
        inst.mode = 'install'
        inst.cert_path = str(primary)

        with patch.object(inst, 'command_exists', side_effect=lambda c: c == 'python3'), \
             patch.object(inst, 'detect_shell', return_value='zsh'), \
             patch.object(inst, 'get_shell_config', return_value=str(shell_config)), \
             patch.object(inst, 'create_bundle_with_system_certs',
                          side_effect=_seed_system_certs):
            result = inst.setup_python_cert()

        python_bundle = str(home / '.python-ca-bundle.pem')
        env = Path(inst._env_file_path()).read_text()
        for var in ('SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
                    'PIP_CERT', 'POETRY_CERTIFICATES_PYPI_CERT', 'BUNDLE_SSL_CA_CERT'):
            assert f'export {var}="{python_bundle}"' in env
        # The vendor bundle is no longer referenced by any managed export.
        assert str(suspicious) not in env
        assert result.status == 'configured'


class TestAikidoGcloudReauthTrust(FumitmTestCase):
    """With Aikido active, setup_gcloud_cert reclaims the reauth trust vars.

    gcloud's reauth handshake runs through the bundled requests library, which
    honors REQUESTS_CA_BUNDLE then CURL_CA_BUNDLE rather than
    core/custom_ca_certs_file. Aikido exports both at its own bundle, which lacks
    the primary proxy root, so reauth fails with "self-signed certificate in
    certificate chain" even when the gcloud property is correct. The gcloud setup
    must therefore re-assert both vars at the both-roots bundle.
    """

    def test_reauth_vars_reclaimed_when_aikido_active(self, tmp_path, monkeypatch):
        home = tmp_path / 'home'
        home.mkdir()
        monkeypatch.setenv('HOME', str(home))
        python_bundle = home / '.python-ca-bundle.pem'
        python_bundle.write_text(mock_data.MOCK_CERTIFICATE)
        aikido = tmp_path / 'aikido.pem'
        aikido.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)
        shell_config = home / '.zshrc'

        inst = _aikido_instance_with_root(aikido)
        inst.mode = 'install'

        # gcloud already points at the both-roots bundle, so the property path is
        # a no-op; the reauth env vars are the only thing left to fix.
        get_value = MagicMock(returncode=0, stdout=str(python_bundle))
        with patch.object(inst, 'command_exists', return_value=True), \
             patch.object(inst, '_ensure_gcloud_properties', return_value=False), \
             patch.object(inst, 'detect_shell', return_value='zsh'), \
             patch.object(inst, 'get_shell_config', return_value=str(shell_config)), \
             patch.object(inst, 'is_suspicious_full_bundle', return_value=(False, None)), \
             patch.object(inst, '_all_roots_present_in_file', return_value=True), \
             patch('fumitm.subprocess.run', return_value=get_value):
            result = inst.setup_gcloud_cert()

        env = Path(inst._env_file_path()).read_text()
        for var in ('REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'):
            assert f'export {var}="{python_bundle}"' in env
        # The reclaimed vars are sourced from the always-last stub, so they win
        # over Aikido's earlier vendor export by last-export-wins.
        assert shell_config.read_text().count(inst._FUMITM_BLOCK_BEGIN) == 1
        # A reauth-only change must be reported, not masked as already_ok.
        assert result.status == 'configured'

    def test_reauth_vars_untouched_without_supplemental_root(
            self, tmp_path, monkeypatch):
        home = tmp_path / 'home'
        home.mkdir()
        monkeypatch.setenv('HOME', str(home))
        python_bundle = home / '.python-ca-bundle.pem'
        python_bundle.write_text(mock_data.MOCK_CERTIFICATE)
        shell_config = home / '.zshrc'

        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        inst.mode = 'install'

        get_value = MagicMock(returncode=0, stdout=str(python_bundle))
        with patch.object(inst, 'command_exists', return_value=True), \
             patch.object(inst, '_ensure_gcloud_properties', return_value=False), \
             patch.object(inst, 'detect_shell', return_value='zsh'), \
             patch.object(inst, 'get_shell_config', return_value=str(shell_config)), \
             patch.object(inst, 'is_suspicious_full_bundle', return_value=(False, None)), \
             patch.object(inst, '_all_roots_present_in_file', return_value=True), \
             patch('fumitm.subprocess.run', return_value=get_value):
            inst.setup_gcloud_cert()

        env = Path(inst._env_file_path()).read_text()
        # Plain single-provider hosts keep only the gcloud property var; the
        # Python/curl trust vars are left to setup_python_cert.
        assert 'CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE' in env
        assert 'REQUESTS_CA_BUNDLE' not in env
        assert 'CURL_CA_BUNDLE' not in env


class TestAikidoWget(FumitmTestCase):
    """wget gets a both-roots bundle; the status check reads the last directive."""

    def test_setup_wget_writes_both_roots_bundle(self, tmp_path, monkeypatch):
        home = tmp_path / 'home'
        home.mkdir()
        monkeypatch.setenv('HOME', str(home))
        primary = tmp_path / 'primary.pem'
        primary.write_text(mock_data.MOCK_CERTIFICATE)
        aikido = tmp_path / 'aikido.pem'
        aikido.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)

        inst = _aikido_instance_with_root(aikido)
        inst.mode = 'install'
        inst.cert_path = str(primary)
        inst.bundle_dir = str(home / '.netskope')

        with patch.object(inst, 'command_exists', side_effect=lambda c: c == 'wget'), \
             patch.object(inst, 'verify_connection', return_value='FAILED'), \
             patch.object(inst, 'create_bundle_with_system_certs',
                          side_effect=_seed_system_certs):
            result = inst.setup_wget_cert()

        wget_bundle = home / '.netskope' / 'wget' / 'ca-bundle.pem'
        wgetrc = home / '.wgetrc'
        assert result.status == 'configured'
        assert wget_bundle.exists()
        body = wget_bundle.read_text()
        assert mock_data.MOCK_CERTIFICATE.strip() in body
        assert mock_data.MOCK_AIKIDO_ROOT_CERT.strip() in body
        assert f'ca_certificate={wget_bundle}' in wgetrc.read_text()

    def test_last_active_wgetrc_ca_picks_last_uncommented(self):
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        content = (
            '#ca_certificate=/commented.pem\n'
            'ca_certificate=/first.pem\n'
            'ca_certificate=/second.pem\n'
        )
        assert inst._last_active_wgetrc_ca(content) == '/second.pem'
        assert inst._last_active_wgetrc_ca('# nothing here\n') is None


class TestAikidoCertFileExpansion(FumitmTestCase):
    """--aikido-cert is stored raw and expanded at read time, after user targeting
    may have rewritten HOME (sudo / --run-as-user)."""

    def test_stored_raw_not_expanded_at_construction(self):
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True,
                                           aikido_cert_file='~/aikido-root.pem')
        assert inst.aikido_cert_file == '~/aikido-root.pem'

    def test_expanded_against_current_home_at_read_time(self, tmp_path, monkeypatch):
        monkeypatch.setenv('HOME', str(tmp_path))
        cert = tmp_path / 'aikido-root.pem'
        cert.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True,
                                           aikido_cert_file='~/aikido-root.pem')
        # Linux skips the keychain; the tilde must resolve under the (mocked) HOME.
        with patch('fumitm.platform.system', return_value='Linux'), \
             patch.object(inst, '_openssl_subject', side_effect=_fake_subject):
            result = inst._get_aikido_root_cert()
        assert result is not None
        assert 'AIKIDOROOT' in result


class TestMultiRootMatching(FumitmTestCase):
    """A multi-certificate source is reported present only when every cert is in
    the bundle (e.g. several Aikido roots returned during a rotation)."""

    def test_every_block_must_be_present(self, tmp_path):
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        two_roots = tmp_path / 'two_roots.pem'
        two_roots.write_text(
            mock_data.MOCK_AIKIDO_ROOT_CERT + '\n'
            + mock_data.MOCK_AIKIDO_INTERMEDIATE_CERT
        )

        # Bundle holds only the first root -> the second is missing.
        first_only = tmp_path / 'first_only.pem'
        first_only.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)
        assert inst.certificate_likely_exists_in_file(
            str(two_roots), str(first_only)) is False
        assert inst.certificate_exists_in_file(
            str(two_roots), str(first_only)) is False

        # Bundle holds both -> complete.
        both = tmp_path / 'both.pem'
        both.write_text(
            mock_data.MOCK_AIKIDO_ROOT_CERT + '\n'
            + mock_data.MOCK_AIKIDO_INTERMEDIATE_CERT
        )
        assert inst.certificate_likely_exists_in_file(
            str(two_roots), str(both)) is True

    def test_single_cert_behaviour_unchanged(self, tmp_path):
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        single = tmp_path / 'single.pem'
        single.write_text(mock_data.MOCK_CERTIFICATE)
        bundle = tmp_path / 'bundle.pem'
        bundle.write_text('PREFIX\n' + mock_data.MOCK_CERTIFICATE + '\nSUFFIX\n')
        assert inst.certificate_likely_exists_in_file(str(single), str(bundle)) is True
        empty = tmp_path / 'empty.pem'
        empty.write_text('')
        assert inst.certificate_likely_exists_in_file(str(single), str(empty)) is False


def _fingerprints(pem_text):
    """SHA-256 of each cert's DER body — how Aikido names adopted-CA files."""
    import base64
    import hashlib
    out = []
    for block in pem_text.split('-----END CERTIFICATE-----'):
        if '-----BEGIN CERTIFICATE-----' not in block:
            continue
        body = ''.join(block.split('-----BEGIN CERTIFICATE-----')[1].split())
        out.append(hashlib.sha256(base64.b64decode(body)).hexdigest())
    return out


def _adopt_instance(tmp_path, mode='install', **kwargs):
    """Netskope instance with Aikido active and the provider root materialized.

    Netskope rather than the suite's default WARP because that is the pairing
    Aikido is actually deployed alongside; the adoption path itself reads the
    provider only through `short_name`.
    """
    inst = FumitmTestCase.create_fumitm_instance(provider='netskope', mode=mode, **kwargs)
    primary = tmp_path / 'primary.pem'
    primary.write_text(mock_data.MOCK_CERTIFICATE)
    inst.cert_path = str(primary)
    inst.extra_roots = [{'key': 'aikido', 'short_name': 'Aikido'}]
    return inst


def _patch_aikido_paths(tmp_path, adopted=False, store=True, bundle_has_root=False,
                        one_bundle_lags=False):
    """Point Aikido's adopted-CA store and built bundles at test files.

    store=False models an agent that keeps no adopted-CA directory.
    one_bundle_lags models the disagreement observed in the wild, where the pip
    bundle carries the provider root and the openssl bundle does not.
    """
    import fumitm
    overrides = {}
    store_dir = tmp_path / 'adopted-cas'
    if store:
        store_dir.mkdir(exist_ok=True)
        if adopted:
            for fp in _fingerprints(mock_data.MOCK_CERTIFICATE):
                (store_dir / f'{fp}.pem').write_text(mock_data.MOCK_CERTIFICATE)
    overrides['adopted_dir'] = str(store_dir)

    run_dir = tmp_path / 'run'
    run_dir.mkdir(exist_ok=True)

    def _bundle(name, with_root):
        path = run_dir / name
        path.write_text(
            mock_data.MOCK_AIKIDO_ROOT_CERT
            + ('\n' + mock_data.MOCK_CERTIFICATE if with_root else '')
        )
        return path

    pip_bundle = _bundle('endpoint-protection-pip-combined-ca.pem', bundle_has_root)
    _bundle('endpoint-protection-openssl-combined-ca.pem',
            bundle_has_root and not one_bundle_lags)
    _bundle('endpoint-protection-npm-cafile.pem', bundle_has_root)
    # Aikido's own root, alone. The globs must never match this file: it can
    # never contain an adopted root, so matching it would fail the check on
    # every host forever.
    (run_dir / 'endpoint-protection-proxy-ca-crt.pem').write_text(
        mock_data.MOCK_AIKIDO_ROOT_CERT
    )

    overrides['run_dir'] = str(run_dir)
    overrides['combined_pem'] = str(pip_bundle)
    return patch.dict(fumitm.SUPPLEMENTAL_ROOTS['aikido'], overrides)


DOCTOR = '/usr/local/bin/aikido-doctor'


@contextlib.contextmanager
def _doctor_on_path(inst, supports_adopt=True):
    """Model a discoverable aikido-doctor, current enough to adopt by default.

    The capability probe is patched alongside discovery rather than left to the
    real `certconfig --help` call, which would otherwise consume the
    subprocess.run mock every adoption test installs for the doctor itself.
    """
    with patch.object(inst, '_find_aikido_doctor', return_value=DOCTOR), \
         patch.object(inst, '_aikido_doctor_supports_adopt',
                      return_value=supports_adopt):
        yield


def _no_doctor(inst):
    """Model an agent whose CLI predates certconfig adopt.

    Always patched explicitly rather than left to the real PATH, since a
    developer machine running Aikido genuinely has the binary installed.
    """
    return patch.object(inst, '_find_aikido_doctor', return_value=None)


def _on_macos():
    """Adoption is gated to Darwin, so its tests must not depend on the host OS."""
    return patch('fumitm.platform.system', return_value='Darwin')


def _stat_override(overrides):
    """Patch os.stat so chosen paths report crafted ownership and mode.

    A test cannot chown anything to root, so the ownership walk is fed synthetic
    values: every path reports root:wheel 0755 unless named in `overrides`,
    which maps an absolute path to (uid, gid, mode).
    """
    real_stat = os.stat

    def fake(path, *args, **kwargs):
        info = real_stat(path, *args, **kwargs)
        uid, gid, mode = overrides.get(str(path), (0, 0, 0o755))
        return os.stat_result((
            stat.S_IFMT(info.st_mode) | mode, info.st_ino, info.st_dev,
            info.st_nlink, uid, gid, info.st_size, 0, 0, 0,
        ))

    return patch('fumitm.os.stat', side_effect=fake)


class TestAikidoDoctorPathSafety(FumitmTestCase):
    """The privileged adoption path must reject user-owned executables."""

    def _doctor(self, tmp_path):
        bin_dir = tmp_path / 'bin'
        bin_dir.mkdir()
        doctor = bin_dir / 'aikido-doctor'
        doctor.write_text('#!/bin/sh\n')
        doctor.chmod(0o755)
        return doctor

    def test_rejects_user_owned_executable(self, tmp_path):
        doctor = tmp_path / 'aikido-doctor'
        doctor.write_text('#!/bin/sh\n')
        doctor.chmod(0o755)
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        assert inst._trusted_system_executable(str(doctor))[0] is None

    def test_accepts_a_binary_under_a_group_writable_applications_dir(self, tmp_path):
        # macOS ships /Applications as root:admin drwxrwxr-x, so rejecting
        # group-writable directories outright made every vendor agent installed
        # as an application bundle permanently undiscoverable.
        doctor = self._doctor(tmp_path)
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        applications = str(tmp_path)
        with _stat_override({applications: (0, 80, 0o775)}):
            assert inst._trusted_system_executable(str(doctor)) == (str(doctor), None)

    def test_rejects_a_group_writable_binary_however_privileged_the_group(self, tmp_path):
        # The directory exemption exists because write access to a root-owned
        # directory grants an admin member nothing new. Write access to the
        # binary itself is a different thing entirely: it rewrites the bytes
        # fumitm is about to run as root.
        doctor = self._doctor(tmp_path)
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        with _stat_override({str(doctor): (0, 80, 0o775)}):
            resolved, reason = inst._trusted_system_executable(str(doctor))
        assert resolved is None
        assert 'group-writable' in reason

    def test_rejects_group_writable_by_an_unprivileged_group(self, tmp_path):
        # staff contains every local user on macOS, so a root:staff writable
        # directory is exactly the escalation this check exists to prevent.
        doctor = self._doctor(tmp_path)
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        with _stat_override({str(tmp_path): (0, 20, 0o775)}):
            assert inst._trusted_system_executable(str(doctor))[0] is None

    def test_rejects_world_writable_even_under_a_privileged_group(self, tmp_path):
        doctor = self._doctor(tmp_path)
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        with _stat_override({str(tmp_path): (0, 80, 0o777)}):
            assert inst._trusted_system_executable(str(doctor))[0] is None

    def test_rejects_a_non_root_owner_however_privileged_the_group(self, tmp_path):
        doctor = self._doctor(tmp_path)
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        with _stat_override({str(tmp_path): (501, 80, 0o755)}):
            assert inst._trusted_system_executable(str(doctor))[0] is None

    def test_rejection_reason_names_the_actual_cause(self, tmp_path):
        # A diagnostic that blames root ownership for every rejection is worse
        # than none: it sends the reader looking for a problem that isn't there.
        doctor = self._doctor(tmp_path)
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        with _stat_override({str(tmp_path): (0, 20, 0o775)}):
            assert 'group-writable' in inst._trusted_system_executable(str(doctor))[1]
        with _stat_override({str(tmp_path): (501, 0, 0o755)}):
            assert 'not owned by root' in inst._trusted_system_executable(str(doctor))[1]
        missing = tmp_path / 'nope' / 'aikido-doctor'
        assert 'regular file' in inst._trusted_system_executable(str(missing))[1]
        doctor.chmod(0o644)
        assert 'not executable' in inst._trusted_system_executable(str(doctor))[1]

    def test_dangling_symlink_is_reported_rather_than_passed_over(self, tmp_path):
        # os.path.exists follows the link, so a broken install — the likeliest
        # shape now that the doctor resolves into an application bundle — used to
        # produce no diagnostic at all while the message told users to run
        # --debug for one.
        bin_dir = tmp_path / 'bin'
        bin_dir.mkdir()
        (bin_dir / 'aikido-doctor').symlink_to(tmp_path / 'gone' / 'aikido-doctor')
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        with patch.dict(os.environ, {'PATH': str(bin_dir)}), \
             patch.object(inst, 'print_debug') as debug:
            assert inst._find_aikido_doctor() is None
        assert any('aikido-doctor' in call.args[0] for call in debug.call_args_list)

    def test_manual_command_is_shell_quoted(self, tmp_path, capsys):
        # The doctor resolves into "/Applications/Aikido Endpoint
        # Protection.app/...", so an unquoted instruction fails the moment a
        # user pastes it.
        inst = _adopt_instance(tmp_path)
        spaced = '/Applications/Aikido Endpoint Protection.app/bin/aikido-doctor'
        with _on_macos(), patch.object(inst, '_find_aikido_doctor', return_value=spaced), \
             patch.object(inst, '_aikido_doctor_supports_adopt', return_value=True), \
             _patch_aikido_paths(tmp_path, store=False), \
             patch('fumitm.os.getuid', return_value=501), \
             patch('fumitm.sys.stdin') as fake_stdin:
            fake_stdin.isatty.return_value = False
            result = inst.setup_aikido_adopt()
        assert result.status == 'skipped'
        printed = capsys.readouterr().out
        assert "'/Applications/Aikido Endpoint Protection.app/bin/aikido-doctor'" in printed

    def test_rejected_candidate_is_reported_rather_than_passed_over(self, tmp_path):
        # "not found" and "found but untrusted" call for different fixes.
        doctor = self._doctor(tmp_path)
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        with patch.dict(os.environ, {'PATH': str(doctor.parent)}), \
             _stat_override({str(doctor.parent): (501, 20, 0o755)}), \
             patch.object(inst, 'print_debug') as debug:
            assert inst._find_aikido_doctor() is None
        assert any('aikido-doctor' in call.args[0] for call in debug.call_args_list)


def _adopts_into_bundles(tmp_path, returncode=0):
    """subprocess.run side effect that adds the root to the built bundles only.

    Models an agent that repairs its bundles without leaving a record in the
    adopted-CA directory — a shape fumitm cannot rule out from the outside.
    """
    def run(argv, **kwargs):
        if returncode == 0:
            run_dir = tmp_path / 'run'
            for pattern in ('*-combined-ca.pem', '*-cafile.pem'):
                for bundle in run_dir.glob(pattern):
                    bundle.write_text(
                        bundle.read_text() + '\n' + mock_data.MOCK_CERTIFICATE
                    )
        return MagicMock(returncode=returncode, stdout='', stderr='')
    return run


def _adopts_on_run(tmp_path, returncode=0, seen=None):
    """subprocess.run side effect modelling a successful `certconfig adopt`.

    Observed against agent 1.7.28: adoption writes the adopted-CA record *and*
    reinstalls every certconfig rule, so each built bundle gains the root — the
    openssl and ruby bundles went from 128 to 130 certificates in one pass. A
    mock that only wrote the record would let a regression through, since the
    trust predicate reads the bundles.

    When a `seen` dict is supplied, records the argv and the content of the
    certificate path handed to the doctor, read at invocation time — the staged
    copy is deleted before the setup function returns.
    """
    def run(argv, **kwargs):
        if seen is not None:
            seen['argv'] = argv
            seen['cert_content'] = Path(argv[-1]).read_text()
        if returncode == 0:
            store = tmp_path / 'adopted-cas'
            store.mkdir(exist_ok=True)
            for fp in _fingerprints(mock_data.MOCK_CERTIFICATE):
                (store / f'{fp}.pem').write_text(mock_data.MOCK_CERTIFICATE)
            _adopts_into_bundles(tmp_path)(argv, **kwargs)
        return MagicMock(returncode=returncode, stdout='', stderr='')
    return run


class TestCertFingerprints(FumitmTestCase):
    """_cert_fingerprints matches openssl, per certificate in a bundle."""

    def test_matches_openssl(self, tmp_path):
        # Cross-check against openssl on a real certificate: the mock PEMs are
        # not DER-valid, and this is what pins the digest to the value Aikido
        # names its adopted-CA files with.
        import subprocess
        pem = tmp_path / 'cert.pem'
        subprocess.run(
            ['openssl', 'req', '-x509', '-newkey', 'ec',
             '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
             '-keyout', str(tmp_path / 'key.pem'), '-out', str(pem),
             '-days', '1', '-subj', '/CN=fumitm-test'],
            capture_output=True, check=True,
        )
        expected = subprocess.run(
            ['openssl', 'x509', '-in', str(pem), '-noout', '-fingerprint', '-sha256'],
            capture_output=True, text=True, check=True,
        ).stdout.strip().split('=')[1].replace(':', '').lower()

        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        assert inst._cert_fingerprints(str(pem)) == [expected]

    def test_one_per_certificate(self, tmp_path):
        pem = tmp_path / 'two.pem'
        pem.write_text(mock_data.MOCK_CERTIFICATE + '\n' + mock_data.MOCK_AIKIDO_ROOT_CERT)
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        fps = inst._cert_fingerprints(str(pem))
        assert len(fps) == 2 and len(set(fps)) == 2

    def test_missing_file_is_empty(self, tmp_path):
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        assert inst._cert_fingerprints(str(tmp_path / 'nope.pem')) == []

    def test_invalid_certificate_block_logs_debug(self, tmp_path):
        pem = tmp_path / 'invalid.pem'
        pem.write_text(
            '-----BEGIN CERTIFICATE-----\n'
            'not-base64\n'
            '-----END CERTIFICATE-----\n'
        )
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        with patch.object(inst, 'print_debug') as debug:
            assert inst._cert_fingerprints(str(pem)) == []
        debug.assert_called_once()
        assert 'Could not fingerprint' in debug.call_args.args[0]


class TestAikidoAdoptionState(FumitmTestCase):
    """Trust needs both signals: every built bundle carries it, and it is recorded."""

    def test_adopted_when_recorded_and_carried(self, tmp_path):
        inst = _adopt_instance(tmp_path)
        with _patch_aikido_paths(tmp_path, adopted=True, bundle_has_root=True):
            assert inst._aikido_has_adopted(inst.cert_path) is True
            assert inst._aikido_trusts_root(inst.cert_path) is True

    def test_record_does_not_excuse_a_lagging_bundle(self, tmp_path):
        # A root adopted once still vanishes from any bundle Aikido later
        # rebuilds from a source that lacks it, and the record would go on
        # asserting a trust that no longer exists.
        inst = _adopt_instance(tmp_path)
        with _patch_aikido_paths(tmp_path, adopted=True, bundle_has_root=True,
                                 one_bundle_lags=True):
            assert inst._aikido_has_adopted(inst.cert_path) is True
            assert inst._aikido_trusts_root(inst.cert_path) is False

    def test_bundle_presence_alone_is_not_adoption(self, tmp_path):
        # Aikido seeds some bundles from the System keychain, which already
        # holds the provider root, so every bundle can carry a root Aikido was
        # never told to keep — and the next rebuild from any other source drops
        # it. Reading the bundles alone would report success and register
        # nothing, which is the original defect wearing the opposite face.
        inst = _adopt_instance(tmp_path)
        with _patch_aikido_paths(tmp_path, adopted=False, bundle_has_root=True), \
             _doctor_on_path(inst):
            assert inst._aikido_bundles_missing(inst.cert_path) == []
            assert inst._aikido_has_adopted(inst.cert_path) is False
            assert inst._aikido_trusts_root(inst.cert_path) is False

    def test_not_adopted_when_store_lacks_fingerprint(self, tmp_path):
        inst = _adopt_instance(tmp_path)
        with _patch_aikido_paths(tmp_path, adopted=False):
            assert inst._aikido_has_adopted(inst.cert_path) is False

    def test_one_recorded_fingerprint_is_enough(self, tmp_path):
        # A provider chain can carry an intermediate alongside its root —
        # Netskope's does — and an intermediate that never earns a record of its
        # own would otherwise deny adoption forever. Completeness is the
        # bundles' question.
        inst = _adopt_instance(tmp_path)
        both = tmp_path / 'two-certs.pem'
        both.write_text(
            mock_data.MOCK_CERTIFICATE + '\n'
            + mock_data.MOCK_AIKIDO_ROOT_CERT
        )
        inst.cert_path = str(both)
        with _patch_aikido_paths(tmp_path, adopted=False):
            fingerprints = _fingerprints(both.read_text())
            (tmp_path / 'adopted-cas' / f'{fingerprints[0]}.pem').write_text(
                mock_data.MOCK_CERTIFICATE
            )
            assert inst._aikido_has_adopted(inst.cert_path) is True

    def test_unfingerprintable_cert_leaves_the_record_unanswered(self, tmp_path):
        inst = _adopt_instance(tmp_path)
        empty = tmp_path / 'empty.pem'
        empty.write_text('')
        inst.cert_path = str(empty)
        with _patch_aikido_paths(tmp_path, adopted=False):
            assert inst._aikido_has_adopted(inst.cert_path) is None

    def test_missing_store_is_not_adopted(self, tmp_path):
        # Aikido creates the record on first adoption, so its absence means
        # nothing has been adopted. Callers reach this only after establishing
        # the agent ships the CLI, which is what makes that reading safe.
        inst = _adopt_instance(tmp_path)
        with _patch_aikido_paths(tmp_path, store=False):
            assert inst._aikido_has_adopted(inst.cert_path) is False

    def test_one_lagging_bundle_denies_trust(self, tmp_path):
        # The case that motivated this: pip and node carried the Netskope chain
        # while openssl and ruby did not, and checking pip alone hid it.
        inst = _adopt_instance(tmp_path)
        with _patch_aikido_paths(tmp_path, adopted=True, bundle_has_root=True,
                                 one_bundle_lags=True), _doctor_on_path(inst):
            missing = inst._aikido_bundles_missing(inst.cert_path)
            assert [os.path.basename(b) for b in missing] == [
                'endpoint-protection-openssl-combined-ca.pem'
            ]
            assert inst._aikido_trusts_root(inst.cert_path) is False

    def test_proxy_ca_file_is_not_treated_as_a_bundle(self, tmp_path):
        # It holds Aikido's own root alone, so matching it would deny trust on
        # every host no matter how many adoptions had run.
        inst = _adopt_instance(tmp_path)
        with _patch_aikido_paths(tmp_path, bundle_has_root=True):
            bundles = inst._aikido_built_bundles()
        assert bundles
        assert not any('proxy-ca-crt' in b for b in bundles)

    def test_legacy_unmaintained_bundle_is_not_treated_as_a_bundle(self, tmp_path):
        # endpoint-protection-combined-ca.pem sits beside the per-tool bundles
        # and looks exactly like one, but `certconfig adopt` leaves it alone —
        # observed six weeks stale at three certificates while every per-tool
        # bundle was rewritten in the same pass. Requiring the provider root in
        # a file nothing maintains denies trust permanently and re-runs adoption
        # on every invocation.
        inst = _adopt_instance(tmp_path)
        with _patch_aikido_paths(tmp_path, adopted=True, bundle_has_root=True):
            (tmp_path / 'run' / 'endpoint-protection-combined-ca.pem').write_text(
                mock_data.MOCK_AIKIDO_ROOT_CERT
            )
            assert not any(b.endswith('/endpoint-protection-combined-ca.pem')
                           for b in inst._aikido_built_bundles())
            assert inst._aikido_trusts_root(inst.cert_path) is True

    def test_unreadable_run_dir_is_reported_not_silently_empty(self, tmp_path):
        # An unreadable directory and an agent that builds no bundles are
        # different diagnoses, and glob conflates them by swallowing the error.
        inst = _adopt_instance(tmp_path)
        with _patch_aikido_paths(tmp_path, adopted=True, bundle_has_root=True), \
             patch('fumitm.os.listdir', side_effect=PermissionError('denied')), \
             patch.object(inst, 'print_debug') as debug:
            assert inst._aikido_built_bundles() is None
            assert inst._aikido_bundles_missing(inst.cert_path) is None
        assert any('bundle directory' in call.args[0] for call in debug.call_args_list)

    def test_absent_run_dir_is_not_an_error(self, tmp_path):
        # A directory that is simply not there is the legacy shape the record
        # exists to cover, not a fault. Conflating the two failed the tool on
        # every host without Aikido installed, including CI.
        inst = _adopt_instance(tmp_path)
        import fumitm
        with patch.dict(fumitm.SUPPLEMENTAL_ROOTS['aikido'],
                        {'run_dir': str(tmp_path / 'never-installed')}):
            assert inst._aikido_built_bundles() == []

    def test_unreadable_run_dir_does_not_defer_to_the_record(self, tmp_path):
        # The record exists and every bundle carries the root, but the directory
        # cannot be read — so none of that is knowable. Deferring to the record
        # here is the one answer that leaves Aikido-backed tools broken while
        # reporting success.
        inst = _adopt_instance(tmp_path)
        with _patch_aikido_paths(tmp_path, adopted=True, bundle_has_root=True):
            assert inst._aikido_trusts_root(inst.cert_path) is True
            with patch('fumitm.os.listdir', side_effect=PermissionError('denied')):
                assert inst._aikido_has_adopted(inst.cert_path) is True
                assert inst._aikido_trusts_root(inst.cert_path) is False

    def test_no_bundles_at_all_falls_back_to_the_record(self, tmp_path):
        inst = _adopt_instance(tmp_path)
        import fumitm
        empty_run = tmp_path / 'empty-run'
        empty_run.mkdir()
        store = tmp_path / 'adopted-cas'
        store.mkdir(exist_ok=True)
        with patch.dict(fumitm.SUPPLEMENTAL_ROOTS['aikido'],
                        {'run_dir': str(empty_run), 'adopted_dir': str(store)}):
            assert inst._aikido_built_bundles() == []
            assert inst._aikido_trusts_root(inst.cert_path) is False
            for fp in _fingerprints(mock_data.MOCK_CERTIFICATE):
                (store / f'{fp}.pem').write_text(mock_data.MOCK_CERTIFICATE)
            assert inst._aikido_trusts_root(inst.cert_path) is True


CERTCONFIG_HELP = """NAME:
   aikido-doctor certconfig - Manage per-tool certificate trust configuration

COMMANDS:
   list             List certconfig rules
   repair           Check a certconfig rule for drift
   adopt            Adopt an extra CA from a PEM file into the CA bundles we build
   help, h          Shows a list of commands
"""

CERTCONFIG_HELP_WITHOUT_ADOPT = """NAME:
   aikido-doctor certconfig - Manage per-tool certificate trust configuration

COMMANDS:
   list             List certconfig rules
   repair           Check a certconfig rule for drift
   help, h          Shows a list of commands
"""

UNKNOWN_COMMAND = 'Unknown command: "certconfig"\nRun \'aikido-doctor --help\'.\n'


class TestAikidoDoctorCapability(FumitmTestCase):
    """Whether this agent can adopt is asked of the CLI, never assumed."""

    def _probe(self, tmp_path, stdout, returncode=0):
        inst = _adopt_instance(tmp_path)
        with patch('fumitm.subprocess.run',
                   return_value=MagicMock(returncode=returncode, stdout=stdout,
                                          stderr='')) as mock_run:
            return inst, inst._aikido_doctor_supports_adopt(DOCTOR), mock_run

    def test_adopt_listed_is_supported(self, tmp_path):
        _, supported, mock_run = self._probe(tmp_path, CERTCONFIG_HELP)
        assert supported is True
        assert mock_run.call_args.args[0] == [DOCTOR, 'certconfig', '--help']

    def test_adopt_absent_from_the_listing_is_unsupported(self, tmp_path):
        _, supported, _ = self._probe(tmp_path, CERTCONFIG_HELP_WITHOUT_ADOPT)
        assert supported is False

    def test_unknown_subcommand_is_unsupported_despite_exiting_zero(self, tmp_path):
        # The CLI answers an unknown subcommand on stdout and exits zero, so a
        # return-code check alone would call an agent predating certconfig
        # current and then report a hard failure for the rest of time.
        _, supported, _ = self._probe(tmp_path, UNKNOWN_COMMAND)
        assert supported is False

    def test_prose_mentioning_adopt_does_not_count(self, tmp_path):
        # The subcommand is matched where a listing puts it, not wherever the
        # word appears — the real help text describes adoption in prose.
        _, supported, _ = self._probe(
            tmp_path, 'COMMANDS:\n   list  Lists rules you can adopt later\n')
        assert supported is False

    def test_probe_failure_is_unsupported(self, tmp_path):
        inst = _adopt_instance(tmp_path)
        with patch('fumitm.subprocess.run', side_effect=OSError('boom')):
            assert inst._aikido_doctor_supports_adopt(DOCTOR) is False

    def test_answer_is_cached_across_callers(self, tmp_path):
        inst, _, mock_run = self._probe(tmp_path, CERTCONFIG_HELP)
        with patch('fumitm.subprocess.run') as second:
            assert inst._aikido_doctor_supports_adopt(DOCTOR) is True
        second.assert_not_called()
        assert mock_run.call_count == 1

    def test_old_agent_skips_instead_of_failing_forever(self, tmp_path):
        # The whole point: this host used to report already_ok. It must not
        # start reporting a hard failure on every scheduled run instead.
        inst = _adopt_instance(tmp_path)
        with _on_macos(), _doctor_on_path(inst, supports_adopt=False), \
             _patch_aikido_paths(tmp_path, adopted=False, bundle_has_root=True), \
             patch('fumitm.subprocess.run') as mock_run:
            result = inst.setup_aikido_adopt()
        assert result.status == 'skipped'
        assert 'predates' in result.message
        mock_run.assert_not_called()

    def test_status_does_not_flag_an_old_agent(self, tmp_path):
        inst = _adopt_instance(tmp_path, mode='status')
        cert = tmp_path / 'temp_cert.pem'
        cert.write_text(mock_data.MOCK_CERTIFICATE)
        with _on_macos(), _doctor_on_path(inst, supports_adopt=False), \
             _patch_aikido_paths(tmp_path, adopted=False, bundle_has_root=True):
            assert inst.check_aikido_adopt_status(str(cert)) is False


class TestAikidoAdoptRegistry(FumitmTestCase):
    """The aikido-adopt tool is registered with the right shape."""

    def test_registry_entry_exists(self):
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        entry = inst.tools_registry['aikido-adopt']
        assert entry['name'] == 'Aikido CA Bundles'
        # 'system' scope: needs root, and must still run when root has no
        # user context (JAMF/MDM), unlike the user-scoped bundle tools.
        assert entry['scope'] == 'system'
        assert entry['setup_func'] == inst.setup_aikido_adopt
        assert entry['check_func'] == inst.check_aikido_adopt_status
        assert 'aikido' in entry['tags']
        assert 'aikido-adopt' in entry['tags']


class TestAikidoAdoptGating(FumitmTestCase):
    """setup_aikido_adopt skips cleanly when its preconditions are absent."""

    def test_skipped_when_aikido_inactive(self):
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True,
                                           mode='install')
        with patch('fumitm.subprocess.run') as mock_run:
            result = inst.setup_aikido_adopt()
        assert result.status == 'skipped'
        assert 'not active' in result.message
        mock_run.assert_not_called()

    def test_skipped_when_doctor_absent(self, tmp_path):
        # Patch the lookup itself: shutil.which is not what resolves the doctor,
        # so this passed only on hosts where the real binary was undiscoverable.
        inst = _adopt_instance(tmp_path)
        with _on_macos(), _no_doctor(inst), \
             patch('fumitm.subprocess.run') as mock_run:
            result = inst.setup_aikido_adopt()
        assert result.status == 'skipped'
        assert 'aikido-doctor not found' in result.message
        mock_run.assert_not_called()

    def test_skipped_when_provider_root_missing(self, tmp_path):
        inst = _adopt_instance(tmp_path)
        inst.cert_path = str(tmp_path / 'nonexistent.pem')
        with _on_macos(), _doctor_on_path(inst), \
             patch('fumitm.subprocess.run') as mock_run:
            result = inst.setup_aikido_adopt()
        assert result.status == 'skipped'
        assert 'not materialized' in result.message
        mock_run.assert_not_called()

    def test_skipped_on_non_darwin(self, tmp_path):
        # Aikido's adopted-CA record lives under /Library/Application Support,
        # so adoption elsewhere could never be recognized as done.
        inst = _adopt_instance(tmp_path)
        with patch('fumitm.platform.system', return_value='Linux'), \
             patch('fumitm.subprocess.run') as mock_run:
            result = inst.setup_aikido_adopt()
        assert result.status == 'skipped'
        assert 'macOS-only' in result.message
        mock_run.assert_not_called()


class TestAikidoAdoptIdempotency(FumitmTestCase):
    """Adopt runs when trust is incomplete and is a no-op once it is not."""

    def test_already_ok_when_adopted(self, tmp_path):
        inst = _adopt_instance(tmp_path)
        with _on_macos(), _doctor_on_path(inst), \
             _patch_aikido_paths(tmp_path, adopted=True, bundle_has_root=True), \
             patch('fumitm.subprocess.run') as mock_run:
            result = inst.setup_aikido_adopt()
        assert result.status == 'already_ok'
        mock_run.assert_not_called()

    def test_runs_adopt_when_one_bundle_lags(self, tmp_path):
        # Regression for the observed host: the pip bundle carried the provider
        # root and the openssl bundle did not, and checking pip alone reported
        # success and skipped the adoption that would have fixed openssl.
        inst = _adopt_instance(tmp_path)
        with _on_macos(), _doctor_on_path(inst), \
             _patch_aikido_paths(tmp_path, adopted=False, bundle_has_root=True,
                                 one_bundle_lags=True), \
             patch('fumitm.os.getuid', return_value=0), \
             patch('fumitm.subprocess.run',
                   side_effect=_adopts_on_run(tmp_path)) as mock_run:
            result = inst.setup_aikido_adopt()
        assert result.status == 'configured'
        mock_run.assert_called_once()

    def test_runs_adopt_when_the_bundles_carry_an_unregistered_root(self, tmp_path):
        # Bundles seeded from the System keychain already hold the provider
        # root, so treating them as proof of adoption would skip the one step
        # that makes the trust survive Aikido's next rebuild.
        inst = _adopt_instance(tmp_path)
        with _on_macos(), _doctor_on_path(inst), \
             _patch_aikido_paths(tmp_path, adopted=False, bundle_has_root=True), \
             patch('fumitm.os.getuid', return_value=0), \
             patch('fumitm.subprocess.run',
                   side_effect=_adopts_on_run(tmp_path)) as mock_run:
            result = inst.setup_aikido_adopt()
        assert result.status == 'configured'
        mock_run.assert_called_once()

    def test_third_run_is_a_no_op_once_both_signals_agree(self, tmp_path):
        # Convergence, restated as a test: having adopted, the next run must do
        # nothing, or every scheduled play re-prompts for sudo and reports a
        # change.
        inst = _adopt_instance(tmp_path)
        with _on_macos(), _doctor_on_path(inst), \
             _patch_aikido_paths(tmp_path, adopted=False, bundle_has_root=True), \
             patch('fumitm.os.getuid', return_value=0), \
             patch('fumitm.subprocess.run', side_effect=_adopts_on_run(tmp_path)):
            assert inst.setup_aikido_adopt().status == 'configured'
            with patch('fumitm.subprocess.run') as mock_run:
                assert inst.setup_aikido_adopt().status == 'already_ok'
        mock_run.assert_not_called()


class TestAikidoAdoptDryRun(FumitmTestCase):
    """Status mode reports the command it would run without executing it."""

    def test_dry_run_prints_command_and_skips(self, tmp_path, capsys):
        inst = _adopt_instance(tmp_path, mode='status')
        with _on_macos(), _doctor_on_path(inst), _patch_aikido_paths(tmp_path), \
             patch('fumitm.subprocess.run') as mock_run:
            result = inst.setup_aikido_adopt()
        assert result.status == 'skipped'
        assert result.message == 'Dry run'
        mock_run.assert_not_called()
        # The printed command shows the durable cert path, not the staged copy,
        # since that copy is gone by the time a user could run it.
        assert f'{DOCTOR} certconfig adopt {inst.cert_path}' in capsys.readouterr().out


class TestAikidoAdoptInvocation(FumitmTestCase):
    """Exact argv for the root and sudo execution paths."""

    def test_root_runs_doctor_directly(self, tmp_path):
        inst = _adopt_instance(tmp_path)
        seen = {}
        with _on_macos(), _doctor_on_path(inst), _patch_aikido_paths(tmp_path), \
             patch('fumitm.os.getuid', return_value=0), \
             patch('fumitm.subprocess.run',
                   side_effect=_adopts_on_run(tmp_path, seen=seen)):
            result = inst.setup_aikido_adopt()
        assert result.status == 'configured'
        assert seen['argv'][:3] == [DOCTOR, 'certconfig', 'adopt']
        # The doctor must read a staged private copy, never the user-writable
        # cert path itself, so the file cannot be swapped between fumitm's
        # checks and the privileged read.
        staged = seen['argv'][3]
        assert staged != inst.cert_path
        assert seen['cert_content'] == mock_data.MOCK_CERTIFICATE
        assert not Path(staged).exists()

    def test_non_root_uses_sudo_after_prompt(self, tmp_path):
        inst = _adopt_instance(tmp_path, auto_yes=True)
        seen = {}
        with _on_macos(), _doctor_on_path(inst), _patch_aikido_paths(tmp_path), \
             patch('fumitm.os.getuid', return_value=501), \
             patch('fumitm.sys.stdin') as mock_stdin, \
             patch('fumitm.subprocess.run',
                   side_effect=_adopts_on_run(tmp_path, seen=seen)):
            mock_stdin.isatty.return_value = True
            result = inst.setup_aikido_adopt()
        assert result.status == 'configured'
        assert seen['argv'][:4] == ['sudo', DOCTOR, 'certconfig', 'adopt']
        assert seen['argv'][4] != inst.cert_path
        assert seen['cert_content'] == mock_data.MOCK_CERTIFICATE

    def test_prompt_declined_skips(self, tmp_path):
        inst = _adopt_instance(tmp_path)
        with _on_macos(), _doctor_on_path(inst), _patch_aikido_paths(tmp_path), \
             patch('fumitm.os.getuid', return_value=501), \
             patch('fumitm.sys.stdin') as mock_stdin, \
             patch.object(inst, '_prompt', return_value='n'), \
             patch('fumitm.subprocess.run') as mock_run:
            mock_stdin.isatty.return_value = True
            result = inst.setup_aikido_adopt()
        assert result.status == 'skipped'
        assert 'Declined' in result.message
        mock_run.assert_not_called()


class TestAikidoAdoptNonInteractive(FumitmTestCase):
    """Non-root without a TTY skips with the command printed, never exit-2."""

    def _run_non_interactive(self, tmp_path, capsys, **kwargs):
        inst = _adopt_instance(tmp_path, **kwargs)
        with _on_macos(), _doctor_on_path(inst), _patch_aikido_paths(tmp_path), \
             patch('fumitm.os.getuid', return_value=501), \
             patch('fumitm.sys.stdin') as mock_stdin, \
             patch('fumitm.subprocess.run') as mock_run:
            mock_stdin.isatty.return_value = False
            result = inst.setup_aikido_adopt()
        mock_run.assert_not_called()
        return result, capsys.readouterr().out

    def test_no_tty_skips_with_command(self, tmp_path, capsys):
        result, out = self._run_non_interactive(tmp_path, capsys)
        assert result.status == 'skipped'
        assert 'Requires sudo' in result.message
        assert f'sudo {DOCTOR} certconfig adopt' in out

    def test_no_tty_with_yes_still_skips(self, tmp_path, capsys):
        # sudo would hang reading a password with no TTY, so --yes must not
        # push the run into the sudo call.
        result, _ = self._run_non_interactive(tmp_path, capsys, auto_yes=True)
        assert result.status == 'skipped'

    def test_headless_non_root_skips(self, tmp_path, capsys):
        inst = _adopt_instance(tmp_path, headless=True, auto_yes=True)
        with _on_macos(), _doctor_on_path(inst), _patch_aikido_paths(tmp_path), \
             patch('fumitm.os.getuid', return_value=501), \
             patch('fumitm.sys.stdin') as mock_stdin, \
             patch('fumitm.subprocess.run') as mock_run:
            mock_stdin.isatty.return_value = True
            result = inst.setup_aikido_adopt()
        assert result.status == 'skipped'
        assert 'Requires sudo' in result.message
        mock_run.assert_not_called()


class TestAikidoAdoptFailure(FumitmTestCase):
    """Failures surface the doctor's output and never raise."""

    def test_nonzero_exit_fails_with_stderr(self, tmp_path):
        inst = _adopt_instance(tmp_path)
        fail = MagicMock(returncode=1, stdout='', stderr='boom')
        with _on_macos(), _doctor_on_path(inst), _patch_aikido_paths(tmp_path), \
             patch('fumitm.os.getuid', return_value=0), \
             patch('fumitm.subprocess.run', return_value=fail):
            result = inst.setup_aikido_adopt()
        assert result.status == 'failed'
        assert 'boom' in result.message

    def test_oserror_fails(self, tmp_path):
        inst = _adopt_instance(tmp_path)
        with _on_macos(), _doctor_on_path(inst), _patch_aikido_paths(tmp_path), \
             patch('fumitm.os.getuid', return_value=0), \
             patch('fumitm.subprocess.run',
                   side_effect=FileNotFoundError('no aikido-doctor')):
            result = inst.setup_aikido_adopt()
        assert result.status == 'failed'
        assert 'no aikido-doctor' in result.message

    def test_timeout_fails_and_preserves_timeout_guard(self, tmp_path):
        import subprocess

        inst = _adopt_instance(tmp_path)
        with _on_macos(), _doctor_on_path(inst), _patch_aikido_paths(tmp_path), \
             patch('fumitm.os.getuid', return_value=0), \
             patch('fumitm.subprocess.run',
                   side_effect=subprocess.TimeoutExpired(DOCTOR, timeout=300)) as mock_run:
            result = inst.setup_aikido_adopt()
        assert result.status == 'failed'
        assert 'timed out' in result.message
        assert mock_run.call_args.kwargs['timeout'] == 300
        staged = mock_run.call_args.args[0][-1]
        assert not Path(staged).exists()

    def test_clean_exit_without_adoption_fails(self, tmp_path):
        # The store is exact, so a clean exit that left nothing in it is a
        # real failure rather than a timing artefact.
        inst = _adopt_instance(tmp_path)
        ok = MagicMock(returncode=0, stdout='', stderr='')
        with _on_macos(), _doctor_on_path(inst), _patch_aikido_paths(tmp_path), \
             patch('fumitm.os.getuid', return_value=0), \
             patch('fumitm.subprocess.run', return_value=ok):
            result = inst.setup_aikido_adopt()
        assert result.status == 'failed'
        assert 'did not adopt' in result.message

    def test_clean_exit_leaving_no_trace_is_a_failure(self, tmp_path):
        # A zero exit that leaves neither an adoption record nor the root in the
        # bundles has not adopted anything, whatever it printed.
        inst = _adopt_instance(tmp_path)
        ok = MagicMock(returncode=0, stdout='', stderr='')
        with _on_macos(), _doctor_on_path(inst), \
             _patch_aikido_paths(tmp_path, store=False), \
             patch('fumitm.os.getuid', return_value=0), \
             patch('fumitm.subprocess.run', return_value=ok):
            result = inst.setup_aikido_adopt()
        assert result.status == 'failed'
        assert 'did not adopt' in result.message

    def test_adoption_leaving_no_record_is_a_failure(self, tmp_path):
        # Agent 1.7.28 writes the record in the same pass that rebuilds the
        # bundles, so bundles repaired without one means the adoption did not
        # register and nothing will survive the next rebuild.
        inst = _adopt_instance(tmp_path)
        with _on_macos(), _doctor_on_path(inst), \
             _patch_aikido_paths(tmp_path, store=False), \
             patch('fumitm.os.getuid', return_value=0), \
             patch('fumitm.subprocess.run',
                   side_effect=_adopts_into_bundles(tmp_path)):
            result = inst.setup_aikido_adopt()
        assert result.status == 'failed'
        assert 'did not adopt' in result.message

    def test_unreadable_run_dir_skips_without_running_the_doctor(self, tmp_path):
        # Adopting without being able to read the bundles is a privileged
        # command run blind, with no way to tell afterwards whether it took.
        # Skipped rather than failed: fumitm never gains the privilege that
        # would fix it, so a hard failure would go red on every scheduled run
        # with nothing able to clear it.
        inst = _adopt_instance(tmp_path)
        with _on_macos(), _doctor_on_path(inst), \
             _patch_aikido_paths(tmp_path, adopted=True, bundle_has_root=True), \
             patch('fumitm.os.listdir', side_effect=PermissionError('denied')), \
             patch('fumitm.subprocess.run') as mock_run:
            result = inst.setup_aikido_adopt()
        assert result.status == 'skipped'
        assert 'bundle directory' in result.message
        mock_run.assert_not_called()

    def test_staged_copy_removed_when_the_run_dir_is_unreadable(self, tmp_path):
        # The early return sits inside the try, so its staged copy is cleaned up
        # like every other exit from this function.
        inst = _adopt_instance(tmp_path)
        staged = {}
        real_stage = inst._stage_adoption_cert

        def record():
            staged['path'] = real_stage()
            return staged['path']

        with _on_macos(), _doctor_on_path(inst), \
             _patch_aikido_paths(tmp_path, adopted=True, bundle_has_root=True), \
             patch.object(inst, '_stage_adoption_cert', side_effect=record), \
             patch('fumitm.os.listdir', side_effect=PermissionError('denied')):
            inst.setup_aikido_adopt()
        assert not Path(staged['path']).exists()

    def test_recorded_adoption_with_a_lagging_bundle_is_not_a_failure(self, tmp_path):
        # Bundles are rebuilt by the agent, not by the CLI's return, so a bundle
        # still behind after a recorded adoption is a state fumitm neither
        # controls nor can wait out. Failing on it turns every scheduled MDM run
        # red for a condition the next agent pass clears.
        inst = _adopt_instance(tmp_path)

        def records_only(argv, **kwargs):
            store = tmp_path / 'adopted-cas'
            store.mkdir(exist_ok=True)
            for fp in _fingerprints(mock_data.MOCK_CERTIFICATE):
                (store / f'{fp}.pem').write_text(mock_data.MOCK_CERTIFICATE)
            return MagicMock(returncode=0, stdout='', stderr='')

        with _on_macos(), _doctor_on_path(inst), \
             _patch_aikido_paths(tmp_path, adopted=False, bundle_has_root=True,
                                 one_bundle_lags=True), \
             patch('fumitm.os.getuid', return_value=0), \
             patch('fumitm.subprocess.run', side_effect=records_only), \
             patch.object(inst, 'print_warn') as warn:
            result = inst.setup_aikido_adopt()
        assert result.status == 'configured'
        assert any('endpoint-protection-openssl-combined-ca.pem' in call.args[0]
                   for call in warn.call_args_list)

    def test_staged_copy_removed_after_failure(self, tmp_path):
        # The staged private copy must not accumulate in the temp directory,
        # whichever way the adoption ends.
        inst = _adopt_instance(tmp_path)
        seen = {}
        with _on_macos(), _doctor_on_path(inst), _patch_aikido_paths(tmp_path), \
             patch('fumitm.os.getuid', return_value=0), \
             patch('fumitm.subprocess.run',
                   side_effect=_adopts_on_run(tmp_path, returncode=1, seen=seen)):
            result = inst.setup_aikido_adopt()
        assert result.status == 'failed'
        assert not Path(seen['argv'][-1]).exists()


class TestAikidoAdoptStatus(FumitmTestCase):
    """check_aikido_adopt_status boolean contract across all gates."""

    def _temp_cert(self, tmp_path):
        cert = tmp_path / 'temp_cert.pem'
        cert.write_text(mock_data.MOCK_CERTIFICATE)
        return str(cert)

    def test_false_when_aikido_inactive(self, tmp_path):
        inst = self.create_fumitm_instance(provider='warp', no_aikido=True)
        assert inst.check_aikido_adopt_status(self._temp_cert(tmp_path)) is False

    def test_false_when_doctor_missing(self, tmp_path):
        inst = _adopt_instance(tmp_path, mode='status')
        with _on_macos(), _no_doctor(inst):
            assert inst.check_aikido_adopt_status(self._temp_cert(tmp_path)) is False

    def test_false_on_non_darwin(self, tmp_path, capsys):
        # Without a recognizable adoption record off macOS, status must not
        # nag about a step --fix would only skip.
        inst = _adopt_instance(tmp_path, mode='status')
        with patch('fumitm.platform.system', return_value='Linux'):
            assert inst.check_aikido_adopt_status(self._temp_cert(tmp_path)) is False
        assert 'macOS-only' in capsys.readouterr().out

    def test_false_when_adopted(self, tmp_path):
        inst = _adopt_instance(tmp_path, mode='status')
        with _on_macos(), _doctor_on_path(inst), \
             _patch_aikido_paths(tmp_path, adopted=True, bundle_has_root=True):
            assert inst.check_aikido_adopt_status(self._temp_cert(tmp_path)) is False

    def test_true_when_the_record_masks_a_lagging_bundle(self, tmp_path):
        inst = _adopt_instance(tmp_path, mode='status')
        with _on_macos(), _doctor_on_path(inst), \
             _patch_aikido_paths(tmp_path, adopted=True, bundle_has_root=True,
                                 one_bundle_lags=True):
            assert inst.check_aikido_adopt_status(self._temp_cert(tmp_path)) is True

    def test_true_when_not_adopted(self, tmp_path):
        inst = _adopt_instance(tmp_path, mode='status')
        with _on_macos(), _doctor_on_path(inst), \
             _patch_aikido_paths(tmp_path, adopted=False):
            assert inst.check_aikido_adopt_status(self._temp_cert(tmp_path)) is True

    def test_true_when_one_bundle_lags(self, tmp_path):
        # Status must flag the host whose bundles disagree, which is the state
        # that leaves openssl- and ruby-based tools without the provider root.
        inst = _adopt_instance(tmp_path, mode='status')
        with _on_macos(), _doctor_on_path(inst), \
             _patch_aikido_paths(tmp_path, adopted=False, bundle_has_root=True,
                                 one_bundle_lags=True):
            assert inst.check_aikido_adopt_status(self._temp_cert(tmp_path)) is True

    def test_true_when_the_run_dir_cannot_be_read(self, tmp_path):
        inst = _adopt_instance(tmp_path, mode='status')
        with _on_macos(), _doctor_on_path(inst), \
             _patch_aikido_paths(tmp_path, adopted=True, bundle_has_root=True), \
             patch('fumitm.os.listdir', side_effect=PermissionError('denied')):
            assert inst.check_aikido_adopt_status(self._temp_cert(tmp_path)) is True

    def test_true_when_bundles_carry_an_unregistered_root(self, tmp_path):
        # Bundles seeded from the System keychain hold the root already; status
        # must still flag the host, because nothing has been registered and the
        # trust does not survive Aikido's next rebuild.
        inst = _adopt_instance(tmp_path, mode='status')
        with _on_macos(), _doctor_on_path(inst), \
             _patch_aikido_paths(tmp_path, adopted=False, bundle_has_root=True):
            assert inst.check_aikido_adopt_status(self._temp_cert(tmp_path)) is True
