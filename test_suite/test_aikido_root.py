"""Tests for Aikido supplemental root-CA support.

Aikido Endpoint Protection performs *selective* TLS interception on top of a
primary provider (WARP/Netskope). fumitm detects it and adds the Aikido root to
every managed bundle/keystore/VM alongside the primary root, never replacing it.
These tests cover detection, root extraction (root kept, ephemeral intermediate
rejected), additive bundle assembly, idempotency, and the absent-Aikido no-op.
"""

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
        content = shell_config.read_text()
        for var in ('SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
                    'PIP_CERT', 'POETRY_CERTIFICATES_PYPI_CERT', 'BUNDLE_SSL_CA_CERT'):
            assert f'export {var}="{python_bundle}"' in content
        # All six live in a single managed block.
        assert content.count(inst._FUMITM_BLOCK_BEGIN) == 1
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
        content = shell_config.read_text()
        for var in ('SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
                    'PIP_CERT', 'POETRY_CERTIFICATES_PYPI_CERT', 'BUNDLE_SSL_CA_CERT'):
            assert f'export {var}="{python_bundle}"' in content
        # The vendor bundle is no longer referenced by any managed export.
        assert str(suspicious) not in content
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

        content = shell_config.read_text()
        for var in ('REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'):
            assert f'export {var}="{python_bundle}"' in content
        # The reclaimed vars live in the always-last managed block so they win
        # over Aikido's earlier vendor export by last-export-wins.
        assert content.count(inst._FUMITM_BLOCK_BEGIN) == 1
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

        content = shell_config.read_text()
        # Plain single-provider hosts keep only the gcloud property var; the
        # Python/curl trust vars are left to setup_python_cert.
        assert 'CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE' in content
        assert 'REQUESTS_CA_BUNDLE' not in content
        assert 'CURL_CA_BUNDLE' not in content


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
