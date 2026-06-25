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
