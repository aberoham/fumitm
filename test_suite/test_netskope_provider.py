"""
Tests for Netskope provider support in fumitm.

Covers provider detection, certificate retrieval, configuration resolution,
and verifies that provider-specific values flow through to bundle paths,
keytool aliases, and container certificate filenames.
"""
import os
import sys
from unittest.mock import patch, MagicMock, mock_open
import pytest

from helpers import FumitmTestCase, MockBuilder
import mock_data

import fumitm


class TestProviderDetection(FumitmTestCase):
    """Tests for _detect_warp() and _detect_netskope()."""

    def test_detect_warp_when_warp_cli_available(self):
        """WARP is detected when warp-cli is on PATH."""
        instance = self.create_fumitm_instance(provider='warp')
        with patch('fumitm.shutil.which', return_value='/usr/local/bin/warp-cli'):
            assert instance._detect_warp() is True

    def test_detect_warp_when_warp_cli_absent(self):
        """WARP is not detected when warp-cli is missing."""
        instance = self.create_fumitm_instance(provider='warp')
        with patch('fumitm.shutil.which', return_value=None):
            assert instance._detect_warp() is False

    def test_detect_netskope_cert_file_exists(self):
        """Netskope is detected when a known cert file is present."""
        instance = self.create_fumitm_instance(provider='warp')
        with patch('platform.system', return_value='Darwin'), \
             patch('fumitm.os.path.exists', side_effect=lambda p: p == mock_data.NETSKOPE_CERT_PATHS_MACOS[0]), \
             patch('fumitm.subprocess.run'):
            assert instance._detect_netskope() is True

    def test_detect_netskope_encrypted_cert(self):
        """Netskope is detected when an encrypted .enc cert variant exists."""
        instance = self.create_fumitm_instance(provider='warp')
        enc_path = mock_data.NETSKOPE_CERT_PATHS_MACOS[0] + '.enc'
        with patch('platform.system', return_value='Darwin'), \
             patch('fumitm.os.path.exists', side_effect=lambda p: p == enc_path), \
             patch('fumitm.subprocess.run'):
            assert instance._detect_netskope() is True

    def test_detect_netskope_via_running_process(self):
        """Netskope is detected via running client process."""
        instance = self.create_fumitm_instance(provider='warp')
        mock_pgrep = MagicMock(returncode=0, stdout='12345\n')
        with patch('platform.system', return_value='Darwin'), \
             patch('fumitm.os.path.exists', return_value=False), \
             patch('fumitm.subprocess.run', return_value=mock_pgrep):
            assert instance._detect_netskope() is True

    def test_detect_netskope_not_installed(self):
        """Netskope is not detected when no cert files or process exist."""
        instance = self.create_fumitm_instance(provider='warp')
        mock_pgrep = MagicMock(returncode=1, stdout='')
        with patch('platform.system', return_value='Darwin'), \
             patch('fumitm.os.path.exists', return_value=False), \
             patch('fumitm.subprocess.run', return_value=mock_pgrep):
            assert instance._detect_netskope() is False


class TestProviderResolution(FumitmTestCase):
    """Tests for _resolve_provider() auto-detection and explicit selection."""

    def test_explicit_warp_provider(self):
        """Explicit --provider warp selects WARP."""
        instance = self.create_fumitm_instance(provider='warp')
        assert instance.provider['name'] == 'Cloudflare WARP'

    def test_explicit_netskope_provider(self):
        """Explicit --provider netskope selects Netskope."""
        instance = self.create_fumitm_instance(provider='netskope')
        assert instance.provider['name'] == 'Netskope'

    def test_auto_detect_prefers_warp_when_both_detected(self):
        """When both providers are detected, WARP is preferred."""
        with patch('platform.system', return_value='Darwin'), \
             patch('fumitm.shutil.which', return_value='/usr/local/bin/warp-cli'), \
             patch('fumitm.os.path.exists', return_value=True), \
             patch('fumitm.subprocess.run', return_value=MagicMock(returncode=0, stdout='12345')):
            instance = fumitm.FumitmPython(provider=None)
            assert instance.provider['short_name'] == 'WARP'

    def test_auto_detect_falls_back_to_netskope(self):
        """When only Netskope is detected, it is selected."""
        mock_pgrep = MagicMock(returncode=0, stdout='12345\n')

        def which_side_effect(cmd):
            if cmd == 'warp-cli':
                return None
            return f'/usr/bin/{cmd}'

        with patch('platform.system', return_value='Darwin'), \
             patch('fumitm.shutil.which', side_effect=which_side_effect), \
             patch('fumitm.os.path.exists', return_value=False), \
             patch('fumitm.subprocess.run', return_value=mock_pgrep):
            instance = fumitm.FumitmPython(provider=None)
            assert instance.provider['short_name'] == 'Netskope'

    def test_invalid_provider_exits(self):
        """An unknown provider name causes sys.exit."""
        with patch('platform.system', return_value='Darwin'), \
             pytest.raises(SystemExit):
            fumitm.FumitmPython(provider='unknown')


class TestNetskopeProviderConfig(FumitmTestCase):
    """Tests that Netskope provider config values propagate correctly."""

    def test_cert_path_is_netskope(self):
        """Netskope provider sets cert_path to ~/.netskope-ca.pem."""
        instance = self.create_fumitm_instance(provider='netskope')
        assert '.netskope-ca.pem' in instance.cert_path

    def test_bundle_dir_is_netskope(self):
        """Netskope provider sets bundle_dir to ~/.netskope."""
        instance = self.create_fumitm_instance(provider='netskope')
        assert instance.bundle_dir.endswith('.netskope')

    def test_keytool_alias_is_netskope(self):
        """Netskope provider uses netskope-zerotrust alias."""
        instance = self.create_fumitm_instance(provider='netskope')
        assert instance.provider['keytool_alias'] == 'netskope-zerotrust'

    def test_container_cert_name_is_netskope(self):
        """Netskope provider uses 'netskope' as the container cert name."""
        instance = self.create_fumitm_instance(provider='netskope')
        assert instance.provider['container_cert_name'] == 'netskope'

    def test_suggest_user_path_uses_netskope_bundle_dir(self):
        """suggest_user_path() uses the Netskope bundle directory."""
        instance = self.create_fumitm_instance(provider='netskope')
        path = instance.suggest_user_path('/some/cacert.pem', 'node')
        assert '.netskope' in path
        assert 'node' in path
        assert 'cacert.pem' in path


class TestNetskopeWarpProviderConfig(FumitmTestCase):
    """Tests that WARP provider config values are unchanged."""

    def test_cert_path_is_warp(self):
        """WARP provider sets cert_path to ~/.cloudflare-ca.pem."""
        instance = self.create_fumitm_instance(provider='warp')
        assert '.cloudflare-ca.pem' in instance.cert_path

    def test_bundle_dir_is_warp(self):
        """WARP provider sets bundle_dir to ~/.cloudflare-warp."""
        instance = self.create_fumitm_instance(provider='warp')
        assert instance.bundle_dir.endswith('.cloudflare-warp')

    def test_keytool_alias_is_warp(self):
        """WARP provider uses cloudflare-zerotrust alias."""
        instance = self.create_fumitm_instance(provider='warp')
        assert instance.provider['keytool_alias'] == 'cloudflare-zerotrust'

    def test_container_cert_name_is_warp(self):
        """WARP provider uses 'cloudflare-warp' as the container cert name."""
        instance = self.create_fumitm_instance(provider='warp')
        assert instance.provider['container_cert_name'] == 'cloudflare-warp'


class TestNetskopeGetCert(FumitmTestCase):
    """Tests for _get_netskope_cert() certificate retrieval."""

    def test_reads_combined_cert_from_file(self):
        """Reads nscacert_combined.pem when it exists."""
        instance = self.create_fumitm_instance(provider='netskope')
        cert_content = mock_data.MOCK_CERTIFICATE

        with patch('platform.system', return_value='Darwin'), \
             patch('fumitm.os.path.exists', side_effect=lambda p: 'nscacert_combined' in p), \
             patch('builtins.open', mock_open(read_data=cert_content)):
            result = instance._get_netskope_cert()
            assert result is not None
            assert '-----BEGIN CERTIFICATE-----' in result

    def test_reads_single_cert_when_combined_missing(self):
        """Falls back to nscacert.pem when combined cert is missing."""
        instance = self.create_fumitm_instance(provider='netskope')
        cert_content = mock_data.MOCK_CERTIFICATE

        def exists_side_effect(p):
            return 'nscacert.pem' in p and 'combined' not in p

        with patch('platform.system', return_value='Darwin'), \
             patch('fumitm.os.path.exists', side_effect=exists_side_effect), \
             patch('builtins.open', mock_open(read_data=cert_content)):
            result = instance._get_netskope_cert()
            assert result is not None

    def test_detects_encrypted_cert_falls_through_to_keychain(self):
        """Encrypted .enc cert triggers keychain fallback on macOS."""
        instance = self.create_fumitm_instance(provider='netskope')

        def exists_side_effect(p):
            return p.endswith('.enc')

        root_cert = "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----"
        root_result = MagicMock(returncode=0, stdout=root_cert)
        no_intermediate = MagicMock(returncode=1, stdout='')

        with patch('platform.system', return_value='Darwin'), \
             patch('fumitm.os.path.exists', side_effect=exists_side_effect), \
             patch('fumitm.subprocess.run', side_effect=[root_result, no_intermediate]):
            result = instance._get_netskope_cert()
            assert result is not None
            assert 'ROOT' in result

    def test_encrypted_cert_returns_none_when_keychain_fails(self):
        """Encrypted .enc cert returns None when keychain extraction also fails."""
        instance = self.create_fumitm_instance(provider='netskope')

        def exists_side_effect(p):
            return p.endswith('.enc')

        no_root = MagicMock(returncode=1, stdout='')

        with patch('platform.system', return_value='Darwin'), \
             patch('fumitm.os.path.exists', side_effect=exists_side_effect), \
             patch('fumitm.subprocess.run', return_value=no_root):
            result = instance._get_netskope_cert()
            assert result is None

    def test_keychain_fallback_root_and_intermediate(self):
        """Extracts root and intermediate CA from macOS keychain."""
        instance = self.create_fumitm_instance(provider='netskope')
        root_cert = "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----"
        intermediate_cert = "-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----"

        root_result = MagicMock(returncode=0, stdout=root_cert)
        intermediate_result = MagicMock(returncode=0, stdout=intermediate_cert)

        with patch('platform.system', return_value='Darwin'), \
             patch('fumitm.os.path.exists', return_value=False), \
             patch('fumitm.subprocess.run', side_effect=[root_result, intermediate_result]):
            result = instance._get_netskope_cert_from_keychain()
            assert result is not None
            assert 'ROOT' in result
            assert 'INTERMEDIATE' in result

    def test_keychain_fallback_root_only(self):
        """Proceeds with root CA only when intermediate is not found."""
        instance = self.create_fumitm_instance(provider='netskope')
        root_cert = "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----"

        root_result = MagicMock(returncode=0, stdout=root_cert)
        no_intermediate = MagicMock(returncode=1, stdout='')

        with patch('platform.system', return_value='Darwin'), \
             patch('fumitm.os.path.exists', return_value=False), \
             patch('fumitm.subprocess.run', side_effect=[root_result, no_intermediate]):
            result = instance._get_netskope_cert_from_keychain()
            assert result is not None
            assert 'ROOT' in result

    def test_keychain_fallback_no_root(self):
        """Returns None when root CA is not found in keychain."""
        instance = self.create_fumitm_instance(provider='netskope')

        no_root = MagicMock(returncode=1, stdout='')

        with patch('platform.system', return_value='Darwin'), \
             patch('fumitm.os.path.exists', return_value=False), \
             patch('fumitm.subprocess.run', return_value=no_root):
            result = instance._get_netskope_cert_from_keychain()
            assert result is None


class TestProviderCLI(FumitmTestCase):
    """Tests for --provider CLI argument."""

    @patch('fumitm.sys.argv', ['fumitm.py', '--provider', 'netskope'])
    def test_cli_provider_netskope(self):
        """--provider netskope passes provider='netskope' to constructor."""
        with patch('fumitm.FumitmPython') as mock_class:
            mock_instance = MagicMock()
            mock_instance.main.return_value = 0
            mock_class.return_value = mock_instance

            with patch('fumitm.sys.exit'):
                fumitm.main()

            mock_class.assert_called_with(
                mode='status', debug=False, selected_tools=[],
                cert_file=None, manual_cert=False, skip_verify=False,
                provider='netskope'
            )

    @patch('fumitm.sys.argv', ['fumitm.py', '--provider', 'warp', '--fix'])
    def test_cli_provider_warp_with_fix(self):
        """--provider warp --fix passes both provider and mode."""
        with patch('fumitm.FumitmPython') as mock_class:
            mock_instance = MagicMock()
            mock_instance.main.return_value = 0
            mock_class.return_value = mock_instance

            with patch('fumitm.sys.exit'):
                fumitm.main()

            mock_class.assert_called_with(
                mode='install', debug=False, selected_tools=[],
                cert_file=None, manual_cert=False, skip_verify=False,
                provider='warp'
            )

    @patch('fumitm.sys.argv', ['fumitm.py', '--provider', 'invalid'])
    def test_cli_provider_invalid_rejected(self):
        """Invalid --provider value is rejected by argparse."""
        with pytest.raises(SystemExit):
            fumitm.main()


class TestCheckProviderConnection(FumitmTestCase):
    """Tests for _check_provider_connection()."""

    def test_warp_connected(self):
        """WARP connected returns no issues."""
        instance = self.create_fumitm_instance(provider='warp')
        mock_result = MagicMock(returncode=0, stdout='Status update: Connected\nSuccess')

        with patch('fumitm.shutil.which', return_value='/usr/local/bin/warp-cli'), \
             patch('fumitm.subprocess.run', return_value=mock_result):
            has_issues = instance._check_provider_connection()
            assert has_issues is False

    def test_netskope_client_running(self):
        """Netskope reports no issues when client process is running."""
        instance = self.create_fumitm_instance(provider='netskope')
        mock_pgrep = MagicMock(returncode=0, stdout='12345\n')

        with patch('fumitm.subprocess.run', return_value=mock_pgrep):
            has_issues = instance._check_provider_connection()
            assert has_issues is False

    def test_netskope_client_not_running(self):
        """Netskope reports issues when client process is not running."""
        instance = self.create_fumitm_instance(provider='netskope')
        mock_pgrep = MagicMock(returncode=1, stdout='')

        with patch('fumitm.subprocess.run', return_value=mock_pgrep):
            has_issues = instance._check_provider_connection()
            assert has_issues is True
