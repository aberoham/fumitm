"""
Integration tests for fumitm_windows.py

These tests verify the Windows port's functionality, particularly the
certificate appending logic and newline handling fix for issue #13.
"""
import os
import re
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

# fumitm_windows imports winreg at module level. Elsewhere a stub stands in
# so the logic can be tested on macOS and Linux too; every registry call in
# these tests is patched out. CI also runs this file on windows-latest.
if sys.platform != 'win32' and 'winreg' not in sys.modules:
    _winreg = types.ModuleType('winreg')
    for _name in ('HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE', 'KEY_READ',
                  'KEY_SET_VALUE', 'REG_EXPAND_SZ'):
        setattr(_winreg, _name, 0)
    for _name in ('OpenKey', 'SetValueEx', 'QueryValueEx', 'CloseKey'):
        setattr(_winreg, _name, MagicMock(side_effect=OSError('winreg stub')))
    sys.modules['winreg'] = _winreg

# Import test utilities
import mock_data
from helpers import import_fumitm_windows

# Import the Windows module using our helper
fumitm_windows = import_fumitm_windows()


class TestCertificateAppendingWindows:
    """Tests for certificate appending to ensure proper PEM formatting (issue #13).

    These tests verify the Windows port handles the edge case where a certificate
    bundle file doesn't end with a newline, which would otherwise produce
    malformed PEM like: -----END CERTIFICATE----------BEGIN CERTIFICATE-----
    """

    def test_append_to_bundle_without_trailing_newline(self, tmp_path):
        """Ensure appending to a bundle without newline doesn't corrupt PEM.

        This is the core bug scenario from issue #13.
        """
        # Create a CA bundle file WITHOUT trailing newline
        bundle_file = tmp_path / "ca-bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE_NO_NEWLINE)

        # Verify setup: bundle should NOT end with newline
        with open(bundle_file, 'rb') as f:
            f.seek(-1, 2)
            last_byte = f.read(1)
            assert last_byte == b'-', f"Setup error: bundle should end with dash, got {last_byte!r}"

        # Create a certificate file to append
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Create instance and call append_certificate_if_missing
        with patch('platform.system', return_value='Windows'):
            instance = fumitm_windows.FumitmWindows(mode='install', debug=True)
            result = instance.append_certificate_if_missing(str(cert_file), str(bundle_file))

        assert result is True

        # Read the resulting file
        content = bundle_file.read_text()

        # THE CRITICAL CHECK: malformed PEM pattern must NOT exist
        malformed_pattern = "-----END CERTIFICATE----------BEGIN CERTIFICATE-----"
        assert malformed_pattern not in content, "MALFORMED PEM DETECTED!"

        # Verify proper separation exists (newline between certs)
        proper_separation = re.search(
            r'-----END CERTIFICATE-----\r?\n+-----BEGIN CERTIFICATE-----',
            content
        )
        assert proper_separation, "Expected newline separation between certificates"

    def test_append_to_bundle_with_crlf_ending(self, tmp_path):
        """Verify Windows-style CRLF line endings are handled correctly."""
        # Create bundle with CRLF line endings
        bundle_crlf = (
            "-----BEGIN CERTIFICATE-----\r\n"
            "MIIDSjCCAjKgAwIBAgIQRK\r\n"
            "-----END CERTIFICATE-----\r\n"
        )
        bundle_file = tmp_path / "ca-bundle.pem"
        # Write in binary mode to preserve exact CRLF
        bundle_file.write_bytes(bundle_crlf.encode('utf-8'))

        # Verify setup: bundle ends with LF (the \n in CRLF)
        with open(bundle_file, 'rb') as f:
            f.seek(-1, 2)
            last_byte = f.read(1)
            assert last_byte == b'\n', f"Setup error: expected LF, got {last_byte!r}"

        # Create certificate file
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Call append
        with patch('platform.system', return_value='Windows'):
            instance = fumitm_windows.FumitmWindows(mode='install', debug=True)
            result = instance.append_certificate_if_missing(str(cert_file), str(bundle_file))

        assert result is True

        content = bundle_file.read_text()

        # Should NOT have malformed PEM
        assert "-----END CERTIFICATE----------BEGIN CERTIFICATE-----" not in content

        # Should NOT have excessive blank lines (3+ newlines between certs)
        excessive = re.search(
            r'-----END CERTIFICATE-----(\r?\n){3,}-----BEGIN CERTIFICATE-----',
            content
        )
        assert not excessive, "Too many blank lines between certificates"

    def test_append_to_bundle_with_lf_ending(self, tmp_path):
        """Verify Unix-style LF line endings work correctly."""
        # Create bundle with Unix LF endings (common when files come from git)
        bundle_lf = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIDSjCCAjKgAwIBAgIQRK\n"
            "-----END CERTIFICATE-----\n"
        )
        bundle_file = tmp_path / "ca-bundle.pem"
        bundle_file.write_bytes(bundle_lf.encode('utf-8'))

        # Create certificate file
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Call append
        with patch('platform.system', return_value='Windows'):
            instance = fumitm_windows.FumitmWindows(mode='install', debug=True)
            result = instance.append_certificate_if_missing(str(cert_file), str(bundle_file))

        assert result is True

        content = bundle_file.read_text()

        # Should NOT have malformed PEM
        assert "-----END CERTIFICATE----------BEGIN CERTIFICATE-----" not in content

    def test_append_skips_if_certificate_exists(self, tmp_path):
        """Verify that appending skips if certificate already exists in bundle."""
        # Create a bundle that already contains the certificate
        bundle_file = tmp_path / "ca-bundle.pem"
        bundle_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Use the same certificate file
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        original_size = bundle_file.stat().st_size

        with patch('platform.system', return_value='Windows'):
            instance = fumitm_windows.FumitmWindows(mode='install', debug=True)
            result = instance.append_certificate_if_missing(str(cert_file), str(bundle_file))

        # Should return True (success, even though skipped)
        assert result is True

        # File size should be the same (nothing appended)
        assert bundle_file.stat().st_size == original_size

    def test_append_to_nonexistent_target_creates_file(self, tmp_path):
        """Verify appending to a non-existent file creates it with the certificate."""
        # Target file doesn't exist
        bundle_file = tmp_path / "new-bundle.pem"

        # Create a certificate file
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Call append
        with patch('platform.system', return_value='Windows'):
            instance = fumitm_windows.FumitmWindows(mode='install', debug=True)
            result = instance.append_certificate_if_missing(str(cert_file), str(bundle_file))

        assert result is True

        # File should now exist
        assert bundle_file.exists()

        # Content should be the certificate
        content = bundle_file.read_text()
        assert "-----BEGIN CERTIFICATE-----" in content
        assert "-----END CERTIFICATE-----" in content

    def test_same_file_graceful_handling(self, tmp_path):
        """Test that append_certificate_if_missing handles same file gracefully.

        This was a bug fixed in PR #15.
        """
        # Create a single file
        test_file = tmp_path / "test.pem"
        test_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Try to append the file to itself
        with patch('platform.system', return_value='Windows'):
            instance = fumitm_windows.FumitmWindows(mode='install', debug=True)
            result = instance.append_certificate_if_missing(str(test_file), str(test_file))

        # Should handle gracefully (return True without error)
        assert result is True


class TestWindowsBasicFunctionality:
    """Basic functionality tests for the Windows port."""

    def test_instance_creation(self):
        """Test that FumitmWindows can be instantiated."""
        with patch('platform.system', return_value='Windows'):
            instance = fumitm_windows.FumitmWindows(mode='status')
            assert instance is not None
            assert instance.mode == 'status'

    def test_install_mode_setting(self):
        """Test that install mode is set correctly."""
        with patch('platform.system', return_value='Windows'):
            instance = fumitm_windows.FumitmWindows(mode='install')
            assert instance.is_install_mode() is True

            instance = fumitm_windows.FumitmWindows(mode='status')
            assert instance.is_install_mode() is False

    def test_debug_mode_setting(self):
        """Test that debug mode is set correctly."""
        with patch('platform.system', return_value='Windows'):
            instance = fumitm_windows.FumitmWindows(mode='status', debug=True)
            assert instance.is_debug_mode() is True

            instance = fumitm_windows.FumitmWindows(mode='status', debug=False)
            assert instance.is_debug_mode() is False


class TestStatusFunctionContractsWindows:
    """Contract tests for all check_*_status() functions in Windows port.

    These tests verify that all status check functions return a boolean value,
    preventing bugs like issue #20 where a function forgot to return has_issues.
    """

    def get_all_status_methods(self, instance):
        """Discover all check_*_status methods via introspection.

        Excludes check_all_status() which is the orchestrator method.
        """
        return [
            name for name in dir(instance)
            if name.startswith('check_') and name.endswith('_status')
            and name != 'check_all_status'  # Exclude orchestrator
            and callable(getattr(instance, name))
        ]

    def test_all_status_functions_return_boolean(self, tmp_path):
        """Ensure all check_*_status() functions return a boolean (not None).

        Regression test for issue #20 - prevents forgetting return statements.
        This test automatically discovers all check_*_status methods and verifies
        each returns a proper boolean value.
        """
        # Create a temporary cert file for the status checks
        cert_file = tmp_path / "test-cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Windows'):
            instance = fumitm_windows.FumitmWindows(mode='status')

        status_methods = self.get_all_status_methods(instance)

        # Verify we found the expected methods (sanity check)
        assert len(status_methods) >= 8, f"Expected at least 8 status methods, found {len(status_methods)}: {status_methods}"

        # Expected methods based on the Windows codebase
        expected_methods = [
            'check_system_status', 'check_node_status', 'check_python_status',
            'check_gcloud_status', 'check_java_status', 'check_wget_status',
            'check_podman_status', 'check_rancher_status', 'check_git_status'
        ]
        for expected in expected_methods:
            assert expected in status_methods, f"Expected method {expected} not found"

        # Test each status method
        failed_methods = []
        for method_name in status_methods:
            method = getattr(instance, method_name)

            # Mock all external dependencies so functions hit early returns
            with patch.object(instance, 'command_exists', return_value=False), \
                 patch.object(instance, 'check_certificate_in_store', return_value=False), \
                 patch('os.path.exists', return_value=False), \
                 patch('os.environ.get', return_value=''):

                result = method(str(cert_file))

                if result is None:
                    failed_methods.append(f"{method_name} returned None")
                elif not isinstance(result, bool):
                    failed_methods.append(f"{method_name} returned {type(result).__name__}, not bool")

        assert not failed_methods, "Status function contract violations:\n" + "\n".join(failed_methods)

    def test_status_functions_return_false_when_tool_not_installed(self, tmp_path):
        """Verify status functions return False (no issues) when tool is not installed."""
        cert_file = tmp_path / "test-cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Windows'):
            instance = fumitm_windows.FumitmWindows(mode='status')

        # Get methods excluding check_system_status (it always checks Windows store)
        status_methods = [
            m for m in self.get_all_status_methods(instance)
            if m != 'check_system_status'  # System status always runs
        ]

        for method_name in status_methods:
            method = getattr(instance, method_name)

            # Mock tool as not installed
            with patch.object(instance, 'command_exists', return_value=False), \
                 patch.object(instance, 'check_certificate_in_store', return_value=True), \
                 patch('os.path.exists', return_value=False), \
                 patch('os.environ.get', return_value=''):

                result = method(str(cert_file))

                # When tool is not installed, there should be no issues to report
                assert result is False, f"{method_name} should return False when tool not installed, got {result}"


# Two distinct, syntactically valid PEM blocks. The Windows helpers compare
# base64 bodies as text, so the DER inside does not need to parse.
ROOT_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "ROOTROOTROOTROOTROOTROOTROOTROOTROOTROOTROOTROOTROOTROOTROOTROOT\n"
    "ROOTROOTROOTROOTROOTROOTROOTROOTROOTROOTROOT\n"
    "-----END CERTIFICATE-----\n"
)
INTERMEDIATE_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "INTERINTERINTERINTERINTERINTERINTERINTERINTERINTERINTERINTERINTE\n"
    "INTERINTERINTERINTERINTERINTERINTERINTERINTER\n"
    "-----END CERTIFICATE-----\n"
)
SYSTEM_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "SYSTEMSYSTEMSYSTEMSYSTEMSYSTEMSYSTEMSYSTEMSYSTEMSYSTEMSYSTEMSYST\n"
    "-----END CERTIFICATE-----\n"
)


def _windows_instance(mode="install"):
    with patch('platform.system', return_value='Windows'):
        return fumitm_windows.FumitmWindows(mode=mode, debug=True, provider="netskope")


class TestNetskopeChainWindows:
    """Netskope root plus tenant intermediate on Windows.

    The Netskope root CA has no Key Usage extension. Python 3.13+ verifies
    chains strictly and fails with "CA cert does not include key usage
    extension" unless the tenant intermediate (which has one) is in the
    bundle, so chain building stops there. The encrypted-config Netskope
    client leaves only .enc files on disk, so the chain comes from the
    Windows certificate store.
    """

    def test_pem_bodies_ignore_line_endings(self):
        crlf = ROOT_PEM.replace("\n", "\r\n")
        assert fumitm_windows.FumitmWindows._pem_bodies(crlf) == \
            fumitm_windows.FumitmWindows._pem_bodies(ROOT_PEM)
        assert len(fumitm_windows.FumitmWindows._pem_blocks(ROOT_PEM + INTERMEDIATE_PEM)) == 2

    def test_store_export_parsing(self):
        instance = _windows_instance()
        stdout = ROOT_PEM + "=====INTERMEDIATE=====\n" + INTERMEDIATE_PEM
        with patch('subprocess.run', return_value=type('R', (), {
                'returncode': 0, 'stdout': stdout, 'stderr': ''})()):
            root, intermediate = instance._get_netskope_certs_from_store()
        assert root == ROOT_PEM.strip()
        assert intermediate == INTERMEDIATE_PEM.strip()

    def test_store_export_handles_missing_intermediate(self):
        instance = _windows_instance()
        with patch('subprocess.run', return_value=type('R', (), {
                'returncode': 0, 'stdout': ROOT_PEM + "=====INTERMEDIATE=====\n", 'stderr': ''})()):
            assert instance._get_netskope_certs_from_store() == (ROOT_PEM.strip(), None)

    def test_encrypted_files_fall_back_to_store(self, tmp_path):
        """Only nscacert.pem.enc on disk: the chain comes from the store."""
        source = tmp_path / "nscacert.pem"
        (tmp_path / "nscacert.pem.enc").write_bytes(b"\x00encrypted")
        instance = _windows_instance()
        with patch.object(instance, 'get_netskope_cert_sources', return_value=[str(source)]), \
             patch.object(instance, '_get_netskope_certs_from_store',
                          return_value=(ROOT_PEM.strip(), INTERMEDIATE_PEM.strip())), \
             patch.object(fumitm_windows, 'CERT_PATH', str(tmp_path / "netskope-ca.pem")):
            content = instance._get_netskope_cert()
        bodies = fumitm_windows.FumitmWindows._pem_bodies(content)
        assert bodies == fumitm_windows.FumitmWindows._pem_bodies(ROOT_PEM + INTERMEDIATE_PEM)

    def test_root_only_file_gains_intermediate_from_store(self, tmp_path):
        """A root-only nscacert.pem (or hand export) still ends up with the intermediate."""
        source = tmp_path / "nscacert.pem"
        source.write_text(ROOT_PEM)
        instance = _windows_instance()
        with patch.object(instance, 'get_netskope_cert_sources', return_value=[str(source)]), \
             patch.object(instance, '_get_netskope_certs_from_store',
                          return_value=(ROOT_PEM.strip(), INTERMEDIATE_PEM.strip())):
            content = instance._get_netskope_cert()
        bodies = fumitm_windows.FumitmWindows._pem_bodies(content)
        assert bodies == fumitm_windows.FumitmWindows._pem_bodies(ROOT_PEM + INTERMEDIATE_PEM)
        # Root stays first: downstream loaders read the first certificate.
        assert content.startswith("-----BEGIN CERTIFICATE-----\nROOT")

    def test_combined_file_does_not_duplicate_intermediate(self, tmp_path):
        source = tmp_path / "nscacert_combined.pem"
        source.write_text(ROOT_PEM + INTERMEDIATE_PEM)
        instance = _windows_instance()
        with patch.object(instance, 'get_netskope_cert_sources', return_value=[str(source)]), \
             patch.object(instance, '_get_netskope_certs_from_store',
                          return_value=(ROOT_PEM.strip(), INTERMEDIATE_PEM.strip())):
            content = instance._get_netskope_cert()
        assert len(fumitm_windows.FumitmWindows._pem_blocks(content)) == 2

    def test_two_copies_of_root_still_gain_intermediate(self, tmp_path):
        """Two blocks in a file do not mean root plus intermediate."""
        source = tmp_path / "nscacert_combined.pem"
        source.write_text(ROOT_PEM + ROOT_PEM)
        instance = _windows_instance()
        with patch.object(instance, 'get_netskope_cert_sources', return_value=[str(source)]), \
             patch.object(instance, '_get_netskope_certs_from_store',
                          return_value=(ROOT_PEM.strip(), INTERMEDIATE_PEM.strip())):
            content = instance._get_netskope_cert()
        bodies = fumitm_windows.FumitmWindows._pem_bodies(content)
        assert bodies == fumitm_windows.FumitmWindows._pem_bodies(ROOT_PEM + INTERMEDIATE_PEM)

    def test_every_store_intermediate_is_added(self, tmp_path):
        """During a tenant CA rotation the store holds two intermediates; both are kept."""
        second = INTERMEDIATE_PEM.replace("INTER", "OTHER")
        source = tmp_path / "nscacert.pem"
        source.write_text(ROOT_PEM)
        instance = _windows_instance()
        with patch.object(instance, 'get_netskope_cert_sources', return_value=[str(source)]), \
             patch.object(instance, '_get_netskope_certs_from_store',
                          return_value=(ROOT_PEM.strip(), (INTERMEDIATE_PEM + second).strip())):
            content = instance._get_netskope_cert()
        assert len(fumitm_windows.FumitmWindows._pem_blocks(content)) == 3

    def test_store_query_failure_returns_nothing(self):
        instance = _windows_instance()
        with patch('subprocess.run', return_value=type('R', (), {
                'returncode': 1, 'stdout': ROOT_PEM, 'stderr': 'Access is denied'})()):
            assert instance._get_netskope_certs_from_store() == (None, None)

    def test_store_query_uses_exact_names_and_stops_on_error(self):
        """The PowerShell must anchor the common names and stop on store errors."""
        instance = _windows_instance()
        with patch('subprocess.run', return_value=type('R', (), {
                'returncode': 0, 'stdout': "=====INTERMEDIATE=====\n", 'stderr': ''})()) as run:
            instance._get_netskope_certs_from_store()
        script = run.call_args[0][0][-1]
        assert "$ErrorActionPreference = 'Stop'" in script
        assert r"CN=certadmin(\s*,|$)" in script
        assert r"CN=ca\.[^,]+\.goskope\.com(\s*,|$)" in script
        assert "Issuer -eq $root.Subject" in script

    def test_manual_cert_path_still_works_when_store_empty(self, tmp_path):
        manual = tmp_path / "netskope-ca.pem"
        manual.write_text(ROOT_PEM)
        instance = _windows_instance()
        with patch.object(instance, 'get_netskope_cert_sources', return_value=[str(tmp_path / "missing.pem")]), \
             patch.object(instance, '_get_netskope_certs_from_store', return_value=(None, None)), \
             patch.object(fumitm_windows, 'CERT_PATH', str(manual)):
            content = instance._get_netskope_cert()
        assert content == ROOT_PEM.strip()

    def test_nothing_found_returns_none(self, tmp_path):
        instance = _windows_instance()
        with patch.object(instance, 'get_netskope_cert_sources', return_value=[str(tmp_path / "missing.pem")]), \
             patch.object(instance, '_get_netskope_certs_from_store', return_value=(None, None)), \
             patch.object(fumitm_windows, 'CERT_PATH', str(tmp_path / "netskope-ca.pem")):
            assert instance._get_netskope_cert() is None


class TestBundleContentsWindows:
    """Duplicate detection and provider-only bundle repair."""

    def test_exists_requires_every_block(self, tmp_path):
        cert = tmp_path / "chain.pem"
        cert.write_text(ROOT_PEM + INTERMEDIATE_PEM)
        bundle = tmp_path / "bundle.pem"
        bundle.write_text(SYSTEM_PEM + ROOT_PEM)
        instance = _windows_instance()
        assert instance.certificate_exists_in_file(str(cert), str(bundle)) is False
        bundle.write_text(SYSTEM_PEM + ROOT_PEM + INTERMEDIATE_PEM)
        assert instance.certificate_exists_in_file(str(cert), str(bundle)) is True

    def test_append_adds_only_missing_blocks(self, tmp_path):
        """Root already present: only the intermediate is appended, once."""
        cert = tmp_path / "chain.pem"
        cert.write_text(ROOT_PEM + INTERMEDIATE_PEM)
        bundle = tmp_path / "bundle.pem"
        bundle.write_text(SYSTEM_PEM + ROOT_PEM.replace("\n", "\r\n"))
        instance = _windows_instance()
        assert instance.append_certificate_if_missing(str(cert), str(bundle)) is True
        assert instance.append_certificate_if_missing(str(cert), str(bundle)) is True
        bodies = fumitm_windows.FumitmWindows._pem_bodies(bundle.read_text())
        assert bodies == fumitm_windows.FumitmWindows._pem_bodies(SYSTEM_PEM + ROOT_PEM + INTERMEDIATE_PEM)

    def test_repeated_append_does_not_duplicate(self, tmp_path):
        """Three --fix runs once produced three copies of the root on Windows."""
        cert = tmp_path / "cert.pem"
        cert.write_text(ROOT_PEM)
        bundle = tmp_path / "bundle.pem"
        instance = _windows_instance()
        for _ in range(3):
            instance.append_certificate_if_missing(str(cert), str(bundle))
        assert bundle.read_text().count("BEGIN CERTIFICATE") == 1

    def test_provider_only_bundle_detection(self, tmp_path):
        cert_path = tmp_path / "netskope-ca.pem"
        cert_path.write_text(ROOT_PEM + INTERMEDIATE_PEM)
        bundle = tmp_path / "bundle.pem"
        instance = _windows_instance()
        with patch.object(fumitm_windows, 'CERT_PATH', str(cert_path)):
            bundle.write_text(ROOT_PEM * 3)
            assert instance._bundle_is_provider_only(str(bundle)) is True
            bundle.write_text("")
            assert instance._bundle_is_provider_only(str(bundle)) is True
            bundle.write_text(SYSTEM_PEM + ROOT_PEM)
            assert instance._bundle_is_provider_only(str(bundle)) is False

    def test_provider_only_bundle_is_rebuilt_with_system_certs(self, tmp_path):
        cert_path = tmp_path / "netskope-ca.pem"
        cert_path.write_text(ROOT_PEM + INTERMEDIATE_PEM)
        bundle_dir = tmp_path / "python"
        bundle_dir.mkdir()
        bundle = bundle_dir / "ca-bundle.pem"
        bundle.write_text(ROOT_PEM * 3)
        instance = _windows_instance()
        with patch.object(fumitm_windows, 'CERT_PATH', str(cert_path)), \
             patch.object(instance, 'get_tool_bundle_path', return_value=str(bundle)), \
             patch.object(instance, 'find_existing_bundle', return_value=str(bundle)), \
             patch.object(instance, 'get_system_ca_bundle', return_value=SYSTEM_PEM.strip()), \
             patch.object(instance, 'set_environment_variable') as set_env:
            result = instance.setup_consistent_bundle("python", env_vars=["REQUESTS_CA_BUNDLE"])
        assert result == str(bundle)
        bodies = fumitm_windows.FumitmWindows._pem_bodies(bundle.read_text())
        assert bodies == fumitm_windows.FumitmWindows._pem_bodies(SYSTEM_PEM + ROOT_PEM + INTERMEDIATE_PEM)
        set_env.assert_called_with("REQUESTS_CA_BUNDLE", str(bundle))

    def test_foreign_provider_only_bundle_is_not_used_as_seed(self, tmp_path):
        """A hand-made REQUESTS_CA_BUNDLE holding only the root is not copied."""
        cert_path = tmp_path / "netskope-ca.pem"
        cert_path.write_text(ROOT_PEM + INTERMEDIATE_PEM)
        foreign = tmp_path / "ca-bundle.crt"
        foreign.write_text(ROOT_PEM)
        bundle = tmp_path / "python" / "ca-bundle.pem"
        instance = _windows_instance()
        with patch.object(fumitm_windows, 'CERT_PATH', str(cert_path)), \
             patch.object(instance, 'get_tool_bundle_path', return_value=str(bundle)), \
             patch.object(instance, 'find_existing_bundle', return_value=str(foreign)), \
             patch.object(instance, 'get_system_ca_bundle', return_value=SYSTEM_PEM.strip()), \
             patch.object(instance, 'set_environment_variable'), \
             patch('builtins.input', side_effect=AssertionError("must not prompt to copy a provider-only bundle")):
            instance.setup_consistent_bundle("python")
        bodies = fumitm_windows.FumitmWindows._pem_bodies(bundle.read_text())
        assert bodies == fumitm_windows.FumitmWindows._pem_bodies(SYSTEM_PEM + ROOT_PEM + INTERMEDIATE_PEM)

    def test_pem_blocks_reject_truncated_and_stray_markers(self):
        truncated = ROOT_PEM + "-----BEGIN CERTIFICATE-----\nINTERINTER\n"
        blocks = fumitm_windows.FumitmWindows._pem_blocks(truncated)
        assert len(blocks) == 1
        stray = "-----BEGIN CERTIFICATE-----\ngarbage\n" + ROOT_PEM
        assert fumitm_windows.FumitmWindows._pem_bodies(stray) == \
            fumitm_windows.FumitmWindows._pem_bodies(ROOT_PEM)
        empty = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"
        assert fumitm_windows.FumitmWindows._pem_blocks(empty) == []

    def test_certificate_file_without_certificates_is_not_present(self, tmp_path):
        """An empty or non-PEM source must not read as 'already present'."""
        bundle = tmp_path / "bundle.pem"
        bundle.write_text(SYSTEM_PEM)
        instance = _windows_instance()
        for text in ("", "not a certificate\n"):
            cert = tmp_path / "cert.pem"
            cert.write_text(text)
            assert instance.certificate_exists_in_file(str(cert), str(bundle)) is False
            assert instance.append_certificate_if_missing(str(cert), str(bundle)) is False
        assert bundle.read_text() == SYSTEM_PEM

    def test_duplicate_source_blocks_are_appended_once(self, tmp_path):
        cert = tmp_path / "cert.pem"
        cert.write_text(ROOT_PEM + ROOT_PEM)
        bundle = tmp_path / "bundle.pem"
        bundle.write_text(SYSTEM_PEM)
        instance = _windows_instance()
        assert instance.append_certificate_if_missing(str(cert), str(bundle)) is True
        assert bundle.read_text().count("BEGIN CERTIFICATE") == 2

    def test_unreadable_bundle_is_not_provider_only(self, tmp_path):
        """A failed read must never trigger a rebuild."""
        cert_path = tmp_path / "netskope-ca.pem"
        cert_path.write_text(ROOT_PEM)
        unreadable = tmp_path / "bundle-dir"
        unreadable.mkdir()
        instance = _windows_instance()
        with patch.object(fumitm_windows, 'CERT_PATH', str(cert_path)):
            assert instance._bundle_is_provider_only(str(unreadable)) is False
            assert instance._bundle_is_provider_only(
                str(cert_path), str(tmp_path / "missing.pem")) is False

    def test_own_bundle_missing_intermediate_is_topped_up_not_rebuilt(self, tmp_path):
        """An earlier bundle with the root gains the intermediate and keeps its system roots."""
        cert_path = tmp_path / "netskope-ca.pem"
        cert_path.write_text(ROOT_PEM + INTERMEDIATE_PEM)
        bundle = tmp_path / "npm" / "ca-bundle.pem"
        bundle.parent.mkdir()
        bundle.write_text(SYSTEM_PEM + ROOT_PEM)
        instance = _windows_instance()
        with patch.object(fumitm_windows, 'CERT_PATH', str(cert_path)), \
             patch.object(instance, 'get_tool_bundle_path', return_value=str(bundle)), \
             patch.object(instance, 'find_existing_bundle', return_value=None), \
             patch.object(instance, 'get_system_ca_bundle',
                          side_effect=AssertionError("must not rebuild from the store")):
            assert instance.setup_consistent_bundle("npm") == str(bundle)
        bodies = fumitm_windows.FumitmWindows._pem_bodies(bundle.read_text())
        assert bodies == fumitm_windows.FumitmWindows._pem_bodies(SYSTEM_PEM + ROOT_PEM + INTERMEDIATE_PEM)

    def test_empty_system_export_writes_nothing(self, tmp_path):
        """No system roots: refuse rather than leave a provider-only bundle."""
        cert_path = tmp_path / "netskope-ca.pem"
        cert_path.write_text(ROOT_PEM + INTERMEDIATE_PEM)
        bundle = tmp_path / "python" / "ca-bundle.pem"
        bundle.parent.mkdir()
        bundle.write_text(ROOT_PEM)
        instance = _windows_instance()
        with patch.object(fumitm_windows, 'CERT_PATH', str(cert_path)), \
             patch.object(instance, 'get_tool_bundle_path', return_value=str(bundle)), \
             patch.object(instance, 'find_existing_bundle', return_value=None), \
             patch.object(instance, 'get_system_ca_bundle', return_value=""), \
             patch.object(instance, 'set_environment_variable') as set_env:
            assert instance.setup_consistent_bundle("python", env_vars=["REQUESTS_CA_BUNDLE"]) is None
        assert bundle.read_text() == ROOT_PEM
        set_env.assert_not_called()

    def test_failed_replace_keeps_previous_bundle(self, tmp_path):
        cert_path = tmp_path / "netskope-ca.pem"
        cert_path.write_text(ROOT_PEM + INTERMEDIATE_PEM)
        bundle = tmp_path / "python" / "ca-bundle.pem"
        bundle.parent.mkdir()
        bundle.write_text(ROOT_PEM)
        instance = _windows_instance()
        with patch.object(fumitm_windows, 'CERT_PATH', str(cert_path)), \
             patch.object(instance, 'get_tool_bundle_path', return_value=str(bundle)), \
             patch.object(instance, 'find_existing_bundle', return_value=None), \
             patch.object(instance, 'get_system_ca_bundle', return_value=SYSTEM_PEM.strip()), \
             patch.object(fumitm_windows.os, 'replace', side_effect=OSError("locked")), \
             patch.object(instance, 'set_environment_variable') as set_env:
            assert instance.setup_consistent_bundle("python", env_vars=["REQUESTS_CA_BUNDLE"]) is None
        assert bundle.read_text() == ROOT_PEM
        assert os.listdir(bundle.parent) == ["ca-bundle.pem"]
        set_env.assert_not_called()

    def test_git_status_flags_provider_only_ca_file(self, tmp_path):
        cert = tmp_path / "current.pem"
        cert.write_text(ROOT_PEM + INTERMEDIATE_PEM)
        git_ca = tmp_path / "git-ca.pem"
        git_ca.write_text(ROOT_PEM + INTERMEDIATE_PEM)
        instance = _windows_instance(mode="status")
        result = type('R', (), {'returncode': 0, 'stdout': str(git_ca) + "\n", 'stderr': ''})()
        with patch.object(instance, 'command_exists', return_value=True), \
             patch('subprocess.run', return_value=result):
            assert instance.check_git_status(str(cert)) is True
            git_ca.write_text(SYSTEM_PEM + ROOT_PEM + INTERMEDIATE_PEM)
            assert instance.check_git_status(str(cert)) is False


class TestChainInstallWindows:
    """keytool and X509Certificate2 read only the first certificate of a file."""

    def test_java_imports_each_certificate_under_its_own_alias(self, tmp_path):
        cert_path = tmp_path / "netskope-ca.pem"
        cert_path.write_text(ROOT_PEM + INTERMEDIATE_PEM)
        java_home = tmp_path / "jdk"
        (java_home / "lib" / "security").mkdir(parents=True)
        (java_home / "lib" / "security" / "cacerts").write_bytes(b"")
        instance = _windows_instance()
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if "-import" in cmd:
                part = cmd[cmd.index("-file") + 1]
                with open(part) as f:
                    assert len(fumitm_windows.FumitmWindows._pem_blocks(f.read())) == 1
            return type('R', (), {'returncode': 0 if "-import" in cmd else 1, 'stdout': b'', 'stderr': b''})()

        with patch.object(fumitm_windows, 'CERT_PATH', str(cert_path)), \
             patch.object(instance, 'command_exists', return_value=True), \
             patch.dict(os.environ, {"JAVA_HOME": str(java_home)}), \
             patch('subprocess.run', side_effect=fake_run):
            instance.setup_java_cert()
        imported = [cmd[cmd.index("-alias") + 1] for cmd in calls if "-import" in cmd]
        assert imported == ["netskope-zerotrust", "netskope-zerotrust-2"]

    def test_java_status_requires_every_alias(self, tmp_path):
        cert = tmp_path / "current.pem"
        cert.write_text(ROOT_PEM + INTERMEDIATE_PEM)
        instance = _windows_instance(mode="status")
        installed = {"netskope-zerotrust"}

        def fake_run(cmd, **kwargs):
            alias = cmd[cmd.index("-alias") + 1]
            found = alias in installed
            return type('R', (), {'returncode': 0 if found else 1,
                                  'stdout': alias.encode() if found else b'', 'stderr': b''})()

        with patch.object(instance, 'command_exists', return_value=True), \
             patch('subprocess.run', side_effect=fake_run):
            assert instance.check_java_status(str(cert)) is True
            installed.add("netskope-zerotrust-2")
            assert instance.check_java_status(str(cert)) is False

    def test_git_missing_ca_file_with_empty_export_creates_nothing(self, tmp_path):
        cert_path = tmp_path / "netskope-ca.pem"
        cert_path.write_text(ROOT_PEM)
        missing = tmp_path / "newdir" / "git-ca.pem"
        instance = _windows_instance()
        result = type('R', (), {'returncode': 0, 'stdout': str(missing) + "\n", 'stderr': ''})()
        with patch.object(fumitm_windows, 'CERT_PATH', str(cert_path)), \
             patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'get_system_ca_bundle', return_value=""), \
             patch.object(instance, 'setup_consistent_bundle', return_value=None), \
             patch('subprocess.run', return_value=result):
            instance.setup_git_cert()
        assert not missing.parent.exists()

    def test_store_install_splits_the_chain(self, tmp_path):
        cert_path = tmp_path / "netskope-ca.pem"
        cert_path.write_text(ROOT_PEM + INTERMEDIATE_PEM)
        instance = _windows_instance()
        scripts = []

        def fake_run(cmd, **kwargs):
            scripts.append(cmd[-1])
            return type('R', (), {'returncode': 0, 'stdout': 'Root', 'stderr': ''})()

        with patch('subprocess.run', side_effect=fake_run):
            assert instance.install_certificate_to_store(str(cert_path), "Root") is True
        assert len(scripts) == 2
        assert all("$cert.Subject -eq $cert.Issuer" in s for s in scripts)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
