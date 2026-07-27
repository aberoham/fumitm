"""
Integration tests for fumitm_windows.py

These tests verify the Windows port's functionality, particularly the
certificate appending logic and newline handling fix for issue #13.
"""
import re
import sys
from unittest.mock import patch

import pytest

# Skip entire module on non-Windows platforms
if sys.platform != 'win32':
    pytest.skip("Windows-only tests", allow_module_level=True)

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

        # Create instance and mock certificate_exists_in_file to return True
        # (since mock certificates don't work with openssl fingerprint check)
        with patch('platform.system', return_value='Windows'):
            instance = fumitm_windows.FumitmWindows(mode='install', debug=True)
            with patch.object(instance, 'certificate_exists_in_file', return_value=True):
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


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
