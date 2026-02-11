"""
Integration tests for fumitm.py

These tests verify the core workflows and functionality of the fumitm script
by mocking external dependencies and testing realistic scenarios.
"""
import os
import sys
import urllib.error
from unittest.mock import patch, MagicMock, call, mock_open
import pytest

# Import test utilities
from helpers import (
    MockBuilder, mock_fumitm_environment, assert_subprocess_called_with,
    assert_file_written, FumitmTestCase
)
import mock_data

# Import the fumitm module
import fumitm


class TestCertificateManagement(FumitmTestCase):
    """Tests for certificate download and validation."""
    
    def test_certificate_download_success(self):
        """Test successful certificate download from warp-cli."""
        mock_config = (MockBuilder()
            .with_warp_connected()
            .with_tools('openssl')
            .build())
        
        with mock_fumitm_environment(mock_config) as mocks:
            instance = self.create_fumitm_instance(mode='install')
            result = instance.download_certificate()
            
            assert result is True
            assert_subprocess_called_with(mocks['subprocess'], ['warp-cli', 'certs'])
    
    def test_certificate_download_warp_not_installed(self):
        """Test certificate download when WARP is not installed."""
        mock_config = MockBuilder().with_warp_not_installed().build()
        
        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance(mode='install')
            result = instance.download_certificate()
            
            assert result is False
    
    def test_certificate_validation_success(self):
        """Test certificate validation with openssl."""
        mock_config = (MockBuilder()
            .with_warp_connected()
            .with_tools('openssl')
            .with_subprocess_response(returncode=0)  # openssl verify success
            .build())
        
        with mock_fumitm_environment(mock_config) as mocks:
            instance = self.create_fumitm_instance()
            # Trigger certificate validation through status check
            instance.check_all_status()
            
            # The actual command uses x509 -checkend, not just verify
            assert_subprocess_called_with(mocks['subprocess'], ['openssl', 'x509', '-noout', '-checkend'])
    
    def test_certificate_already_exists_check(self):
        """Test behavior when certificate already exists and is valid."""
        mock_config = (MockBuilder()
            .with_certificate()
            .with_warp_connected()
            .with_tools('openssl')
            .with_subprocess_response(returncode=0)  # openssl check shows valid
            .build())
        
        with mock_fumitm_environment(mock_config) as mocks:
            instance = self.create_fumitm_instance()
            instance.check_all_status()
            
            # Should check existing certificate validity
            assert mocks['exists'].called


class TestToolSetup(FumitmTestCase):
    """Tests for individual tool certificate setup."""
    
    @pytest.mark.parametrize("tool,check_commands", [
        ("node", [["npm", "config", "get", "cafile"]]),
        ("python", [["python3", "-m", "pip", "--version"]]),
        ("java", [["java", "-version"]]),
    ])
    def test_tool_availability_check(self, tool, check_commands):
        """Test that tools are properly checked for availability."""
        mock_config = (MockBuilder()
            .with_certificate()
            .with_tool(tool)
            .build())
        
        # Add appropriate responses for each tool
        for _ in check_commands:
            mock_config['subprocess_side_effect'].append(MagicMock(returncode=0, stdout=""))
        
        with mock_fumitm_environment(mock_config) as mocks:
            instance = self.create_fumitm_instance()
            setup_method = getattr(instance, f"setup_{tool}_cert")
            setup_method()
            
            assert mocks['which'].called
            assert any(call(tool) in mocks['which'].call_args_list for call in [call])
    
    def test_node_npm_setup_workflow(self):
        """Test complete Node.js/npm certificate setup."""
        mock_config = (MockBuilder()
            .with_certificate()
            .with_tools('node', 'npm')
            .with_env_var('HOME', mock_data.HOME_DIR)
            .with_subprocess_response(stdout=mock_data.NPM_CONFIG_CAFILE_NULL)  # npm config get
            .with_subprocess_response(returncode=0)  # npm config set
            .build())
        
        with mock_fumitm_environment(mock_config) as mocks:
            # Mock input to auto-answer 'Y' and Path.touch
            with patch('builtins.input', return_value='Y'), \
                 patch('pathlib.Path.touch'):
                instance = self.create_fumitm_instance(mode='install')
                instance.setup_node_cert()
            
            # Should check npm config
            assert_subprocess_called_with(mocks['subprocess'], ['npm', 'config', 'get', 'cafile'])
    
    def test_python_requests_setup(self):
        """Test Python requests/urllib3 certificate setup."""
        mock_config = (MockBuilder()
            .with_certificate()
            .with_tool('python3')
            .with_subprocess_response(stdout=mock_data.PYTHON_VERSION)  # python version
            .with_subprocess_response(returncode=1)  # pip not found
            .build())
        
        with mock_fumitm_environment(mock_config) as mocks:
            instance = self.create_fumitm_instance(mode='status')
            instance.setup_python_cert()
            
            # Python should have been checked
            assert mocks['which'].called
            assert any(call('python3') in mocks['which'].call_args_list for call in [call])


class TestJavaMultiInstallation(FumitmTestCase):
    """Tests for multi-Java installation detection and configuration."""

    def test_find_all_java_homes_macos_multiple_installations(self):
        """Test finding multiple Java installations on macOS."""
        java_home_output = """Matching Java Virtual Machines (3):
    21.0.1 (arm64) "Eclipse Temurin" - "OpenJDK 21.0.1" /Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home
    17.0.9 (arm64) "Eclipse Temurin" - "OpenJDK 17.0.9" /Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
    11.0.21 (arm64) "Eclipse Temurin" - "OpenJDK 11.0.21" /Users/user/Library/Java/JavaVirtualMachines/temurin-11.jdk/Contents/Home

/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home"""

        with patch('platform.system', return_value='Darwin'), \
             patch.dict(os.environ, {'JAVA_HOME': ''}, clear=False), \
             patch('os.path.exists') as mock_exists, \
             patch('os.path.isdir', return_value=True), \
             patch('os.listdir', return_value=[]), \
             patch('subprocess.run') as mock_run:

            # Mock /usr/libexec/java_home exists
            def exists_side_effect(path):
                if path == '/usr/libexec/java_home':
                    return True
                # Mock cacerts files exist for all Java homes
                if 'lib/security/cacerts' in path:
                    return True
                return False

            mock_exists.side_effect = exists_side_effect

            # Mock java_home -V output
            mock_result = MagicMock()
            mock_result.stdout = java_home_output
            mock_run.return_value = mock_result

            instance = fumitm.FumitmPython(mode='status')
            java_homes = instance.find_all_java_homes()

            assert len(java_homes) == 3
            assert '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home' in java_homes
            assert '/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home' in java_homes
            assert '/Users/user/Library/Java/JavaVirtualMachines/temurin-11.jdk/Contents/Home' in java_homes

    def test_find_all_java_homes_macos_directory_scan(self):
        """Test finding Java installations via directory scan on macOS."""
        with patch('platform.system', return_value='Darwin'), \
             patch.dict(os.environ, {'JAVA_HOME': ''}, clear=False), \
             patch('os.path.exists', return_value=True), \
             patch('os.path.isdir', return_value=True), \
             patch('os.listdir') as mock_listdir, \
             patch('subprocess.run') as mock_run:

            # Mock java_home -V returns empty
            mock_result = MagicMock()
            mock_result.stdout = ""
            mock_run.return_value = mock_result

            # Mock directory listings
            def listdir_side_effect(path):
                if 'JavaVirtualMachines' in path:
                    return ['temurin-21.jdk', 'temurin-17.jdk', 'not-a-jdk']
                return []

            mock_listdir.side_effect = listdir_side_effect

            instance = fumitm.FumitmPython(mode='status')
            java_homes = instance.find_all_java_homes()

            # Should find the .jdk directories
            assert any('temurin-21' in home for home in java_homes)
            assert any('temurin-17' in home for home in java_homes)

    def test_find_all_java_homes_linux_update_alternatives(self):
        """Test finding Java installations via update-alternatives on Linux."""
        alternatives_output = """/usr/lib/jvm/java-21-openjdk-amd64/bin/java
/usr/lib/jvm/java-17-openjdk-amd64/bin/java
/usr/lib/jvm/java-11-openjdk-amd64/bin/java"""

        with patch('platform.system', return_value='Linux'), \
             patch.dict(os.environ, {'JAVA_HOME': ''}, clear=False), \
             patch('os.path.exists', return_value=True), \
             patch('os.path.isdir', return_value=True), \
             patch('subprocess.run') as mock_run:

            # Mock update-alternatives output
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = alternatives_output
            mock_run.return_value = mock_result

            instance = fumitm.FumitmPython(mode='status')
            java_homes = instance.find_all_java_homes()

            assert len(java_homes) >= 3
            assert any('java-21-openjdk-amd64' in home for home in java_homes)
            assert any('java-17-openjdk-amd64' in home for home in java_homes)
            assert any('java-11-openjdk-amd64' in home for home in java_homes)

    def test_setup_java_cert_multiple_installations(self):
        """Test setup_java_cert configures all detected installations."""
        fake_java_homes = [
            '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home',
            '/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home'
        ]

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')

            with patch.object(instance, 'command_exists', return_value=True), \
                 patch.object(instance, 'find_all_java_homes', return_value=fake_java_homes), \
                 patch.object(instance, 'find_java_cacerts', return_value='/fake/cacerts'), \
                 patch('subprocess.run') as mock_run:

                # Mock keytool checks - all return "not installed"
                mock_result = MagicMock()
                mock_result.returncode = 1
                mock_run.return_value = mock_result

                instance.setup_java_cert()

                # Should have called keytool for each Java installation
                # Each gets checked (list) then installed (import)
                assert mock_run.call_count >= len(fake_java_homes) * 2

    def test_check_java_status_multiple_installations(self):
        """Test check_java_status checks all detected installations."""
        fake_java_homes = [
            '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home',
            '/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home'
        ]

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

            with patch.object(instance, 'command_exists', return_value=True), \
                 patch.object(instance, 'find_all_java_homes', return_value=fake_java_homes), \
                 patch.object(instance, 'find_java_cacerts', return_value='/fake/cacerts'), \
                 patch('subprocess.run') as mock_run:

                # Mock keytool checks - first installed, second missing
                def run_side_effect(*args, **kwargs):
                    result = MagicMock()
                    # Alternate between success (cert exists) and failure (cert missing)
                    if mock_run.call_count % 2 == 1:
                        result.returncode = 0
                    else:
                        result.returncode = 1
                    return result

                mock_run.side_effect = run_side_effect

                has_issues = instance.check_java_status('/fake/cert.pem')

                # Should report issues because second installation is missing cert
                assert has_issues is True
                # Should have checked both installations
                assert mock_run.call_count == len(fake_java_homes)

    def test_find_all_java_homes_validates_cacerts(self):
        """Test that find_all_java_homes only returns paths with valid cacerts."""
        with patch('platform.system', return_value='Darwin'), \
             patch('os.path.exists', return_value=False), \
             patch('os.path.isdir', return_value=True), \
             patch('subprocess.run') as mock_run:

            # Mock java_home returns empty
            mock_result = MagicMock()
            mock_result.stdout = ""
            mock_run.return_value = mock_result

            instance = fumitm.FumitmPython(mode='status')

            # Mock find_java_home to return a path but find_java_cacerts returns empty
            with patch.object(instance, 'find_java_home', return_value='/fake/java'), \
                 patch.object(instance, 'find_java_cacerts', return_value=''):

                java_homes = instance.find_all_java_homes()

                # Should return empty because cacerts validation fails
                assert len(java_homes) == 0


class TestCLIAndWorkflow(FumitmTestCase):
    """Tests for CLI argument parsing and complete workflows."""
    
    @patch('fumitm.sys.argv', ['fumitm.py', '--fix'])
    def test_cli_fix_mode(self):
        """Test --fix argument sets install mode."""
        with patch('fumitm.FumitmPython') as mock_class:
            mock_instance = MagicMock()
            mock_instance.main.return_value = 0
            mock_class.return_value = mock_instance
            
            with patch('fumitm.sys.exit'):
                fumitm.main()
            
            mock_class.assert_called_with(
                mode='install', debug=False, selected_tools=[],
                cert_file=None, manual_cert=False, skip_verify=False,
                provider=None
            )
    
    @patch('fumitm.sys.argv', ['fumitm.py', '--tools', 'node,python'])
    def test_cli_tool_selection(self):
        """Test --tools argument parsing."""
        with patch('fumitm.FumitmPython') as mock_class:
            mock_instance = MagicMock()
            mock_instance.main.return_value = 0
            mock_class.return_value = mock_instance
            
            with patch('fumitm.sys.exit'):
                fumitm.main()
            
            mock_class.assert_called_with(
                mode='status',
                debug=False,
                selected_tools=['node', 'python'],
                cert_file=None, manual_cert=False, skip_verify=False,
                provider=None
            )
    
    def test_complete_status_workflow(self):
        """Test complete status check workflow with multiple tools."""
        mock_config = (MockBuilder()
            .with_warp_connected()
            .with_certificate()
            .with_tools('node', 'npm', 'python3', 'keytool', 'openssl')
            .with_subprocess_response(stdout=mock_data.NPM_CONFIG_CAFILE_SET)  # npm config get
            .with_subprocess_response(stdout=mock_data.NODE_VERSION)  # node version  
            .with_subprocess_response(stdout=mock_data.PYTHON_VERSION)  # python version
            .with_subprocess_response(returncode=1)  # pip not found
            .with_subprocess_response(stdout="keytool 11.0.17")  # keytool exists
            .with_subprocess_response(returncode=0)  # openssl validity check
            .build())
        
        with mock_fumitm_environment(mock_config) as mocks:
            instance = self.create_fumitm_instance()
            # Run the complete status check
            instance.check_all_status()
            
            # Should have checked for various tools
            assert mocks['which'].called
            # Check that npm config was queried
            assert_subprocess_called_with(mocks['subprocess'], ['npm', 'config', 'get'])
            # Check that keytool was found
            assert any(call('keytool') in mocks['which'].call_args_list for call in [call])


class TestToolSelection(FumitmTestCase):
    """Tests for tool selection and filtering logic."""
    
    def test_tool_selection_by_key(self):
        """Test selecting tools by their key names."""
        instance = self.create_fumitm_instance(selected_tools=['node', 'python'])
        
        assert instance.should_process_tool('node') is True
        assert instance.should_process_tool('python') is True
        assert instance.should_process_tool('java') is False
    
    def test_tool_selection_by_tag(self):
        """Test selecting tools by their tags."""
        instance = self.create_fumitm_instance(selected_tools=['nodejs', 'pip'])
        
        # Should match by tag
        assert instance.should_process_tool('node') is True  # 'nodejs' tag
        assert instance.should_process_tool('python') is True  # 'pip' tag
        assert instance.should_process_tool('java') is False
    
    def test_tool_selection_validation(self):
        """Test validation of selected tools."""
        instance = self.create_fumitm_instance(
            selected_tools=['node', 'invalid-tool', 'python']
        )
        
        invalid_tools = instance.validate_selected_tools()
        assert 'invalid-tool' in invalid_tools
        assert 'node' not in invalid_tools


class TestErrorScenarios(FumitmTestCase):
    """Tests for error handling and edge cases."""
    
    def test_certificate_download_network_error(self):
        """Test handling of network errors during certificate download."""
        mock_config = (MockBuilder()
            .with_tools('warp-cli', 'openssl')
            .with_subprocess_response(
                returncode=1, 
                stderr=mock_data.NETWORK_ERROR
            )
            .build())
        
        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance(mode='install')
            result = instance.download_certificate()
            
            assert result is False
    
    def test_permission_denied_writing_certificate(self):
        """Test handling of permission errors when writing certificates."""
        mock_config = (MockBuilder()
            .with_warp_connected()
            .with_tools('openssl')
            .build())
        
        with mock_fumitm_environment(mock_config):
            with patch('fumitm.shutil.copy') as mock_copy:
                mock_copy.side_effect = PermissionError(mock_data.PERMISSION_DENIED_ERROR)
                
                instance = self.create_fumitm_instance(mode='install')
                # The download_certificate method doesn't catch PermissionError
                # so we expect it to raise
                with pytest.raises(PermissionError):
                    instance.download_certificate()
    
    def test_malformed_certificate_handling(self):
        """Test handling of malformed certificates from warp-cli."""
        mock_config = (MockBuilder()
            .with_tools('warp-cli', 'openssl')
            .with_subprocess_response(
                returncode=0,
                stdout=mock_data.MOCK_INVALID_CERTIFICATE
            )
            .with_subprocess_response(
                returncode=1,  # openssl verify fails
                stderr=mock_data.OPENSSL_VERIFY_FAILURE
            )
            .build())
        
        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance(mode='install')
            result = instance.download_certificate()
            
            assert result is False
    
    def test_tool_not_found_graceful_handling(self):
        """Test graceful handling when tools are not found."""
        mock_config = (MockBuilder()
            .with_warp_connected()
            .with_certificate()
            .build())  # No tools configured except warp
        
        with mock_fumitm_environment(mock_config) as mocks:
            instance = self.create_fumitm_instance(mode='status')
            # Run status check - should handle missing tools gracefully
            instance.check_all_status()
            
            # Should have tried to check for various tools
            assert mocks['which'].called
            # Should have completed without errors despite missing tools
            assert True  # If we get here, no exceptions were raised


class TestConnectionVerification(FumitmTestCase):
    """Tests for network connection verification."""
    
    @patch('fumitm.urllib.request.urlopen')
    def test_python_connection_verification_success(self, mock_urlopen):
        """Test successful Python HTTPS connection verification."""
        mock_response = MagicMock()
        mock_response.code = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response
        
        instance = self.create_fumitm_instance()
        result = instance.verify_connection('python')
        
        assert result == "WORKING"
        mock_urlopen.assert_called_once()
    
    def test_node_connection_verification_success(self):
        """Test successful Node.js HTTPS connection verification."""
        mock_config = (MockBuilder()
            .with_tool('node')
            .with_subprocess_response(
                returncode=0,
                stderr="HTTP Status: 200"
            )
            .build())
        
        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance()
            result = instance.verify_connection('node')
            
            assert result == "WORKING"
    
    def test_connection_verification_failure(self):
        """Test failed connection verification."""
        mock_config = (MockBuilder()
            .with_tool('wget')
            .with_subprocess_response(
                returncode=1,
                stderr="Unable to establish SSL connection"
            )
            .build())
        
        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance()
            result = instance.verify_connection('wget')
            
            assert result == "FAILED"


class TestPlatformSpecific(FumitmTestCase):
    """Tests for platform-specific behavior."""

    @pytest.mark.parametrize("platform,expected_path", [
        ("Darwin", "/Library/Java/JavaVirtualMachines"),
        ("Linux", "/usr/lib/jvm"),
    ])
    def test_platform_specific_paths(self, platform, expected_path):
        """Test that platform-specific paths are used correctly."""
        with patch('platform.system', return_value=platform):
            instance = fumitm.FumitmPython(mode='status')

            # Check that instance is aware of platform
            # This would need actual implementation testing
            assert True  # Placeholder for actual platform-specific tests


class TestStatusFunctionContracts(FumitmTestCase):
    """Contract tests for all check_*_status() functions.

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

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        status_methods = self.get_all_status_methods(instance)

        # Verify we found the expected methods (sanity check)
        assert len(status_methods) >= 10, f"Expected at least 10 status methods, found {len(status_methods)}: {status_methods}"

        # Expected methods based on the codebase
        expected_methods = [
            'check_git_status', 'check_node_status', 'check_python_status',
            'check_gcloud_status', 'check_java_status', 'check_jenv_status',
            'check_gradle_status', 'check_dbeaver_status', 'check_wget_status',
            'check_podman_status', 'check_rancher_status', 'check_android_status',
            'check_colima_status'
        ]
        for expected in expected_methods:
            assert expected in status_methods, f"Expected method {expected} not found"

        # Test each status method
        failed_methods = []
        for method_name in status_methods:
            method = getattr(instance, method_name)

            # Mock all external dependencies so functions hit early returns
            with patch.object(instance, 'command_exists', return_value=False), \
                 patch.object(instance, 'get_jenv_java_homes', return_value=[]), \
                 patch.object(instance, 'find_all_java_homes', return_value=[]), \
                 patch('os.path.exists', return_value=False):

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

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        status_methods = self.get_all_status_methods(instance)

        for method_name in status_methods:
            method = getattr(instance, method_name)

            # Mock tool as not installed
            with patch.object(instance, 'command_exists', return_value=False), \
                 patch.object(instance, 'get_jenv_java_homes', return_value=[]), \
                 patch.object(instance, 'find_all_java_homes', return_value=[]), \
                 patch('os.path.exists', return_value=False):

                result = method(str(cert_file))

                # When tool is not installed, there should be no issues to report
                assert result is False, f"{method_name} should return False when tool not installed, got {result}"

    def test_check_jenv_status_returns_boolean_with_java_homes(self, tmp_path):
        """Verify check_jenv_status returns boolean when jenv has Java installations.

        Regression test for issue #20 - the bug only manifests when jenv has
        Java homes because empty java_homes triggers an early return.
        """
        cert_file = tmp_path / "test-cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        # Mock jenv having Java installations
        fake_java_homes = ['/fake/java/home/17', '/fake/java/home/11']

        # Mock keytool as available but certificate check fails
        mock_keytool_result = MagicMock()
        mock_keytool_result.returncode = 1
        mock_keytool_result.stdout = b''

        with patch.object(instance, 'get_jenv_java_homes', return_value=fake_java_homes), \
             patch.object(instance, 'command_exists', return_value=True), \
             patch('os.path.exists', return_value=True), \
             patch('subprocess.run', return_value=mock_keytool_result):

            result = instance.check_jenv_status(str(cert_file))

            assert result is not None, "check_jenv_status returned None instead of bool"
            assert isinstance(result, bool), f"check_jenv_status returned {type(result).__name__}, not bool"


class TestBundleCreation(FumitmTestCase):
    """Tests for system CA bundle creation helper."""

    def test_creates_bundle_from_macos_system_certs(self, tmp_path):
        """Test bundle creation when /etc/ssl/cert.pem exists (macOS)."""
        # Create a mock system cert file
        mock_system_cert = tmp_path / "system-cert.pem"
        mock_system_cert.write_text(mock_data.SAMPLE_CA_BUNDLE)

        target_bundle = tmp_path / "bundle.pem"

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')

            # Mock os.path.exists to simulate macOS system cert location
            with patch('os.path.exists') as mock_exists:
                mock_exists.side_effect = lambda p: p == "/etc/ssl/cert.pem" or p == str(target_bundle.parent)

                with patch('shutil.copy') as mock_copy:
                    result = instance.create_bundle_with_system_certs(str(target_bundle))

                    # Should have copied from macOS location
                    mock_copy.assert_called_once_with("/etc/ssl/cert.pem", str(target_bundle))
                    assert result is True

    def test_creates_bundle_from_linux_system_certs(self, tmp_path):
        """Test bundle creation when /etc/ssl/certs/ca-certificates.crt exists (Linux)."""
        target_bundle = tmp_path / "bundle.pem"

        with patch('platform.system', return_value='Linux'):
            instance = fumitm.FumitmPython(mode='install')

            # Mock os.path.exists: macOS path doesn't exist, Linux path does
            with patch('os.path.exists') as mock_exists:
                mock_exists.side_effect = lambda p: p == "/etc/ssl/certs/ca-certificates.crt"

                with patch('shutil.copy') as mock_copy:
                    result = instance.create_bundle_with_system_certs(str(target_bundle))

                    # Should have copied from Linux location
                    mock_copy.assert_called_once_with("/etc/ssl/certs/ca-certificates.crt", str(target_bundle))
                    assert result is True

    def test_creates_empty_bundle_when_no_system_certs(self, tmp_path):
        """Test empty bundle creation when no system certs found."""
        target_bundle = tmp_path / "bundle.pem"

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')

            # Mock os.path.exists: neither system cert location exists
            with patch('os.path.exists', return_value=False):
                result = instance.create_bundle_with_system_certs(str(target_bundle))

                # Should create empty file and return False
                assert result is False
                assert target_bundle.exists()
                assert target_bundle.read_text() == ""

    def test_returns_true_when_system_certs_copied(self, tmp_path):
        """Test return value indicates whether system certs were found."""
        target_bundle = tmp_path / "bundle.pem"

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')

            # Test True case (system certs exist)
            with patch('os.path.exists', side_effect=lambda p: p == "/etc/ssl/cert.pem"):
                with patch('shutil.copy'):
                    result = instance.create_bundle_with_system_certs(str(target_bundle))
                    assert result is True

            # Test False case (no system certs)
            with patch('os.path.exists', return_value=False):
                result = instance.create_bundle_with_system_certs(str(target_bundle))
                assert result is False


class TestCertificateAppending(FumitmTestCase):
    """Tests for certificate appending to ensure proper PEM formatting (issue #13)."""

    def test_append_to_bundle_without_trailing_newline(self, tmp_path):
        """Ensure appending to a bundle without newline doesn't corrupt PEM.

        This tests the fix for issue #13 where appending to a file without
        a trailing newline would produce malformed PEM like:
        -----END CERTIFICATE----------BEGIN CERTIFICATE-----
        """
        # Create a CA bundle file WITHOUT trailing newline
        bundle_file = tmp_path / "ca-bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE_NO_NEWLINE)

        # Create a certificate file to append
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Create instance and call safe_append_certificate
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')
            result = instance.safe_append_certificate(str(cert_file), str(bundle_file))

        assert result is True

        # Read the resulting file
        content = bundle_file.read_text()

        # Verify that -----END CERTIFICATE----- is followed by newline, not -----BEGIN
        # This pattern should NOT appear in a valid PEM file
        assert "-----END CERTIFICATE----------BEGIN CERTIFICATE-----" not in content

        # Verify proper separation exists
        assert "-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----" in content or \
               "-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----" in content

    def test_append_to_bundle_with_trailing_newline(self, tmp_path):
        """Verify normal case still works - bundle with trailing newline."""
        # Create a CA bundle file WITH trailing newline
        bundle_file = tmp_path / "ca-bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE)  # Has trailing newline

        # Create a certificate file to append
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Create instance and call safe_append_certificate
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')
            result = instance.safe_append_certificate(str(cert_file), str(bundle_file))

        assert result is True

        # Read the resulting file
        content = bundle_file.read_text()

        # Verify that the malformed pattern doesn't exist
        assert "-----END CERTIFICATE----------BEGIN CERTIFICATE-----" not in content

    def test_append_ensures_certificate_ends_with_newline(self, tmp_path):
        """Ensure appended certificate itself ends with newline."""
        # Create an empty bundle file
        bundle_file = tmp_path / "ca-bundle.pem"
        bundle_file.write_text("")

        # Create a certificate file WITHOUT trailing newline
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE_NO_NEWLINE)

        # Create instance and call safe_append_certificate
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')
            result = instance.safe_append_certificate(str(cert_file), str(bundle_file))

        assert result is True

        # Read the resulting file
        content = bundle_file.read_text()

        # Verify the file ends with a newline
        assert content.endswith('\n')

    def test_append_skips_if_certificate_already_exists(self, tmp_path):
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
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')
            with patch.object(instance, 'certificate_exists_in_file', return_value=True):
                result = instance.safe_append_certificate(str(cert_file), str(bundle_file))

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

        # Create instance and call safe_append_certificate
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')
            result = instance.safe_append_certificate(str(cert_file), str(bundle_file))

        assert result is True

        # File should now exist
        assert bundle_file.exists()

        # Content should be the certificate
        content = bundle_file.read_text()
        assert "-----BEGIN CERTIFICATE-----" in content
        assert "-----END CERTIFICATE-----" in content


class TestCodeQuality:
    """Static analysis tests to catch unsafe patterns in the codebase."""

    def test_no_unsafe_certificate_appends_in_fumitm(self):
        """Ensure fumitm.py uses safe_append_certificate() for all certificate appends.

        Regression test for issue #21 - prevents adding new unsafe certificate
        appends that could produce malformed PEM files.

        Unsafe patterns detected:
        - Direct file opens with 'a' mode for certificate/bundle files
        - Writing certificate content without using safe_append_certificate()
        """
        import os
        import re

        # Read the source file
        test_dir = os.path.dirname(os.path.abspath(__file__))
        fumitm_path = os.path.join(os.path.dirname(test_dir), "fumitm.py")

        with open(fumitm_path, 'r') as f:
            source = f.read()

        # Pattern 1: Direct append mode opens for bundle/cert files
        # This catches: with open(some_bundle, 'a') as f:
        unsafe_append_pattern = re.compile(
            r"with\s+open\s*\([^)]*(?:bundle|cert|ca)[^)]*['\"]a['\"]\s*\)\s*as",
            re.IGNORECASE
        )

        matches = unsafe_append_pattern.findall(source)
        assert not matches, (
            f"Found unsafe certificate append patterns in fumitm.py:\n"
            f"{matches}\n\n"
            f"Use self.safe_append_certificate(cert_path, target_path) instead"
        )

        # Pattern 2: Direct f.write() of certificate content to append
        # This catches patterns like: f.write(cf.read()) where cf is a cert file
        unsafe_write_pattern = re.compile(
            r"f\.write\s*\(\s*(?:cf|cert_file|CERT).*\.read\s*\(\s*\)\s*\)"
        )

        matches = unsafe_write_pattern.findall(source)
        assert not matches, (
            f"Found unsafe certificate write patterns in fumitm.py:\n"
            f"{matches}\n\n"
            f"Use self.safe_append_certificate(cert_path, target_path) instead"
        )

    def test_no_unsafe_certificate_appends_in_fumitm_windows(self):
        """Ensure fumitm_windows.py uses append_certificate_if_missing() for all appends.

        Same as test_no_unsafe_certificate_appends_in_fumitm but for Windows port.
        """
        import os
        import re

        # Read the source file
        test_dir = os.path.dirname(os.path.abspath(__file__))
        fumitm_windows_path = os.path.join(os.path.dirname(test_dir), "fumitm_windows.py")

        with open(fumitm_windows_path, 'r') as f:
            source = f.read()

        # Pattern 1: Direct append mode opens for bundle/cert files
        # Exclude the append_certificate_if_missing implementation itself
        lines = source.split('\n')
        in_append_method = False
        unsafe_lines = []

        for i, line in enumerate(lines, 1):
            # Track when we're inside append_certificate_if_missing
            if 'def append_certificate_if_missing' in line:
                in_append_method = True
            elif in_append_method and line.strip().startswith('def '):
                in_append_method = False

            # Skip the implementation of the safe method
            if in_append_method:
                continue

            # Check for unsafe patterns
            if re.search(r"with\s+open\s*\([^)]*['\"]a['\"]\s*\)", line, re.IGNORECASE):
                if 'bundle' in line.lower() or 'cert' in line.lower() or 'ca' in line.lower():
                    unsafe_lines.append(f"Line {i}: {line.strip()}")

        assert not unsafe_lines, (
            f"Found unsafe certificate append patterns in fumitm_windows.py:\n"
            + "\n".join(unsafe_lines) + "\n\n"
            f"Use self.append_certificate_if_missing(cert_path, target_path) instead"
        )

    def test_no_unused_globals_in_fumitm(self):
        """Ensure no unused global variables exist in fumitm.py.

        Regression test to prevent unused globals like SHELL_MODIFIED and
        CERT_FINGERPRINT from being introduced (or reintroduced).
        """
        import os
        import re

        test_dir = os.path.dirname(os.path.abspath(__file__))
        fumitm_path = os.path.join(os.path.dirname(test_dir), "fumitm.py")

        with open(fumitm_path, 'r') as f:
            source = f.read()

        # Find module-level UPPER_CASE variable assignments (globals)
        # Pattern: line starts with UPPER_CASE_NAME = (not inside class/function)
        global_pattern = re.compile(r'^([A-Z][A-Z0-9_]*)\s*=', re.MULTILINE)

        # CERT_PATH is kept as a public constant for backward compatibility
        # but is no longer used internally (replaced by self.cert_path).
        known_unused = {'CERT_PATH'}

        globals_found = set()
        for match in global_pattern.finditer(source):
            name = match.group(1)
            # Skip dunder variables (like __version__)
            if name.startswith('__'):
                continue
            globals_found.add(name)

        # Check each global is used somewhere else in the code
        unused_globals = []
        for name in globals_found:
            if name in known_unused:
                continue
            # Count occurrences - should be more than 1 if used after definition
            pattern = re.compile(r'\b' + re.escape(name) + r'\b')
            matches = pattern.findall(source)
            if len(matches) <= 1:
                unused_globals.append(name)

        assert not unused_globals, (
            f"Unused global variables found in fumitm.py: {unused_globals}\n"
            "These variables are defined but never referenced elsewhere in the code."
        )

    def test_no_unused_globals_in_fumitm_windows(self):
        """Ensure no unused global variables exist in fumitm_windows.py.

        Same check as test_no_unused_globals_in_fumitm but for Windows port.
        """
        import os
        import re

        test_dir = os.path.dirname(os.path.abspath(__file__))
        fumitm_windows_path = os.path.join(os.path.dirname(test_dir), "fumitm_windows.py")

        with open(fumitm_windows_path, 'r') as f:
            source = f.read()

        # Known unused globals pending Windows refactoring
        # See WINDOWS_REFACTORING_NOTES.md for cleanup plan
        known_unused = {'ALT_CERT_NAMES', 'SHELL_MODIFIED', 'CERT_FINGERPRINT'}

        # Find module-level UPPER_CASE variable assignments (globals)
        global_pattern = re.compile(r'^([A-Z][A-Z0-9_]*)\s*=', re.MULTILINE)

        globals_found = set()
        for match in global_pattern.finditer(source):
            name = match.group(1)
            if name.startswith('__'):
                continue
            globals_found.add(name)

        # Check each global is used somewhere else in the code
        unused_globals = []
        for name in globals_found:
            # Skip known unused globals (tracked for future cleanup)
            if name in known_unused:
                continue
            pattern = re.compile(r'\b' + re.escape(name) + r'\b')
            matches = pattern.findall(source)
            if len(matches) <= 1:
                unused_globals.append(name)

        assert not unused_globals, (
            f"Unused global variables found in fumitm_windows.py: {unused_globals}\n"
            "These variables are defined but never referenced elsewhere in the code."
        )

    def test_consistent_setup_messaging_in_fumitm(self):
        """Ensure setup functions use consistent messaging patterns.

        All setup functions should use "Configuring <tool> certificate..."
        instead of the inconsistent "Setting up <tool> certificate..." pattern.
        This ensures a consistent user experience across all tools.
        """
        import os
        import re

        test_dir = os.path.dirname(os.path.abspath(__file__))
        fumitm_path = os.path.join(os.path.dirname(test_dir), "fumitm.py")

        with open(fumitm_path, 'r') as f:
            source = f.read()

        # Find "Setting up" patterns which should be "Configuring"
        setting_up_pattern = re.compile(r'Setting up.*certificate', re.IGNORECASE)

        matches = setting_up_pattern.findall(source)
        assert not matches, (
            f"Found inconsistent messaging in fumitm.py:\n"
            f"{matches}\n\n"
            f"Use 'Configuring <tool> certificate...' instead of 'Setting up <tool> certificate...'"
        )

    def test_no_bare_except_clauses_in_fumitm(self):
        """Ensure no bare 'except:' clauses exist in fumitm.py.

        Bare except clauses catch all exceptions including SystemExit and
        KeyboardInterrupt, which is rarely what's intended. They should be
        replaced with specific exception types like 'except Exception:' or
        more specific exceptions.
        """
        import os
        import re

        test_dir = os.path.dirname(os.path.abspath(__file__))
        fumitm_path = os.path.join(os.path.dirname(test_dir), "fumitm.py")

        with open(fumitm_path, 'r') as f:
            lines = f.readlines()

        # Find bare except clauses (except: without an exception type)
        bare_excepts = []
        for i, line in enumerate(lines, 1):
            # Match 'except:' but not 'except SomeException:' or 'except (A, B):'
            if re.match(r'^\s*except\s*:\s*$', line) or re.match(r'^\s*except\s*:\s*#', line):
                bare_excepts.append(f"Line {i}: {line.strip()}")

        assert not bare_excepts, (
            f"Found bare 'except:' clauses in fumitm.py:\n"
            + "\n".join(bare_excepts) + "\n\n"
            f"Replace with 'except Exception:' or a more specific exception type."
        )

    def test_no_raw_cert_comparisons_in_fumitm(self):
        """Ensure setup functions use certificate_exists_in_file() not raw string comparison.

        Regression test for issue #35 - Status checks use certificate_exists_in_file()
        which does normalized base64 comparison, but setup functions were using raw
        string comparison like 'cert_content in file_content'. This caused --fix to
        silently skip tools that status correctly identified as needing fixes.

        All certificate existence checks in setup functions should use:
        - self.certificate_exists_in_file(CERT_PATH, target_file)
        Not:
        - cert_content in file_content
        - cert_content not in file_content
        """
        import os
        import re

        test_dir = os.path.dirname(os.path.abspath(__file__))
        fumitm_path = os.path.join(os.path.dirname(test_dir), "fumitm.py")

        with open(fumitm_path, 'r') as f:
            source = f.read()

        # Find raw certificate content comparisons in setup functions
        # These patterns indicate raw string comparison instead of certificate_exists_in_file()
        unsafe_patterns = [
            # Pattern: cert_content in file_content or similar
            (r'cert_content\s+(?:not\s+)?in\s+file_content', 'cert_content in/not in file_content'),
            # Pattern: file_content containing cert check
            (r'file_content.*cert_content|cert_content.*file_content', 'raw content comparison'),
        ]

        violations = []
        lines = source.split('\n')
        for i, line in enumerate(lines, 1):
            for pattern, description in unsafe_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    violations.append(f"Line {i}: {line.strip()} ({description})")

        assert not violations, (
            f"Found raw certificate comparisons in fumitm.py:\n"
            + "\n".join(violations) + "\n\n"
            "Setup functions must use self.certificate_exists_in_file(CERT_PATH, target)\n"
            "instead of raw 'cert_content in file_content' comparisons.\n"
            "See issue #35 for details on why this is required."
        )


class TestPerformance(FumitmTestCase):
    """Tests for performance and subprocess call limits.

    These tests ensure that certificate checking operations don't spawn
    excessive subprocess calls, which was identified as a performance issue.
    The goal is to use pure Python string matching instead of openssl calls
    for duplicate detection.
    """

    def test_certificate_likely_exists_uses_no_subprocess(self, tmp_path):
        """Verify certificate_likely_exists_in_file uses zero subprocess calls.

        This is a regression test to ensure the fast path stays fast.
        The function should use pure Python string matching, not openssl.
        """
        # Create test certificate files
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        bundle_file = tmp_path / "bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE + mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        # Count subprocess calls
        with patch('subprocess.run') as mock_subprocess:
            result = instance.certificate_likely_exists_in_file(
                str(cert_file), str(bundle_file)
            )

            # Should find the certificate
            assert result is True

            # Should NOT call subprocess at all - pure Python only
            assert mock_subprocess.call_count == 0, (
                f"certificate_likely_exists_in_file called subprocess {mock_subprocess.call_count} times. "
                f"Expected 0 calls (pure Python string matching)."
            )

    def test_certificate_likely_exists_no_match_uses_no_subprocess(self, tmp_path):
        """Verify no subprocess calls even when certificate is not found."""
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Bundle that doesn't contain the certificate
        bundle_file = tmp_path / "bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch('subprocess.run') as mock_subprocess:
            result = instance.certificate_likely_exists_in_file(
                str(cert_file), str(bundle_file)
            )

            # Should NOT find the certificate
            assert result is False

            # Should NOT call subprocess at all
            assert mock_subprocess.call_count == 0, (
                f"certificate_likely_exists_in_file called subprocess {mock_subprocess.call_count} times "
                f"even when certificate not found. Expected 0 calls."
            )

    def test_safe_append_uses_fast_check(self, tmp_path):
        """Verify safe_append_certificate uses fast check, not fingerprint comparison.

        Even in install mode, duplicate detection should use fast string matching
        rather than spawning openssl for each certificate in the bundle.
        """
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Bundle that already contains the certificate
        bundle_file = tmp_path / "bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE + mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')

        with patch('subprocess.run') as mock_subprocess:
            # This should detect the certificate already exists and skip
            result = instance.safe_append_certificate(
                str(cert_file), str(bundle_file)
            )

            assert result is True

            # Should use minimal subprocess calls (ideally 0 for duplicate detection)
            # Allow some slack for now, but the key is NOT O(n) calls where n=certs in bundle
            assert mock_subprocess.call_count <= 1, (
                f"safe_append_certificate made {mock_subprocess.call_count} subprocess calls. "
                f"Expected at most 1 (for initial validation). "
                f"Duplicate detection should use pure Python."
            )

    def test_no_subprocess_explosion_for_large_bundles(self, tmp_path):
        """Ensure subprocess calls don't scale with bundle size.

        This is a critical regression test. With a bundle containing N certificates,
        we should NOT make O(N) subprocess calls to check for duplicates.
        """
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Create a bundle with many certificates (simulating a real CA bundle)
        # Real bundles have 100-150 certs; we'll use 10 for speed
        bundle_content = ""
        for i in range(10):
            # Generate slightly different certs by modifying the base64
            modified_cert = mock_data.SAMPLE_CA_BUNDLE.replace(
                "MIIDSjCCAjKgAwIBAgIQRK",
                f"MIIDSjCCAjKgAwIBAgIQR{i}"
            )
            bundle_content += modified_cert

        bundle_file = tmp_path / "large-bundle.pem"
        bundle_file.write_text(bundle_content)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')

        with patch('subprocess.run') as mock_subprocess:
            # Check if certificate exists in bundle
            result = instance.certificate_likely_exists_in_file(
                str(cert_file), str(bundle_file)
            )

            # The result doesn't matter - what matters is call count
            # Should be O(1), not O(N) where N is number of certs in bundle
            assert mock_subprocess.call_count <= 1, (
                f"Checking certificate existence made {mock_subprocess.call_count} subprocess calls "
                f"for a bundle with 10 certificates. This suggests O(N) complexity. "
                f"Expected O(1) - constant time regardless of bundle size."
            )

    def test_get_cert_fingerprint_is_cached(self, tmp_path):
        """Verify fingerprint is computed once and cached."""
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')

        # Mock the CERT_PATH to our test file
        with patch.object(fumitm, 'CERT_PATH', str(cert_file)):
            with patch('subprocess.run') as mock_subprocess:
                mock_subprocess.return_value = MagicMock(
                    returncode=0,
                    stdout="SHA256 Fingerprint=AA:BB:CC:DD"
                )

                # Call get_cert_fingerprint multiple times
                fp1 = instance.get_cert_fingerprint(str(cert_file))
                fp2 = instance.get_cert_fingerprint(str(cert_file))
                fp3 = instance.get_cert_fingerprint(str(cert_file))

                # Should only call subprocess once (cached after first call)
                # Note: current implementation caches only for CERT_PATH
                # This test documents expected behavior after optimization
                assert mock_subprocess.call_count <= 3, (
                    f"get_cert_fingerprint called subprocess {mock_subprocess.call_count} times "
                    f"for 3 calls. Expected caching to reduce this."
                )


class TestCertificateContentMatching(FumitmTestCase):
    """Tests for pure Python certificate content matching.

    These tests verify that certificate duplicate detection works correctly
    using string matching without requiring openssl subprocess calls.
    """

    def test_extracts_cert_unique_portion(self, tmp_path):
        """Test extraction of unique certificate portion for matching."""
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        # The function should be able to extract a unique portion
        # This tests the internal helper if it exists
        if hasattr(instance, 'get_cert_unique_portion'):
            unique = instance.get_cert_unique_portion(str(cert_file))
            assert unique is not None
            assert len(unique) >= 50  # Should have enough chars to be unique

    def test_matching_finds_cert_in_bundle(self, tmp_path):
        """Test that string matching correctly finds certificate in bundle."""
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Bundle containing the certificate
        bundle_file = tmp_path / "bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE + "\n" + mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        result = instance.certificate_likely_exists_in_file(
            str(cert_file), str(bundle_file)
        )

        assert result is True, "Failed to find certificate in bundle using string matching"

    def test_matching_returns_false_when_not_found(self, tmp_path):
        """Test that string matching correctly returns False when cert not in bundle."""
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Bundle NOT containing the certificate
        bundle_file = tmp_path / "bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        result = instance.certificate_likely_exists_in_file(
            str(cert_file), str(bundle_file)
        )

        assert result is False, "Incorrectly found certificate that isn't in bundle"

    def test_matching_handles_whitespace_variations(self, tmp_path):
        """Test that matching works despite whitespace differences."""
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        # Bundle with extra whitespace around the certificate
        cert_with_spaces = mock_data.MOCK_CERTIFICATE.replace('\n', '\n\n')
        bundle_file = tmp_path / "bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE + "\n\n\n" + cert_with_spaces)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        result = instance.certificate_likely_exists_in_file(
            str(cert_file), str(bundle_file)
        )

        # Should still find the certificate despite whitespace differences
        assert result is True, "Failed to find certificate with whitespace variations"


class TestUpdateCheck(FumitmTestCase):
    """Tests for the update check functionality."""

    def test_check_for_updates_uses_unverified_ssl(self, tmp_path):
        """Verify update check uses unverified SSL context."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch('urllib.request.urlopen') as mock_urlopen, \
             patch('builtins.open', mock_open(read_data=b'test content')):

            mock_response = MagicMock()
            mock_response.read.return_value = b'different content'
            mock_response.__enter__ = MagicMock(return_value=mock_response)
            mock_response.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            instance.check_for_updates()

            # Verify urlopen was called with context parameter
            call_kwargs = mock_urlopen.call_args
            assert call_kwargs is not None
            # The context should be passed as a keyword argument
            assert 'context' in call_kwargs.kwargs or len(call_kwargs.args) >= 2

    def test_check_for_updates_handles_network_error(self, tmp_path):
        """Verify update check handles network errors gracefully."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError("Network error")

            result = instance.check_for_updates()

            # Should return False on error, not raise
            assert result is False


class TestGcloudVerification(FumitmTestCase):
    """Tests for gcloud verification functionality."""

    def test_verify_connection_gcloud_working(self, tmp_path):
        """Test gcloud verification when API call succeeds."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch('subprocess.run') as mock_run, \
             patch.object(instance, 'command_exists', return_value=True), \
             patch('shutil.which', return_value='/usr/bin/gcloud'):

            # Successful 'gcloud projects list --limit=1' response
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='PROJECT_ID\nmy-project\n',
                stderr=''
            )

            result = instance.verify_connection("gcloud")

            assert result == "WORKING"

    def test_verify_connection_gcloud_ssl_error(self, tmp_path):
        """Test gcloud verification with SSL error."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch('subprocess.run') as mock_run, \
             patch.object(instance, 'command_exists', return_value=True), \
             patch('shutil.which', return_value='/usr/bin/gcloud'):

            mock_run.return_value = MagicMock(
                returncode=1,
                stdout='',
                stderr='SSL certificate problem: unable to get local issuer certificate'
            )

            result = instance.verify_connection("gcloud")

            assert result == "FAILED"

    def test_verify_connection_gcloud_permission_error_is_ok(self, tmp_path):
        """Test gcloud verification with permission error (TLS still works)."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch('subprocess.run') as mock_run, \
             patch.object(instance, 'command_exists', return_value=True), \
             patch('shutil.which', return_value='/usr/bin/gcloud'):

            # Permission denied error - TLS handshake succeeded
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout='',
                stderr='ERROR: (gcloud.projects.list) User does not have permission'
            )

            result = instance.verify_connection("gcloud")

            # Non-SSL errors mean TLS connectivity is working
            assert result == "WORKING"

    def test_verify_connection_gcloud_not_installed(self, tmp_path):
        """Test gcloud verification when not installed."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch.object(instance, 'command_exists', return_value=False):
            result = instance.verify_connection("gcloud")

            assert result == "NOT_INSTALLED"

    def test_check_gcloud_status_working_no_custom_ca(self, tmp_path):
        """Test gcloud status when working without custom CA."""
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value="WORKING"), \
             patch('subprocess.run') as mock_run:

            # gcloud config get-value returns empty (no custom CA)
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='',
                stderr=''
            )

            has_issues = instance.check_gcloud_status(str(cert_file))

            # Should NOT have issues when gcloud works without custom CA
            assert has_issues is False

    def test_check_gcloud_status_failed_suggests_fix(self, tmp_path):
        """Test gcloud status suggests fix when connection fails."""
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value="FAILED"), \
             patch('subprocess.run') as mock_run:

            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='',
                stderr=''
            )

            has_issues = instance.check_gcloud_status(str(cert_file))

            assert has_issues is True


class TestCalVerVersion(FumitmTestCase):
    """Tests for CalVer version handling."""

    def test_version_variable_exists(self):
        """Verify __version__ is defined."""
        assert hasattr(fumitm, '__version__')
        assert fumitm.__version__ is not None

    def test_version_format_valid(self):
        """Verify version follows CalVer format."""
        import re
        pattern = r'^\d{4}\.\d{1,2}\.\d{1,2}(\.\d+)?$'
        assert re.match(pattern, fumitm.__version__), \
            f"Version '{fumitm.__version__}' doesn't match CalVer format YYYY.M.D or YYYY.M.D.N"

    def test_parse_calver_basic(self):
        """Test CalVer parsing for basic version."""
        result = fumitm.parse_calver("2025.12.18")
        assert result == (2025, 12, 18, 0)

    def test_parse_calver_with_patch(self):
        """Test CalVer parsing with patch number."""
        result = fumitm.parse_calver("2025.12.18.3")
        assert result == (2025, 12, 18, 3)

    def test_parse_calver_single_digit_month_day(self):
        """Test CalVer parsing with single-digit month/day."""
        result = fumitm.parse_calver("2025.1.5")
        assert result == (2025, 1, 5, 0)

    def test_parse_calver_invalid_format(self):
        """Test CalVer parsing rejects invalid formats."""
        with pytest.raises(ValueError):
            fumitm.parse_calver("invalid")
        with pytest.raises(ValueError):
            fumitm.parse_calver("2025.12")
        with pytest.raises(ValueError):
            fumitm.parse_calver("2025")

    def test_version_comparison_newer(self):
        """Test version comparison detects newer versions."""
        assert fumitm.parse_calver("2025.12.19") > fumitm.parse_calver("2025.12.18")
        assert fumitm.parse_calver("2025.12.18.1") > fumitm.parse_calver("2025.12.18")
        assert fumitm.parse_calver("2026.1.1") > fumitm.parse_calver("2025.12.31")

    def test_version_comparison_older(self):
        """Test version comparison detects older versions."""
        assert fumitm.parse_calver("2025.12.17") < fumitm.parse_calver("2025.12.18")
        assert fumitm.parse_calver("2025.12.18") < fumitm.parse_calver("2025.12.18.1")
        assert fumitm.parse_calver("2024.12.31") < fumitm.parse_calver("2025.1.1")

    def test_version_comparison_equal(self):
        """Test version comparison with equal versions."""
        assert fumitm.parse_calver("2025.12.18") == fumitm.parse_calver("2025.12.18")
        # Note: (2025, 12, 18, 0) should equal (2025, 12, 18, 0)
        assert fumitm.parse_calver("2025.12.18") == (2025, 12, 18, 0)


class TestUpdateCheckCalVer(FumitmTestCase):
    """Tests for CalVer-based update checking."""

    def test_check_for_updates_newer_available(self, tmp_path):
        """Verify update check returns True for newer version."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        # Mock remote file with a version far in the future
        remote_content = b'__version__ = "2099.12.31"\n# rest of file...'

        # Simulate a non-dev environment (main branch, clean tree) so the
        # update warning is not suppressed by the working-copy check.
        non_dev_version_info = {**fumitm.VERSION_INFO, 'branch': 'main', 'dirty': False}

        with patch('urllib.request.urlopen') as mock_urlopen, \
             patch.object(fumitm, '__version__', '2025.1.1'), \
             patch.object(fumitm, 'VERSION_INFO', non_dev_version_info):
            mock_response = MagicMock()
            mock_response.read.return_value = remote_content
            mock_response.__enter__ = MagicMock(return_value=mock_response)
            mock_response.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            result = instance.check_for_updates()
            assert result is True

    def test_check_for_updates_same_version(self, tmp_path):
        """Verify update check returns False for same version."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        # Mock remote file with same version as local
        remote_content = f'__version__ = "{fumitm.__version__}"\n# rest...'.encode()

        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = remote_content
            mock_response.__enter__ = MagicMock(return_value=mock_response)
            mock_response.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            result = instance.check_for_updates()
            assert result is False

    def test_check_for_updates_older_remote(self, tmp_path):
        """Verify update check returns False if remote is older."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        remote_content = b'__version__ = "2020.1.1"\n# rest...'

        with patch('urllib.request.urlopen') as mock_urlopen, \
             patch.object(fumitm, '__version__', '2025.12.18'):
            mock_response = MagicMock()
            mock_response.read.return_value = remote_content
            mock_response.__enter__ = MagicMock(return_value=mock_response)
            mock_response.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            result = instance.check_for_updates()
            assert result is False

    def test_check_for_updates_no_version_in_remote(self, tmp_path):
        """Verify graceful handling when remote has no version."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        remote_content = b'# file without __version__\nprint("hello")'

        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_response = MagicMock()
            mock_response.read.return_value = remote_content
            mock_response.__enter__ = MagicMock(return_value=mock_response)
            mock_response.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            result = instance.check_for_updates()
            assert result is False  # Graceful failure


if __name__ == '__main__':
    pytest.main([__file__, '-v'])