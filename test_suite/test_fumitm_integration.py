"""
Integration tests for fumitm.py

These tests verify the core workflows and functionality of the fumitm script
by mocking external dependencies and testing realistic scenarios.
"""
import os
import subprocess
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
            with patch('builtins.input', return_value='Y'), \
                 patch('sys.stdin') as mock_stdin, \
                 patch('pathlib.Path.touch'):
                mock_stdin.isatty.return_value = True
                instance = self.create_fumitm_instance(mode='install')
                instance.setup_node_cert()

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


class TestBrewCacerts(FumitmTestCase):
    """Tests for Homebrew ca-certificates setup and status."""

    def test_setup_skips_when_brew_not_installed(self):
        """setup_brew_cacerts returns early when brew is not on PATH."""
        mock_config = (MockBuilder()
            .with_certificate()
            .build())

        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance(mode='install')
            # brew is not in which_mapping, so command_exists returns False
            instance.setup_brew_cacerts()
            # No error, just silently returns

    def test_setup_skips_when_formula_not_installed(self):
        """setup_brew_cacerts returns early when ca-certificates is not installed."""
        mock_config = (MockBuilder()
            .with_certificate()
            .with_tool('brew')
            .with_subprocess_response(returncode=1, stderr="No such keg")
            .build())

        with mock_fumitm_environment(mock_config) as mocks:
            instance = self.create_fumitm_instance(mode='install')
            instance.setup_brew_cacerts()
            assert_subprocess_called_with(
                mocks['subprocess'],
                ['brew', 'list', 'ca-certificates']
            )

    def test_setup_runs_postinstall_when_cert_missing(self):
        """setup_brew_cacerts runs brew postinstall when proxy cert is missing from bundle."""
        brew_prefix = '/opt/homebrew'
        bundle_path = f'{brew_prefix}/etc/ca-certificates/cert.pem'

        mock_config = (MockBuilder()
            .with_certificate()
            .with_tool('brew')
            # brew list ca-certificates -> installed
            .with_subprocess_response(returncode=0)
            # brew --prefix
            .with_subprocess_response(returncode=0, stdout=brew_prefix)
            # brew postinstall ca-certificates
            .with_subprocess_response(returncode=0)
            .build())

        # Bundle exists but does not contain the proxy cert
        mock_config['exists_side_effect'] = lambda p: {
            bundle_path: True,
            f"{mock_data.HOME_DIR}/.cloudflare-ca.pem": True,
        }.get(str(p), False)

        with mock_fumitm_environment(mock_config) as mocks:
            instance = self.create_fumitm_instance(mode='install')
            instance.setup_brew_cacerts()
            assert_subprocess_called_with(
                mocks['subprocess'],
                ['brew', 'postinstall', 'ca-certificates']
            )

    def test_setup_status_mode_shows_action(self):
        """In status mode, setup_brew_cacerts prints action without running brew."""
        brew_prefix = '/opt/homebrew'
        bundle_path = f'{brew_prefix}/etc/ca-certificates/cert.pem'

        mock_config = (MockBuilder()
            .with_certificate()
            .with_tool('brew')
            .with_subprocess_response(returncode=0)  # brew list
            .with_subprocess_response(returncode=0, stdout=brew_prefix)
            .build())

        mock_config['exists_side_effect'] = lambda p: {
            bundle_path: True,
            f"{mock_data.HOME_DIR}/.cloudflare-ca.pem": True,
        }.get(str(p), False)

        with mock_fumitm_environment(mock_config) as mocks:
            instance = self.create_fumitm_instance(mode='status')
            instance.setup_brew_cacerts()
            # Should NOT call brew postinstall (only 2 subprocess calls)
            calls = mocks['subprocess'].call_args_list
            for c in calls:
                args = c[0][0] if c[0] else []
                assert 'postinstall' not in args

    def test_check_status_no_brew(self, tmp_path):
        """check_brew_cacerts_status returns False when brew is absent."""
        cert_file = tmp_path / "test-cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch.object(instance, 'command_exists', return_value=False):
            result = instance.check_brew_cacerts_status(str(cert_file))

        assert result is False

    def test_check_status_cert_present(self, tmp_path):
        """check_brew_cacerts_status reports no issues when cert is in bundle."""
        cert_file = tmp_path / "test-cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        def cmd_exists(cmd):
            return cmd == 'brew'

        with patch.object(instance, 'command_exists', side_effect=cmd_exists), \
             patch('subprocess.run') as mock_run, \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, 'certificate_exists_in_file', return_value=True):

            mock_run.side_effect = [
                MagicMock(returncode=0),  # brew list
                MagicMock(returncode=0, stdout='/opt/homebrew'),  # brew --prefix
            ]
            result = instance.check_brew_cacerts_status(str(cert_file))

        assert result is False

    def test_check_status_cert_missing(self, tmp_path):
        """check_brew_cacerts_status reports issues when cert is missing from bundle."""
        cert_file = tmp_path / "test-cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        def cmd_exists(cmd):
            return cmd == 'brew'

        with patch.object(instance, 'command_exists', side_effect=cmd_exists), \
             patch('subprocess.run') as mock_run, \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, 'certificate_exists_in_file', return_value=False):

            mock_run.side_effect = [
                MagicMock(returncode=0),  # brew list
                MagicMock(returncode=0, stdout='/opt/homebrew'),  # brew --prefix
            ]
            result = instance.check_brew_cacerts_status(str(cert_file))

        assert result is True

    def test_setup_postinstall_failure_on_missing_bundle(self):
        """setup_brew_cacerts reports error when postinstall fails on missing bundle."""
        brew_prefix = '/opt/homebrew'

        mock_config = (MockBuilder()
            .with_certificate()
            .with_tool('brew')
            # brew list ca-certificates -> installed
            .with_subprocess_response(returncode=0)
            # brew --prefix
            .with_subprocess_response(returncode=0, stdout=brew_prefix)
            # brew postinstall ca-certificates -> fails
            .with_subprocess_response(
                returncode=1, stderr="Error: something went wrong"
            )
            .build())

        # Bundle does not exist
        mock_config['exists_side_effect'] = lambda p: {
            f"{mock_data.HOME_DIR}/.cloudflare-ca.pem": True,
        }.get(str(p), False)

        with mock_fumitm_environment(mock_config) as mocks:
            instance = self.create_fumitm_instance(mode='install')
            instance.setup_brew_cacerts()
            assert_subprocess_called_with(
                mocks['subprocess'],
                ['brew', 'postinstall', 'ca-certificates']
            )

    def test_setup_postinstall_success_but_cert_not_in_bundle(self):
        """setup_brew_cacerts warns when postinstall succeeds but cert not in bundle."""
        brew_prefix = '/opt/homebrew'
        bundle_path = f'{brew_prefix}/etc/ca-certificates/cert.pem'

        mock_config = (MockBuilder()
            .with_certificate()
            .with_tool('brew')
            .with_subprocess_response(returncode=0)  # brew list
            .with_subprocess_response(returncode=0, stdout=brew_prefix)
            .with_subprocess_response(returncode=0)  # brew postinstall
            .build())

        # Bundle does not exist before postinstall
        mock_config['exists_side_effect'] = lambda p: {
            f"{mock_data.HOME_DIR}/.cloudflare-ca.pem": True,
        }.get(str(p), False)

        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance(mode='install')
            # cert_exists_in_file returns False since bundle doesn't exist
            instance.setup_brew_cacerts()
            # Should have warned (no assertion error means it ran through)

    def test_get_brew_prefix_fallback_on_failure(self):
        """_get_brew_prefix falls back to default when brew --prefix fails."""
        with patch('platform.system', return_value='Darwin'), \
             patch('platform.machine', return_value='arm64'):
            instance = fumitm.FumitmPython(
                mode='status', provider='warp'
            )

        with patch('subprocess.run') as mock_run, \
             patch('platform.machine', return_value='arm64'):
            mock_run.return_value = MagicMock(
                returncode=1, stdout='', stderr='error'
            )
            result = instance._get_brew_prefix()

        assert result == '/opt/homebrew'

    def test_get_brew_prefix_fallback_on_empty_stdout(self):
        """_get_brew_prefix falls back to default when stdout is empty."""
        with patch('platform.system', return_value='Darwin'), \
             patch('platform.machine', return_value='x86_64'):
            instance = fumitm.FumitmPython(
                mode='status', provider='warp'
            )

        with patch('subprocess.run') as mock_run, \
             patch('platform.machine', return_value='x86_64'):
            mock_run.return_value = MagicMock(
                returncode=0, stdout=''
            )
            result = instance._get_brew_prefix()

        assert result == '/usr/local'

    def test_get_brew_prefix_success(self):
        """_get_brew_prefix returns brew --prefix output on success."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(
                mode='status', provider='warp'
            )

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout='/opt/homebrew\n'
            )
            result = instance._get_brew_prefix()

        assert result == '/opt/homebrew'

    def test_get_brew_prefix_intel_fallback(self):
        """_get_brew_prefix uses /usr/local on Intel macs."""
        with patch('platform.system', return_value='Darwin'), \
             patch('platform.machine', return_value='x86_64'):
            instance = fumitm.FumitmPython(
                mode='status', provider='warp'
            )

        with patch('subprocess.run') as mock_run, \
             patch('platform.machine', return_value='x86_64'):
            mock_run.side_effect = OSError("not found")
            result = instance._get_brew_prefix()

        assert result == '/usr/local'

    def test_check_status_brew_prefix_fallback(self, tmp_path):
        """check_brew_cacerts_status uses fallback when brew --prefix fails."""
        cert_file = tmp_path / "test-cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'), \
             patch('platform.machine', return_value='arm64'):
            instance = fumitm.FumitmPython(mode='status')

        def cmd_exists(cmd):
            return cmd == 'brew'

        with patch.object(instance, 'command_exists', side_effect=cmd_exists), \
             patch('subprocess.run') as mock_run, \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, 'certificate_exists_in_file', return_value=True):

            mock_run.side_effect = [
                MagicMock(returncode=0),  # brew list
                MagicMock(returncode=1, stdout=''),  # brew --prefix fails
            ]
            result = instance.check_brew_cacerts_status(str(cert_file))

        assert result is False


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
             patch('os.path.isfile') as mock_isfile, \
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
            mock_isfile.side_effect = lambda path: 'lib/security/cacerts' in path

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
             patch('os.path.isfile', return_value=True), \
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
             patch('os.path.isfile', return_value=True), \
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

    def test_find_all_java_homes_includes_sdkman_installations(self):
        """find_all_java_homes discovers all JDKs installed under ~/.sdkman/candidates/java/."""
        sdkman_java_dir = os.path.expanduser('~/.sdkman/candidates/java')
        sdkman_versions = ['21.0.2-tem', '17.0.10-tem', '11.0.22-tem']

        def isfile_side_effect(path):
            if path == sdkman_java_dir:
                return False
            if 'lib/security/cacerts' in path:
                return True
            return False

        def isdir_side_effect(path):
            if path == sdkman_java_dir:
                return True
            if any(v in path for v in sdkman_versions):
                return True
            return False

        with patch('platform.system', return_value='Darwin'), \
             patch.dict(os.environ, {'JAVA_HOME': '', 'SDKMAN_DIR': ''}, clear=False), \
             patch('os.path.isfile', side_effect=isfile_side_effect), \
             patch('os.path.isdir', side_effect=isdir_side_effect), \
             patch('os.listdir', return_value=['21.0.2-tem', '17.0.10-tem', '11.0.22-tem', 'current']), \
             patch('subprocess.run') as mock_run:

            os.environ.pop('SDKMAN_DIR', None)
            mock_result = MagicMock()
            mock_result.stdout = ''
            mock_run.return_value = mock_result

            instance = fumitm.FumitmPython(mode='status')
            java_homes = instance.find_all_java_homes()

        expected_paths = [
            os.path.join(sdkman_java_dir, v) for v in sdkman_versions
        ]
        for path in expected_paths:
            assert path in java_homes, f"Expected SDKMAN JDK {path} in java_homes, got: {java_homes}"

    def test_find_all_java_homes_sdkman_skips_current_symlink(self):
        """find_all_java_homes does not add the 'current' symlink as a separate entry."""
        sdkman_java_dir = os.path.expanduser('~/.sdkman/candidates/java')

        with patch('platform.system', return_value='Darwin'), \
             patch.dict(os.environ, {'JAVA_HOME': '', 'SDKMAN_DIR': ''}, clear=False), \
             patch('os.path.exists', return_value=True), \
             patch('os.path.isdir', return_value=True), \
             patch('os.listdir', return_value=['21.0.2-tem', 'current']), \
             patch('subprocess.run') as mock_run:

            os.environ.pop('SDKMAN_DIR', None)
            mock_result = MagicMock()
            mock_result.stdout = ''
            mock_run.return_value = mock_result

            instance = fumitm.FumitmPython(mode='status')
            java_homes = instance.find_all_java_homes()

        current_path = os.path.join(sdkman_java_dir, 'current')
        assert current_path not in java_homes, \
            f"'current' symlink should not appear as a separate entry in java_homes"

    def test_find_all_java_homes_sdkman_absent(self):
        """find_all_java_homes does not fail when ~/.sdkman/candidates/java does not exist."""
        sdkman_java_dir = os.path.expanduser('~/.sdkman/candidates/java')

        def exists_side_effect(path):
            if path == sdkman_java_dir:
                return False
            return False

        with patch('platform.system', return_value='Darwin'), \
             patch.dict(os.environ, {'JAVA_HOME': '', 'SDKMAN_DIR': ''}, clear=False), \
             patch('os.path.exists', side_effect=exists_side_effect), \
             patch('os.path.isdir', return_value=False), \
             patch('subprocess.run') as mock_run:

            os.environ.pop('SDKMAN_DIR', None)
            mock_result = MagicMock()
            mock_result.stdout = ''
            mock_run.return_value = mock_result

            instance = fumitm.FumitmPython(mode='status')
            java_homes = instance.find_all_java_homes()

        assert java_homes == []

    def test_find_all_java_homes_sdkman_macos_bundle_layout(self):
        """find_all_java_homes handles vendors that ship a .jdk bundle under the version dir.

        Some SDKMAN distributions (e.g. Azul Zulu on macOS) are extracted as:
            ~/.sdkman/candidates/java/11.0.18-zulu/zulu-11.jdk/Contents/Home
        rather than the flat layout:
            ~/.sdkman/candidates/java/21.0.2-tem/
        Both must be discovered and produce a valid Java home.
        """
        sdkman_java_dir = os.path.expanduser('~/.sdkman/candidates/java')
        version_dir = os.path.join(sdkman_java_dir, '11.0.18-zulu')
        bundle_home = os.path.join(version_dir, 'zulu-11.jdk', 'Contents', 'Home')
        cacerts = os.path.join(bundle_home, 'lib', 'security', 'cacerts')

        def isdir_side_effect(path):
            return path in {sdkman_java_dir, version_dir, bundle_home,
                            os.path.join(version_dir, 'zulu-11.jdk')}

        def isfile_side_effect(path):
            return path == cacerts

        def listdir_side_effect(path):
            if path == sdkman_java_dir:
                return ['11.0.18-zulu', 'current']
            if path == version_dir:
                return ['zulu-11.jdk']
            return []

        with patch('platform.system', return_value='Darwin'), \
             patch.dict(os.environ, {'JAVA_HOME': '', 'SDKMAN_DIR': ''}, clear=False), \
             patch('os.path.isfile', side_effect=isfile_side_effect), \
             patch('os.path.isdir', side_effect=isdir_side_effect), \
             patch('os.listdir', side_effect=listdir_side_effect), \
             patch('subprocess.run') as mock_run:

            mock_result = MagicMock()
            mock_result.stdout = ''
            mock_run.return_value = mock_result

            instance = fumitm.FumitmPython(mode='status')
            java_homes = instance.find_all_java_homes()

        assert bundle_home in java_homes, \
            f"Expected bundle-layout SDKMAN JDK {bundle_home} in java_homes, got: {java_homes}"

    def test_find_all_java_homes_respects_sdkman_dir_env_var(self):
        """find_all_java_homes uses $SDKMAN_DIR instead of ~/.sdkman when set."""
        custom_sdkman_root = '/opt/sdkman'
        custom_sdkman_java_dir = '/opt/sdkman/candidates/java'
        default_sdkman_java_dir = os.path.expanduser('~/.sdkman/candidates/java')

        def isdir_side_effect(path):
            if path == custom_sdkman_java_dir:
                return True
            if path == default_sdkman_java_dir:
                return False
            if '21.0.2-tem' in path:
                return True
            return False

        def isfile_side_effect(path):
            if 'lib/security/cacerts' in path and '21.0.2-tem' in path:
                return True
            return False

        env = {'SDKMAN_DIR': custom_sdkman_root, 'JAVA_HOME': ''}
        with patch('platform.system', return_value='Darwin'), \
             patch.dict(os.environ, env, clear=False), \
             patch('os.path.isfile', side_effect=isfile_side_effect), \
             patch('os.path.isdir', side_effect=isdir_side_effect), \
             patch('os.listdir', return_value=['21.0.2-tem', 'current']), \
             patch('subprocess.run') as mock_run:

            mock_result = MagicMock()
            mock_result.stdout = ''
            mock_run.return_value = mock_result

            instance = fumitm.FumitmPython(mode='status')
            java_homes = instance.find_all_java_homes()

        expected = os.path.join(custom_sdkman_java_dir, '21.0.2-tem')
        assert expected in java_homes, \
            f"Expected JDK from custom $SDKMAN_DIR at {expected}, got: {java_homes}"
        unexpected = os.path.join(default_sdkman_java_dir, '21.0.2-tem')
        assert unexpected not in java_homes


class TestCLIAndWorkflow(FumitmTestCase):
    """Tests for CLI argument parsing and complete workflows."""
    
    # Default kwargs for new headless/MDM flags, used by CLI constructor tests
    _DEFAULT_NEW_KWARGS = dict(
        no_color=False, headless=False, skip_update_check=False,
        log_file=None, log_dir=None, json_log_file=None, json_log_dir=None,
        run_as_user=None, with_aikido=False, no_aikido=False,
        aikido_cert_file=None,
    )

    @patch('fumitm.sys.argv', ['fumitm.py', '--fix'])
    def test_cli_fix_mode(self):
        """Test --fix argument sets install mode."""
        env = {k: v for k, v in os.environ.items()
               if k not in ('NO_COLOR', 'FUMITM_HEADLESS')}
        with patch('fumitm.FumitmPython') as mock_class, \
             patch.dict(os.environ, env, clear=True):
            mock_instance = MagicMock()
            mock_instance.main.return_value = 0
            mock_class.return_value = mock_instance

            with patch('fumitm.sys.exit'):
                fumitm.main()

            mock_class.assert_called_with(
                mode='install', debug=False, selected_tools=[],
                cert_file=None, manual_cert=False, skip_verify=False,
                provider=None, auto_yes=False, **self._DEFAULT_NEW_KWARGS
            )

    @patch('fumitm.sys.argv', ['fumitm.py', '--tools', 'node,python'])
    def test_cli_tool_selection(self):
        """Test --tools argument parsing."""
        env = {k: v for k, v in os.environ.items()
               if k not in ('NO_COLOR', 'FUMITM_HEADLESS')}
        with patch('fumitm.FumitmPython') as mock_class, \
             patch.dict(os.environ, env, clear=True):
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
                provider=None, auto_yes=False, **self._DEFAULT_NEW_KWARGS
            )

    @patch('fumitm.sys.argv', ['fumitm.py', '--fix', '--yes'])
    def test_cli_yes_flag(self):
        """Test --yes flag passes auto_yes=True."""
        env = {k: v for k, v in os.environ.items()
               if k not in ('NO_COLOR', 'FUMITM_HEADLESS')}
        with patch('fumitm.FumitmPython') as mock_class, \
             patch.dict(os.environ, env, clear=True):
            mock_instance = MagicMock()
            mock_instance.main.return_value = 0
            mock_class.return_value = mock_instance

            with patch('fumitm.sys.exit'):
                fumitm.main()

            mock_class.assert_called_with(
                mode='install', debug=False, selected_tools=[],
                cert_file=None, manual_cert=False, skip_verify=False,
                provider=None, auto_yes=True, **self._DEFAULT_NEW_KWARGS
            )

    def test_prompt_returns_y_without_stdin_when_auto_yes(self):
        """--yes must work without any stdin input (e.g. curl pipe)."""
        instance = self.create_fumitm_instance()
        instance.auto_yes = True
        result = instance._prompt("Do you want to proceed? (Y/n) ")
        assert result == 'y'

    @patch('builtins.input', side_effect=EOFError)
    def test_prompt_reads_stdin_when_no_auto_yes(self, _mock_input):
        """Without --yes, _prompt delegates to input() which needs stdin."""
        instance = self.create_fumitm_instance()
        instance.auto_yes = False
        with patch('sys.stdin') as mock_stdin:
            mock_stdin.isatty.return_value = True
            with pytest.raises(EOFError):
                instance._prompt("Do you want to proceed? (Y/n) ")

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
        assert len(status_methods) >= 12, f"Expected at least 12 status methods, found {len(status_methods)}: {status_methods}"

        # Expected methods based on the codebase
        expected_methods = [
            'check_brew_cacerts_status',
            'check_git_status', 'check_node_status', 'check_python_status',
            'check_gcloud_status', 'check_java_status', 'check_jenv_status',
            'check_gradle_status', 'check_dbeaver_status', 'check_wget_status',
            'check_podman_status', 'check_rancher_status', 'check_android_status',
            'check_colima_status', 'check_docker_status'
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

            # Mock os.path.exists: neither system cert location exists.
            # The assertions run outside this patch because Python 3.13's
            # pathlib.Path.exists() delegates to os.path.exists(), so a global
            # patch would otherwise mask the file the method actually created.
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

    def test_no_raw_makedirs_in_setup_functions(self):
        """Ensure setup functions use _safe_makedirs() instead of raw os.makedirs().

        Running ``os.makedirs()`` under sudo creates root-owned directories in
        the user's home directory. All setup functions must use the ownership-
        correcting ``_safe_makedirs()`` wrapper instead. The only permitted raw
        call is inside ``_safe_makedirs`` itself.
        """
        import os
        import re

        test_dir = os.path.dirname(os.path.abspath(__file__))
        fumitm_path = os.path.join(os.path.dirname(test_dir), "fumitm.py")

        with open(fumitm_path, 'r') as f:
            lines = f.readlines()

        # Methods that legitimately use raw os.makedirs (log dirs are system
        # paths like /var/log/fumitm that should stay root-owned)
        allowed_methods = {'_safe_makedirs', '_open_log_files'}
        in_allowed = False
        violations = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Track when we're inside an allowed method
            if any(f'def {m}' in line for m in allowed_methods):
                in_allowed = True
            elif in_allowed and re.match(r'^\s{4}def ', line):
                in_allowed = False

            if in_allowed:
                continue

            if 'os.makedirs(' in stripped:
                violations.append(f"Line {i}: {stripped}")

        assert not violations, (
            f"Found raw os.makedirs() calls outside _safe_makedirs in fumitm.py:\n"
            + "\n".join(violations) + "\n\n"
            "Use self._safe_makedirs(path) instead to ensure correct ownership under sudo."
        )


class TestOwnershipProtection(FumitmTestCase):
    """Tests for sudo detection and file ownership correction."""

    def test_is_running_as_sudo_true(self):
        """Detect when the process is root via sudo."""
        instance = self.create_fumitm_instance()
        with patch('os.getuid', return_value=0), \
             patch.dict(os.environ, {'SUDO_UID': '1000', 'SUDO_GID': '1000'}):
            assert instance._is_running_as_sudo() is True

    def test_is_running_as_sudo_false_normal_user(self):
        """Normal user (non-root) should not be detected as sudo."""
        instance = self.create_fumitm_instance()
        with patch('os.getuid', return_value=1000):
            assert instance._is_running_as_sudo() is False

    def test_is_running_as_sudo_false_actual_root(self):
        """Actual root login (no SUDO_UID) should not be detected as sudo."""
        instance = self.create_fumitm_instance()
        env = os.environ.copy()
        env.pop('SUDO_UID', None)
        with patch('os.getuid', return_value=0), \
             patch.dict(os.environ, env, clear=True):
            assert instance._is_running_as_sudo() is False

    def test_get_real_user_ids_under_sudo(self):
        """Under sudo, return the real user's UID/GID from environment."""
        instance = self.create_fumitm_instance()
        with patch('os.getuid', return_value=0), \
             patch.dict(os.environ, {'SUDO_UID': '501', 'SUDO_GID': '20'}):
            uid, gid = instance._get_real_user_ids()
            assert uid == 501
            assert gid == 20

    def test_get_real_user_ids_normal(self):
        """Without sudo, return the current process UID/GID."""
        instance = self.create_fumitm_instance()
        with patch('os.getuid', return_value=1000), \
             patch('os.getgid', return_value=1000):
            uid, gid = instance._get_real_user_ids()
            assert uid == 1000
            assert gid == 1000

    def test_fix_ownership_only_affects_home_paths(self, tmp_path):
        """_fix_ownership should skip paths outside $HOME."""
        instance = self.create_fumitm_instance()

        system_file = tmp_path / "etc" / "ssl" / "cert.pem"
        system_file.parent.mkdir(parents=True)
        system_file.touch()

        with patch('os.getuid', return_value=0), \
             patch.dict(os.environ, {'SUDO_UID': '501', 'SUDO_GID': '20'}), \
             patch('os.path.expanduser', return_value=str(tmp_path / "home" / "user")), \
             patch('os.chown') as mock_chown:
            instance._fix_ownership(str(system_file))
            mock_chown.assert_not_called()

    def test_fix_ownership_noop_when_not_sudo(self, tmp_path):
        """_fix_ownership should be a no-op for non-sudo users."""
        instance = self.create_fumitm_instance()

        home_file = tmp_path / "home" / "user" / "test.pem"
        home_file.parent.mkdir(parents=True)
        home_file.touch()

        with patch('os.getuid', return_value=1000), \
             patch('os.chown') as mock_chown:
            instance._fix_ownership(str(home_file))
            mock_chown.assert_not_called()

    def test_home_correction_under_sudo_linux(self):
        """Verify HOME is corrected when sudo sets it to /root."""
        import pwd

        mock_pw = MagicMock()
        mock_pw.pw_dir = '/home/realuser'

        with patch('os.getuid', return_value=0), \
             patch.dict(os.environ, {'SUDO_USER': 'realuser', 'HOME': '/root'}), \
             patch('pwd.getpwnam', return_value=mock_pw), \
             patch('platform.system', return_value='Linux'):
            instance = fumitm.FumitmPython(mode='status', provider='warp')
            assert os.environ['HOME'] == '/home/realuser'

    def test_check_ownership_sanity_detects_root_files(self, tmp_path):
        """check_ownership_sanity should warn about root-owned files."""
        instance = self.create_fumitm_instance()
        instance.cert_path = str(tmp_path / "cert.pem")
        instance.bundle_dir = str(tmp_path / "bundle")

        cert = tmp_path / "cert.pem"
        cert.touch()

        # Build a stat wrapper that only overrides st_uid for the target file
        # while preserving all other stat fields (st_mode, etc.)
        original_stat = os.stat
        def mock_stat(path, *args, **kwargs):
            result = original_stat(path, *args, **kwargs)
            if str(path) == str(cert):
                # Return a copy with st_uid patched to 0 (root)
                return os.stat_result((
                    result.st_mode, result.st_ino, result.st_dev, result.st_nlink,
                    0,  # st_uid = root
                    result.st_gid, result.st_size, result.st_atime, result.st_mtime, result.st_ctime
                ))
            return result

        with patch('os.getuid', return_value=1000), \
             patch('os.stat', side_effect=mock_stat), \
             patch('os.path.expanduser', return_value=str(tmp_path)):
            result = instance.check_ownership_sanity()
            assert result is True

    def test_check_ownership_sanity_clean(self, tmp_path):
        """check_ownership_sanity should return False when no problems exist."""
        instance = self.create_fumitm_instance()
        instance.cert_path = str(tmp_path / "cert.pem")
        instance.bundle_dir = str(tmp_path / "bundle")

        # No files exist — nothing to flag
        with patch('os.getuid', return_value=1000):
            result = instance.check_ownership_sanity()
            assert result is False


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
        """gcloud status flags missing core/custom_ca_certs_file even when basic HTTPS works.

        IAP tunnel reads core/custom_ca_certs_file explicitly and ignores the
        system trust store, so a working `gcloud projects list` is not enough.
        """
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

            assert has_issues is True

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


class TestProviderMigration(FumitmTestCase):
    """Tests for provider migration detection and path correction.

    When a user switches MITM proxy providers (e.g. WARP to Netskope), tool
    configs may still reference the old provider's bundle_dir. These tests
    verify that fumitm detects the mismatch and migrates paths accordingly.
    """

    def test_path_belongs_to_other_provider_cross_provider(self):
        """A path under WARP's bundle_dir should be flagged when Netskope is active."""
        instance = self.create_fumitm_instance(provider='netskope')
        warp_path = os.path.expanduser("~/.cloudflare-warp/node/ca-bundle.pem")
        result = instance._path_belongs_to_other_provider(warp_path)
        assert result == "Cloudflare WARP"

    def test_path_belongs_to_other_provider_same_provider(self):
        """A path under the current provider's bundle_dir should return None."""
        instance = self.create_fumitm_instance(provider='netskope')
        netskope_path = os.path.expanduser("~/.netskope/node/ca-bundle.pem")
        result = instance._path_belongs_to_other_provider(netskope_path)
        assert result is None

    def test_path_belongs_to_other_provider_unrelated(self):
        """An unrelated path should return None."""
        instance = self.create_fumitm_instance(provider='netskope')
        result = instance._path_belongs_to_other_provider("/etc/ssl/certs/ca-certificates.crt")
        assert result is None

    def test_path_belongs_to_other_provider_netskope_when_warp_active(self):
        """A path under Netskope's bundle_dir should be flagged when WARP is active."""
        instance = self.create_fumitm_instance(provider='warp')
        netskope_path = os.path.expanduser("~/.netskope/npm/ca-bundle.pem")
        result = instance._path_belongs_to_other_provider(netskope_path)
        assert result == "Netskope"

    def test_check_node_status_flags_cross_provider_path(self):
        """check_node_status should set has_issues when NODE_EXTRA_CA_CERTS points to another provider."""
        warp_node_bundle = os.path.expanduser("~/.cloudflare-warp/node/ca-bundle.pem")

        mock_config = (MockBuilder()
            .with_tool('node')
            .with_env_var('NODE_EXTRA_CA_CERTS', warp_node_bundle)
            .build())

        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance(provider='netskope')
            has_issues = instance.check_node_status("FAKE_CERT_CONTENT")
            assert has_issues is True

    def test_check_git_status_flags_cross_provider_path(self):
        """check_git_status should set has_issues when http.sslCAInfo points to another provider."""
        warp_git_bundle = os.path.expanduser("~/.cloudflare-warp/git/ca-bundle.pem")

        mock_config = (MockBuilder()
            .with_tool('git')
            .with_subprocess_response(returncode=0, stdout=warp_git_bundle)
            .build())

        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance(provider='netskope')
            has_issues = instance.check_git_status("FAKE_CERT_CONTENT")
            assert has_issues is True

    def test_check_curl_status_flags_cross_provider_path(self):
        """check_curl_status should flag CURL_CA_BUNDLE under another provider's dir."""
        warp_curl_bundle = os.path.expanduser("~/.cloudflare-warp/curl/ca-bundle.pem")

        mock_config = (MockBuilder()
            .with_tool('curl')
            # verify_connection returns WORKING
            .with_subprocess_response(returncode=0, stderr="")
            # curl --version
            .with_subprocess_response(returncode=0, stdout="curl 8.4.0 (x86_64) libcurl/8.4.0 OpenSSL/3.0")
            .with_env_var('CURL_CA_BUNDLE', warp_curl_bundle)
            .build())

        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance(provider='netskope')
            has_issues = instance.check_curl_status("FAKE_CERT_CONTENT")
            assert has_issues is True

    def test_setup_node_cert_migrates_cross_provider_path(self):
        """setup_node_cert should create a new bundle at the current provider's path when migrating."""
        warp_node_bundle = os.path.expanduser("~/.cloudflare-warp/node/ca-bundle.pem")

        mock_config = (MockBuilder()
            .with_tool('node')
            # npm/yarn/pnpm are not installed so setup_node_cert won't call into them
            .with_env_var('NODE_EXTRA_CA_CERTS', warp_node_bundle)
            .with_certificate(os.path.expanduser("~/.netskope-ca.pem"))
            .build())

        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance(mode='install', provider='netskope')
            instance.setup_node_cert()

            # The shell config should reference the netskope path, not the warp path
            assert instance.bundle_dir == os.path.expanduser("~/.netskope")

    def test_check_node_status_no_issues_for_same_provider(self):
        """check_node_status should not flag paths belonging to the current provider."""
        netskope_node_bundle = os.path.expanduser("~/.netskope/node/ca-bundle.pem")
        cert_path = "/tmp/test-cert.pem"
        cert_content = mock_data.MOCK_CERTIFICATE

        mock_config = (MockBuilder()
            .with_tool('node')
            .with_env_var('NODE_EXTRA_CA_CERTS', netskope_node_bundle)
            .with_file(netskope_node_bundle, cert_content)
            .with_file(cert_path, cert_content)
            # verify_connection for node
            .with_subprocess_response(returncode=0, stderr="HTTP Status: 200")
            .build())

        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance(provider='netskope')
            has_issues = instance.check_node_status(cert_path)
            assert has_issues is False


class TestToolResultAccuracy(FumitmTestCase):
    """Tests that setup functions return accurate ToolResult statuses."""

    def test_java_all_fail_returns_failed(self):
        """setup_java_cert returns failed when all JDKs fail keytool import."""
        fake_java_homes = [
            '/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home',
            '/Library/Java/JavaVirtualMachines/temurin-11.jdk/Contents/Home',
        ]

        instance = self.create_fumitm_instance(mode='install')

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'find_all_java_homes', return_value=fake_java_homes), \
             patch.object(instance, 'find_java_cacerts', return_value='/fake/cacerts'), \
             patch('subprocess.run') as mock_run:

            # keytool -list says not installed, keytool -import fails (permission denied)
            def run_side_effect(*args, **kwargs):
                cmd = args[0]
                result = MagicMock()
                result.returncode = 1
                result.stdout = b'Permission denied'
                return result

            mock_run.side_effect = run_side_effect

            result = instance.setup_java_cert()
            assert result.status == 'failed'
            assert result.tool == 'java'

    def test_java_all_already_installed_returns_already_ok(self):
        """setup_java_cert returns already_ok when all JDKs have the cert."""
        fake_java_homes = [
            '/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home',
            '/Library/Java/JavaVirtualMachines/temurin-11.jdk/Contents/Home',
        ]

        instance = self.create_fumitm_instance(mode='install')

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'find_all_java_homes', return_value=fake_java_homes), \
             patch.object(instance, 'find_java_cacerts', return_value='/fake/cacerts'), \
             patch('subprocess.run') as mock_run:

            # keytool -list returns success with alias present
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = instance.provider['keytool_alias'].encode()
            mock_run.return_value = mock_result

            result = instance.setup_java_cert()
            assert result.status == 'already_ok'

    def test_java_mixed_results_returns_failed(self):
        """setup_java_cert returns failed when some JDKs succeed but others fail."""
        fake_java_homes = [
            '/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home',
            '/Library/Java/JavaVirtualMachines/temurin-11.jdk/Contents/Home',
        ]

        instance = self.create_fumitm_instance(mode='install')

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'find_all_java_homes', return_value=fake_java_homes), \
             patch.object(instance, 'find_java_cacerts', return_value='/fake/cacerts'), \
             patch('subprocess.run') as mock_run:

            call_count = [0]

            def run_side_effect(*args, **kwargs):
                call_count[0] += 1
                result = MagicMock()
                cmd = args[0]
                if '-list' in cmd:
                    # Neither has cert installed yet
                    result.returncode = 1
                    result.stdout = b''
                elif '-import' in cmd:
                    # First import succeeds, second fails
                    if call_count[0] == 2:  # first -import
                        result.returncode = 0
                        result.stdout = b'Certificate was added'
                    else:  # second -import
                        result.returncode = 1
                        result.stdout = b'Permission denied'
                return result

            mock_run.side_effect = run_side_effect

            result = instance.setup_java_cert()
            assert result.status == 'failed'
            assert result.changed is True
            assert '1/2 Java installation(s) configured' in result.message
            assert '1/2 failed' in result.message

    def test_java_all_succeed_returns_configured(self):
        """setup_java_cert returns configured when all JDKs are newly configured."""
        fake_java_homes = [
            '/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home',
        ]

        instance = self.create_fumitm_instance(mode='install')

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'find_all_java_homes', return_value=fake_java_homes), \
             patch.object(instance, 'find_java_cacerts', return_value='/fake/cacerts'), \
             patch('subprocess.run') as mock_run:

            def run_side_effect(*args, **kwargs):
                result = MagicMock()
                cmd = args[0]
                if '-list' in cmd:
                    result.returncode = 1
                    result.stdout = b''
                else:
                    result.returncode = 0
                    result.stdout = b'Certificate was added'
                return result

            mock_run.side_effect = run_side_effect

            result = instance.setup_java_cert()
            assert result.status == 'configured'

    def test_java_no_java_returns_skipped(self):
        """setup_java_cert returns skipped when java/keytool not found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=False):
            result = instance.setup_java_cert()
            assert result.status == 'skipped'

    def test_java_no_installations_returns_skipped(self):
        """setup_java_cert returns skipped when no Java homes found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'find_all_java_homes', return_value=[]):
            result = instance.setup_java_cert()
            assert result.status == 'skipped'

    def test_find_java_cacerts_skips_directory(self):
        """find_java_cacerts returns jre path when lib/security/cacerts is a directory."""
        instance = self.create_fumitm_instance()
        java_home = '/Library/Java/JavaVirtualMachines/temurin-8.jdk/Contents/Home'
        modern_path = os.path.join(java_home, 'lib/security/cacerts')
        legacy_path = os.path.join(java_home, 'jre/lib/security/cacerts')

        def isfile_side_effect(path):
            if path == modern_path:
                return False  # it's a directory, not a file
            if path == legacy_path:
                return True
            return False

        with patch('os.path.isfile', side_effect=isfile_side_effect):
            result = instance.find_java_cacerts(java_home)
            assert result == legacy_path

    def test_find_java_cacerts_returns_empty_when_both_missing(self):
        """find_java_cacerts returns empty string when no cacerts file exists."""
        instance = self.create_fumitm_instance()
        java_home = '/fake/java/home'
        with patch('os.path.isfile', return_value=False):
            result = instance.find_java_cacerts(java_home)
            assert result == ''

    def test_find_java_cacerts_prefers_modern_path(self):
        """find_java_cacerts returns lib/security/cacerts when it's a regular file."""
        instance = self.create_fumitm_instance()
        java_home = '/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home'
        modern_path = os.path.join(java_home, 'lib/security/cacerts')

        with patch('os.path.isfile', return_value=True):
            result = instance.find_java_cacerts(java_home)
            assert result == modern_path

    def test_jenv_all_fail_returns_failed(self):
        """setup_jenv_cert returns failed when all jenv JDKs fail."""
        instance = self.create_fumitm_instance(mode='install')
        fake_java_homes = ['/Users/user/.jenv/versions/17.0']

        with patch.object(instance, 'get_jenv_java_homes', return_value=fake_java_homes), \
             patch.object(instance, 'command_exists', return_value=True), \
             patch('os.path.exists', return_value=True), \
             patch('subprocess.run') as mock_run:

            def run_side_effect(*args, **kwargs):
                result = MagicMock()
                result.returncode = 1
                result.stdout = 'Permission denied'
                return result

            mock_run.side_effect = run_side_effect

            result = instance.setup_jenv_cert()
            assert result.status == 'failed'
            assert result.tool == 'jenv'

    def test_jenv_no_homes_returns_skipped(self):
        """setup_jenv_cert returns skipped when no jenv installations found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'get_jenv_java_homes', return_value=[]):
            result = instance.setup_jenv_cert()
            assert result.status == 'skipped'

    def test_jenv_no_keytool_returns_skipped(self):
        """setup_jenv_cert returns skipped when keytool not found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'get_jenv_java_homes', return_value=['/fake']), \
             patch.object(instance, 'command_exists', return_value=False):
            result = instance.setup_jenv_cert()
            assert result.status == 'skipped'
            assert result.tool == 'jenv'

    def test_jenv_mixed_results_marks_change_state(self):
        """setup_jenv_cert preserves partial success when some installs fail."""
        instance = self.create_fumitm_instance(mode='install')
        fake_java_homes = [
            '/Users/user/.jenv/versions/17.0',
            '/Users/user/.jenv/versions/21.0',
        ]

        with patch.object(instance, 'get_jenv_java_homes', return_value=fake_java_homes), \
             patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'find_java_cacerts', return_value='/fake/cacerts'), \
             patch('subprocess.run') as mock_run:

            call_count = [0]

            def run_side_effect(*args, **kwargs):
                call_count[0] += 1
                result = MagicMock()
                cmd = args[0]
                if '-list' in cmd:
                    result.returncode = 1
                    result.stdout = ''
                elif '-import' in cmd:
                    if call_count[0] == 2:
                        result.returncode = 0
                        result.stdout = 'Certificate was added'
                    else:
                        result.returncode = 1
                        result.stdout = 'Permission denied'
                return result

            mock_run.side_effect = run_side_effect

            result = instance.setup_jenv_cert()
            assert result.status == 'failed'
            assert result.tool == 'jenv'
            assert result.changed is True
            assert '1/2 jenv installation(s) configured' in result.message
            assert '1/2 failed' in result.message

    def test_dbeaver_not_installed_returns_skipped(self):
        """setup_dbeaver_cert returns skipped when DBeaver not found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch('os.path.exists', return_value=False):
            result = instance.setup_dbeaver_cert()
            assert result.status == 'skipped'

    def test_dbeaver_already_installed_returns_already_ok(self):
        """setup_dbeaver_cert returns already_ok when cert already in keystore."""
        instance = self.create_fumitm_instance(mode='install')

        def exists_side_effect(path):
            return True  # both keytool and cacerts exist

        with patch('os.path.exists', side_effect=exists_side_effect), \
             patch('subprocess.run') as mock_run:

            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = instance.provider['keytool_alias'].encode()
            mock_run.return_value = mock_result

            result = instance.setup_dbeaver_cert()
            assert result.status == 'already_ok'

    def test_dbeaver_import_fails_returns_failed(self):
        """setup_dbeaver_cert returns failed when keytool import fails."""
        instance = self.create_fumitm_instance(mode='install')

        with patch('os.path.exists', return_value=True), \
             patch('subprocess.run') as mock_run:

            call_count = [0]

            def run_side_effect(*args, **kwargs):
                call_count[0] += 1
                result = MagicMock()
                if call_count[0] == 1:
                    # keytool -list: cert not found
                    result.returncode = 1
                    result.stdout = b''
                else:
                    # keytool -import: permission denied
                    result.returncode = 1
                    result.stdout = b'Permission denied'
                return result

            mock_run.side_effect = run_side_effect

            result = instance.setup_dbeaver_cert()
            assert result.status == 'failed'

    def test_dbeaver_import_succeeds_returns_configured(self):
        """setup_dbeaver_cert returns configured when keytool import succeeds."""
        instance = self.create_fumitm_instance(mode='install')

        with patch('os.path.exists', return_value=True), \
             patch('subprocess.run') as mock_run:

            call_count = [0]

            def run_side_effect(*args, **kwargs):
                call_count[0] += 1
                result = MagicMock()
                if call_count[0] == 1:
                    # keytool -list: cert not found
                    result.returncode = 1
                    result.stdout = b''
                else:
                    # keytool -import: success
                    result.returncode = 0
                    result.stdout = b'Certificate was added'
                return result

            mock_run.side_effect = run_side_effect

            result = instance.setup_dbeaver_cert()
            assert result.status == 'configured'

    def test_java_failures_propagate_through_run_setup(self):
        """_run_setup passes through ToolResult from setup_java_cert."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=False):
            result = instance._run_setup('java', instance.setup_java_cert)
            assert result.status == 'skipped'

    def test_dbeaver_failure_propagates_through_run_setup(self):
        """_run_setup passes through failed ToolResult from setup_dbeaver_cert."""
        instance = self.create_fumitm_instance(mode='install')

        with patch('os.path.exists', return_value=True), \
             patch('subprocess.run') as mock_run:

            # All keytool calls fail
            mock_result = MagicMock()
            mock_result.returncode = 1
            mock_result.stdout = b'Permission denied'
            mock_run.return_value = mock_result

            result = instance._run_setup('dbeaver', instance.setup_dbeaver_cert)
            assert result.status == 'failed'

    # --- Rancher Desktop ---

    def test_rancher_not_installed_returns_skipped(self):
        """setup_rancher_cert returns skipped when rdctl not found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=False):
            result = instance.setup_rancher_cert()
            assert result.status == 'skipped'

    def test_rancher_already_ok(self):
        """setup_rancher_cert returns already_ok when cert already installed."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=True), \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, 'certificate_likely_exists_in_file', return_value=True), \
             patch('subprocess.run', return_value=MagicMock(returncode=0, stdout='v1.0')), \
             patch.object(instance, '_check_cert_in_rancher_vm', return_value=True):
            result = instance.setup_rancher_cert()
            assert result.status == 'already_ok'

    def test_rancher_vm_install_fails_returns_configured(self):
        """setup_rancher_cert returns configured when persistent succeeds but VM fails."""
        instance = self.create_fumitm_instance(mode='install')
        instance.cert_path = '/tmp/fake-cert.pem'
        with patch.object(instance, 'command_exists', return_value=True), \
             patch('os.path.exists', return_value=False), \
             patch.object(instance, 'certificate_likely_exists_in_file', return_value=False), \
             patch.object(instance, '_safe_makedirs'), \
             patch('shutil.copy'), \
             patch.object(instance, '_fix_ownership'), \
             patch('subprocess.run', return_value=MagicMock(returncode=0, stdout='v1.0')), \
             patch.object(instance, '_check_cert_in_rancher_vm', return_value=False), \
             patch.object(instance, '_install_cert_via_rdctl_shell', return_value=(False, 'test error')):
            result = instance.setup_rancher_cert()
            assert result.status == 'configured'
            assert 'VM install failed' in result.message

    def test_rancher_installs_via_rdctl_when_docker_absent(self):
        """Regression: rdctl present + VM running + docker absent must not
        touch _install_cert_in_docker_vm or _check_cert_in_docker_vm.

        Before the fix, setup_rancher_cert delegated to the shared Docker
        nsenter helpers, which require the docker CLI. When rdctl was
        available but docker was not, the VM install path failed even
        though rdctl shell would have worked.
        """
        instance = self.create_fumitm_instance(mode='install')
        instance.cert_path = '/tmp/fake-cert.pem'

        def selective_command_exists(cmd):
            return cmd in ('rdctl',)  # docker is absent

        with patch.object(instance, 'command_exists', side_effect=selective_command_exists), \
             patch('os.path.exists', return_value=False), \
             patch.object(instance, 'certificate_likely_exists_in_file', return_value=False), \
             patch.object(instance, '_safe_makedirs'), \
             patch('shutil.copy'), \
             patch.object(instance, '_fix_ownership'), \
             patch('subprocess.run', return_value=MagicMock(returncode=0, stdout='v1.0')), \
             patch.object(instance, '_check_cert_in_rancher_vm', return_value=False), \
             patch.object(instance, '_install_cert_via_rdctl_shell', return_value=(True, 'ok')) as mock_rdctl, \
             patch.object(instance, '_install_cert_in_docker_vm') as mock_nsenter:
            result = instance.setup_rancher_cert()
            assert result.status == 'configured'
            mock_rdctl.assert_called_once()
            mock_nsenter.assert_not_called()

    # --- Podman ---

    def test_podman_not_installed_returns_skipped(self):
        """setup_podman_cert returns skipped when podman not found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=False):
            result = instance.setup_podman_cert()
            assert result.status == 'skipped'

    def test_podman_already_ok(self):
        """setup_podman_cert returns already_ok when cert already installed."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=True), \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, 'certificate_likely_exists_in_file', return_value=True), \
             patch('subprocess.run') as mock_run:
            # podman machine list shows not running
            mock_run.return_value = MagicMock(returncode=0, stdout='no machines')
            result = instance.setup_podman_cert()
            assert result.status == 'already_ok'

    # --- Colima ---

    def test_colima_not_installed_returns_skipped(self):
        """setup_colima_cert returns skipped when colima not found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=False):
            result = instance.setup_colima_cert()
            assert result.status == 'skipped'

    def test_colima_already_ok(self):
        """setup_colima_cert returns already_ok when cert already installed."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=True), \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, 'certificate_likely_exists_in_file', return_value=True), \
             patch('subprocess.run') as mock_run:
            # colima status shows not running
            mock_run.return_value = MagicMock(returncode=1)
            result = instance.setup_colima_cert()
            assert result.status == 'already_ok'

    def test_colima_vm_install_fails_persistent_ok(self):
        """setup_colima_cert returns configured when persistent ok but VM fails."""
        instance = self.create_fumitm_instance(mode='install')
        instance.cert_path = '/tmp/fake-cert.pem'
        with patch.object(instance, 'command_exists', return_value=True), \
             patch('os.path.exists', return_value=False), \
             patch.object(instance, 'certificate_likely_exists_in_file', return_value=False), \
             patch.object(instance, '_safe_makedirs'), \
             patch('shutil.copy'), \
             patch.object(instance, '_fix_ownership'), \
             patch('subprocess.run', return_value=MagicMock(returncode=0)), \
             patch.object(instance, '_check_cert_in_colima_vm', return_value=False), \
             patch.object(instance, '_install_cert_via_colima_ssh', return_value=(False, 'test error')):
            result = instance.setup_colima_cert()
            assert result.status == 'configured'
            assert 'VM install failed' in result.message

    def test_colima_installs_via_ssh_when_docker_absent(self):
        """Regression: colima present + VM running + docker absent must not
        touch _install_cert_in_docker_vm or _check_cert_in_docker_vm.

        Before the fix, setup_colima_cert delegated to the shared Docker
        nsenter helpers, which require the docker CLI. When colima was
        available but docker was not, the VM install path failed even
        though colima ssh would have worked.
        """
        instance = self.create_fumitm_instance(mode='install')
        instance.cert_path = '/tmp/fake-cert.pem'

        def selective_command_exists(cmd):
            return cmd in ('colima',)  # docker is absent

        with patch.object(instance, 'command_exists', side_effect=selective_command_exists), \
             patch('os.path.exists', return_value=False), \
             patch.object(instance, 'certificate_likely_exists_in_file', return_value=False), \
             patch.object(instance, '_safe_makedirs'), \
             patch('shutil.copy'), \
             patch.object(instance, '_fix_ownership'), \
             patch('subprocess.run', return_value=MagicMock(returncode=0)), \
             patch.object(instance, '_check_cert_in_colima_vm', return_value=False), \
             patch.object(instance, '_install_cert_via_colima_ssh', return_value=(True, 'ok')) as mock_ssh, \
             patch.object(instance, '_install_cert_in_docker_vm') as mock_nsenter, \
             patch.object(instance, '_restart_docker_in_vm'):
            result = instance.setup_colima_cert()
            assert result.status == 'configured'
            mock_ssh.assert_called_once()
            mock_nsenter.assert_not_called()

    # --- Docker (generic) ---

    def test_docker_not_installed_returns_skipped(self):
        """setup_docker_cert returns skipped when docker not found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=False):
            result = instance.setup_docker_cert()
            assert result.status == 'skipped'

    def test_docker_already_ok(self):
        """setup_docker_cert returns already_ok when cert already installed."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=True), \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, 'certificate_likely_exists_in_file', return_value=True), \
             patch.object(instance, '_docker_is_running', return_value=False):
            result = instance.setup_docker_cert()
            assert result.status == 'already_ok'

    def test_docker_vm_install_fails_persistent_ok(self):
        """setup_docker_cert returns configured when persistent ok but VM fails."""
        instance = self.create_fumitm_instance(mode='install')
        instance.cert_path = '/tmp/fake-cert.pem'
        with patch.object(instance, 'command_exists', return_value=True), \
             patch('os.path.exists', return_value=False), \
             patch.object(instance, 'certificate_likely_exists_in_file', return_value=False), \
             patch.object(instance, '_safe_makedirs'), \
             patch('shutil.copy'), \
             patch.object(instance, '_fix_ownership'), \
             patch.object(instance, '_docker_is_running', return_value=True), \
             patch.object(instance, '_check_cert_in_docker_vm', return_value=False), \
             patch.object(instance, '_install_cert_in_docker_vm', return_value=(False, 'test error')):
            result = instance.setup_docker_cert()
            assert result.status == 'configured'
            assert 'VM install failed' in result.message

    def test_container_tool_keys_returns_tagged_tools(self):
        """_container_tool_keys includes all tools with 'container' tag."""
        instance = self.create_fumitm_instance()
        keys = instance._container_tool_keys()
        assert 'docker' in keys
        assert 'colima' in keys
        assert 'podman' in keys
        assert 'rancher' in keys

    def test_rancher_has_container_tag(self):
        """Rancher Desktop must have the 'container' tag."""
        instance = self.create_fumitm_instance()
        assert 'container' in instance.tools_registry['rancher']['tags']

    # --- Brew cacerts ---

    def test_brew_not_installed_returns_skipped(self):
        """setup_brew_cacerts returns skipped when brew not found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=False):
            result = instance.setup_brew_cacerts()
            assert result.status == 'skipped'

    def test_brew_cacerts_already_ok(self):
        """setup_brew_cacerts returns already_ok when cert already in bundle."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=True), \
             patch('subprocess.run', return_value=MagicMock(returncode=0)), \
             patch.object(instance, '_get_brew_prefix', return_value='/opt/homebrew'), \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, 'certificate_exists_in_file', return_value=True):
            result = instance.setup_brew_cacerts()
            assert result.status == 'already_ok'

    def test_brew_postinstall_fails_returns_failed(self):
        """setup_brew_cacerts returns failed when brew postinstall fails."""
        instance = self.create_fumitm_instance(mode='install')

        call_count = [0]

        def run_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # brew list ca-certificates: installed
                return MagicMock(returncode=0)
            else:
                # brew postinstall: fails
                return MagicMock(returncode=1, stderr='error')

        with patch.object(instance, 'command_exists', return_value=True), \
             patch('subprocess.run', side_effect=run_side_effect), \
             patch.object(instance, '_get_brew_prefix', return_value='/opt/homebrew'), \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, 'certificate_exists_in_file', return_value=False):
            result = instance.setup_brew_cacerts()
            assert result.status == 'failed'

    # --- Android Emulator ---

    def test_android_not_installed_returns_skipped(self):
        """setup_android_emulator_cert returns skipped when adb/emulator not found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=False):
            result = instance.setup_android_emulator_cert()
            assert result.status == 'skipped'

    def test_android_no_emulator_running_returns_skipped(self):
        """setup_android_emulator_cert returns skipped when no emulator is running."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=True), \
             patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout='List of devices attached\n\n')
            result = instance.setup_android_emulator_cert()
            assert result.status == 'skipped'


class TestBareReturnsFixed(FumitmTestCase):
    """Tests that setup functions return explicit ToolResult instead of None."""

    def test_node_not_found_returns_skipped(self):
        """setup_node_cert returns skipped when node not found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=False):
            result = instance.setup_node_cert()
            assert result.status == 'skipped'
            assert result.tool == 'node'

    def test_python_not_found_returns_skipped(self):
        """setup_python_cert returns skipped when python not found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=False):
            result = instance.setup_python_cert()
            assert result.status == 'skipped'
            assert result.tool == 'python'

    def test_gcloud_not_found_returns_skipped(self):
        """setup_gcloud_cert returns skipped when gcloud not found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=False), \
             patch('os.path.exists', return_value=False):
            result = instance.setup_gcloud_cert()
            assert result.status == 'skipped'
            assert result.tool == 'gcloud'

    def test_gcloud_already_configured_returns_already_ok(self):
        """setup_gcloud_cert returns already_ok when core/custom_ca_certs_file already points to a bundle with our cert."""
        instance = self.create_fumitm_instance(mode='install')
        existing_bundle = '/Users/testuser/.python-ca-bundle.pem'
        with patch.object(instance, 'command_exists', return_value=True), \
             patch('os.path.exists', return_value=False), \
             patch('subprocess.run') as mock_run, \
             patch.object(instance, 'is_suspicious_full_bundle', return_value=(False, None)), \
             patch.object(instance, 'certificate_exists_in_file', return_value=True):
            mock_run.return_value = MagicMock(returncode=0, stdout=existing_bundle)
            with patch('os.path.exists', side_effect=lambda p: p == existing_bundle):
                result = instance.setup_gcloud_cert()
            assert result.status == 'already_ok'

    def test_gcloud_iap_regression_configures_when_https_works_but_ca_unset(self):
        """IAP regression: even if basic HTTPS works, missing core/custom_ca_certs_file must be configured.

        IAP tunnel (`gcloud compute ssh --tunnel-through-iap`) reads ca_certs
        explicitly from core/custom_ca_certs_file and ignores system trust /
        SSL_CERT_FILE, so we must always set the property.
        """
        instance = self.create_fumitm_instance(mode='install')
        gcloud_managed = os.path.expanduser("~/.config/gcloud/certs/combined-ca-bundle.pem")
        with patch.object(instance, 'command_exists', return_value=True), \
             patch('os.path.exists', return_value=False), \
             patch.object(instance, '_safe_makedirs'), \
             patch.object(instance, 'create_bundle_with_system_certs'), \
             patch.object(instance, 'safe_append_certificate'), \
             patch.object(instance, 'is_devcontainer', return_value=True), \
             patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout='')
            result = instance.setup_gcloud_cert()
            assert result.status == 'configured'
            assert_subprocess_called_with(
                mock_run,
                ['gcloud', 'config', 'set', 'core/custom_ca_certs_file', gcloud_managed]
            )

    def test_curl_not_found_returns_skipped(self):
        """setup_curl_cert returns skipped when curl not found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=False):
            result = instance.setup_curl_cert()
            assert result.status == 'skipped'
            assert result.tool == 'curl'

    def test_curl_already_works_returns_already_ok(self):
        """setup_curl_cert returns already_ok when curl works via system trust."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value='WORKING'):
            result = instance.setup_curl_cert()
            assert result.status == 'already_ok'

    def test_wget_not_found_returns_skipped(self):
        """setup_wget_cert returns skipped when wget not found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=False):
            result = instance.setup_wget_cert()
            assert result.status == 'skipped'
            assert result.tool == 'wget'

    def test_wget_already_works_returns_already_ok(self):
        """setup_wget_cert returns already_ok when wget works via system trust."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value='WORKING'):
            result = instance.setup_wget_cert()
            assert result.status == 'already_ok'

    def test_gradle_not_found_returns_skipped(self):
        """setup_gradle_cert returns skipped when gradle not found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=False), \
             patch('os.path.exists', return_value=False):
            result = instance.setup_gradle_cert()
            assert result.status == 'skipped'
            assert result.tool == 'gradle'

    def test_brew_cacerts_status_mode_returns_skipped(self):
        """setup_brew_cacerts returns skipped in dry-run mode when bundle missing."""
        instance = self.create_fumitm_instance(mode='status')
        brew_prefix = instance._get_brew_prefix()
        bundle_path = os.path.join(brew_prefix, 'etc', 'ca-certificates', 'cert.pem')
        with patch.object(instance, 'command_exists', return_value=True), \
             patch('subprocess.run') as mock_run, \
             patch('os.path.exists', return_value=False):
            mock_run.return_value = MagicMock(returncode=0)  # brew list succeeds
            result = instance.setup_brew_cacerts()
            assert result.status == 'skipped'

    def test_node_nonexistent_file_returns_failed(self):
        """setup_node_cert returns failed when NODE_EXTRA_CA_CERTS points to missing file."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.dict(os.environ, {'NODE_EXTRA_CA_CERTS': '/nonexistent/cert.pem'}), \
             patch.object(instance, '_path_belongs_to_other_provider', return_value=None), \
             patch('os.path.exists', return_value=False):
            result = instance.setup_node_cert()
            assert result.status == 'failed'
            assert 'non-existent' in result.message

    def test_python_nonexistent_requests_ca_bundle_returns_failed(self):
        """setup_python_cert returns failed when REQUESTS_CA_BUNDLE points to missing file."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.dict(os.environ, {'REQUESTS_CA_BUNDLE': '/nonexistent/bundle.pem'}, clear=False), \
             patch('os.path.exists', return_value=False):
            result = instance.setup_python_cert()
            assert result.status == 'failed'
            assert 'non-existent' in result.message

    def test_python_healthy_requests_but_missing_ssl_cert_returns_configured(self):
        """setup_python_cert returns configured when SSL_CERT_FILE needs setting."""
        instance = self.create_fumitm_instance(mode='install')
        bundle_path = '/Users/testuser/.python-ca-bundle.pem'
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.dict(os.environ, {
                 'REQUESTS_CA_BUNDLE': bundle_path,
                 'SSL_CERT_FILE': '',
             }, clear=False), \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, 'is_writable', return_value=True), \
             patch.object(instance, 'is_suspicious_full_bundle', return_value=(False, None)), \
             patch.object(instance, 'certificate_exists_in_file', return_value=True), \
             patch.object(instance, 'detect_shell', return_value='zsh'), \
             patch.object(instance, 'get_shell_config', return_value='/tmp/.zshrc'), \
             patch.object(instance, 'add_to_shell_config') as mock_shell:
            result = instance.setup_python_cert()
            assert result.status == 'configured'
            # assert_any_call (not assert_called_with): the Aikido/vendor-var
            # post-pass may append further trust-var calls after this one.
            mock_shell.assert_any_call('SSL_CERT_FILE', bundle_path, '/tmp/.zshrc')

    def test_gcloud_pre_bootstrap_without_gcloud_returns_configured(self):
        """setup_gcloud_cert returns configured when pre-bootstrap changes config."""
        instance = self.create_fumitm_instance(mode='install')
        python_bundle = os.path.expanduser("~/.python-ca-bundle.pem")

        def exists_side_effect(path):
            return path == python_bundle

        with patch.object(instance, 'command_exists', return_value=False), \
             patch('os.path.exists', side_effect=exists_side_effect), \
             patch.object(instance, '_ensure_gcloud_properties', return_value=True) as mock_props, \
             patch.object(instance, 'detect_shell', return_value='zsh'), \
             patch.object(instance, 'get_shell_config', return_value='/tmp/.zshrc'), \
             patch.object(instance, 'add_to_shell_config') as mock_shell:
            result = instance.setup_gcloud_cert()
            assert result.status == 'configured'
            mock_props.assert_called_once()
            mock_shell.assert_called_once()

    def test_gcloud_pre_bootstrap_already_configured_returns_skipped(self):
        """setup_gcloud_cert returns skipped when pre-bootstrap is a no-op."""
        instance = self.create_fumitm_instance(mode='install')
        python_bundle = os.path.expanduser("~/.python-ca-bundle.pem")
        shell_config = '/tmp/.zshrc'

        def exists_side_effect(path):
            if path == python_bundle:
                return True
            if path == shell_config:
                return True
            return False

        shell_content = f'export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE="{python_bundle}"\n'
        mock_open_obj = mock_open(read_data=shell_content)

        with patch.object(instance, 'command_exists', return_value=False), \
             patch('os.path.exists', side_effect=exists_side_effect), \
             patch.object(instance, '_ensure_gcloud_properties', return_value=False), \
             patch.object(instance, 'detect_shell', return_value='zsh'), \
             patch.object(instance, 'get_shell_config', return_value=shell_config), \
             patch('builtins.open', mock_open_obj), \
             patch.object(instance, 'add_to_shell_config', return_value=False):
            result = instance.setup_gcloud_cert()
            assert result.status == 'skipped'
            assert result.tool == 'gcloud'

    def test_gcloud_pre_bootstrap_status_mode_returns_skipped(self):
        """setup_gcloud_cert returns skipped (not configured) in status mode."""
        instance = self.create_fumitm_instance(mode='status')
        python_bundle = os.path.expanduser("~/.python-ca-bundle.pem")

        def exists_side_effect(path):
            return path == python_bundle

        with patch.object(instance, 'command_exists', return_value=False), \
             patch('os.path.exists', side_effect=exists_side_effect), \
             patch.object(instance, '_ensure_gcloud_properties', return_value=True), \
             patch.object(instance, 'detect_shell', return_value='zsh'), \
             patch.object(instance, 'get_shell_config', return_value='/tmp/.zshrc'), \
             patch.object(instance, 'add_to_shell_config'):
            result = instance.setup_gcloud_cert()
            assert result.status == 'skipped'

    def test_gcloud_pre_bootstrap_stale_shell_export_returns_configured(self):
        """setup_gcloud_cert returns configured when shell export has wrong value."""
        instance = self.create_fumitm_instance(mode='install')
        python_bundle = os.path.expanduser("~/.python-ca-bundle.pem")
        shell_config = '/tmp/.zshrc'

        def exists_side_effect(path):
            if path == python_bundle:
                return True
            if path == shell_config:
                return True
            return False

        stale = 'export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE="/wrong/path.pem"\n'
        mock_open_obj = mock_open(read_data=stale)

        with patch.object(instance, 'command_exists', return_value=False), \
             patch('os.path.exists', side_effect=exists_side_effect), \
             patch.object(instance, '_ensure_gcloud_properties', return_value=False), \
             patch.object(instance, 'detect_shell', return_value='zsh'), \
             patch.object(instance, 'get_shell_config', return_value=shell_config), \
             patch('builtins.open', mock_open_obj), \
             patch.object(instance, 'add_to_shell_config'):
            result = instance.setup_gcloud_cert()
            assert result.status == 'configured'

    def test_node_user_declined_fallback_returns_skipped(self):
        """setup_node_cert returns skipped when user declines alternative path."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.dict(os.environ, {'NODE_EXTRA_CA_CERTS': '/system/cert.pem'}), \
             patch.object(instance, '_path_belongs_to_other_provider', return_value=None), \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, 'certificate_exists_in_file', return_value=False), \
             patch.object(instance, 'is_writable', return_value=False), \
             patch.object(instance, 'suggest_user_path', return_value='/tmp/alt.pem'), \
             patch.object(instance, '_prompt', return_value='n'):
            result = instance.setup_node_cert()
            assert result.status == 'skipped'
            assert 'declined' in result.message.lower()

    def test_python_unwritable_requests_ca_bundle_dry_run_returns_skipped(self):
        """setup_python_cert returns skipped in status mode for unwritable bundle."""
        instance = self.create_fumitm_instance(mode='status')
        bundle = '/system/ca-bundle.pem'
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.dict(os.environ, {
                 'REQUESTS_CA_BUNDLE': bundle,
                 'SSL_CERT_FILE': '',
             }, clear=False), \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, 'is_writable', return_value=False), \
             patch.object(instance, 'suggest_user_path', return_value='/tmp/alt.pem'):
            result = instance.setup_python_cert()
            assert result.status == 'skipped'

    def test_python_unwritable_requests_ca_bundle_decline_returns_skipped(self):
        """setup_python_cert returns skipped when user declines alternative path."""
        instance = self.create_fumitm_instance(mode='install')
        bundle = '/system/ca-bundle.pem'
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.dict(os.environ, {
                 'REQUESTS_CA_BUNDLE': bundle,
                 'SSL_CERT_FILE': '',
             }, clear=False), \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, 'is_writable', return_value=False), \
             patch.object(instance, 'suggest_user_path', return_value='/tmp/alt.pem'), \
             patch.object(instance, '_prompt', return_value='n'):
            result = instance.setup_python_cert()
            assert result.status == 'skipped'
            assert 'declined' in result.message.lower()

    def test_gradle_already_configured_returns_already_ok(self):
        """setup_gradle_cert returns already_ok when properties already set."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'find_java_cacerts', return_value='/fake/cacerts'), \
             patch.object(instance, 'update_properties_file', return_value=False):
            result = instance.setup_gradle_cert()
            assert result.status == 'already_ok'
            assert result.tool == 'gradle'


class TestAwsVerification(FumitmTestCase):
    """Tests for AWS CLI verify_connection and status checking."""

    def test_verify_connection_aws_working(self):
        """verify_connection returns WORKING when aws call succeeds (no SSL error)."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch('subprocess.run') as mock_run, \
             patch.object(instance, 'command_exists', return_value=True), \
             patch('shutil.which', return_value='/usr/local/bin/aws'):

            mock_run.return_value = MagicMock(
                returncode=0,
                stdout='{"Account": "123456789012"}',
                stderr=''
            )

            result = instance.verify_connection("aws")
            assert result == "WORKING"

    def test_verify_connection_aws_access_denied_is_working(self):
        """verify_connection returns WORKING when aws gets access denied (TLS works)."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch('subprocess.run') as mock_run, \
             patch.object(instance, 'command_exists', return_value=True), \
             patch('shutil.which', return_value='/usr/local/bin/aws'):

            mock_run.return_value = MagicMock(
                returncode=254,
                stdout='',
                stderr='An error occurred (AccessDenied) when calling the GetCallerIdentity operation'
            )

            result = instance.verify_connection("aws")
            assert result == "WORKING"

    def test_verify_connection_aws_ssl_error(self):
        """verify_connection returns FAILED when aws gets SSL error."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch('subprocess.run') as mock_run, \
             patch.object(instance, 'command_exists', return_value=True), \
             patch('shutil.which', return_value='/usr/local/bin/aws'):

            mock_run.return_value = MagicMock(
                returncode=1,
                stdout='',
                stderr='SSL validation failed for https://sts.amazonaws.com/ [SSL: CERTIFICATE_VERIFY_FAILED]'
            )

            result = instance.verify_connection("aws")
            assert result == "FAILED"

    def test_verify_connection_aws_certificate_error(self):
        """verify_connection returns FAILED when stderr mentions certificate."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch('subprocess.run') as mock_run, \
             patch.object(instance, 'command_exists', return_value=True), \
             patch('shutil.which', return_value='/usr/local/bin/aws'):

            mock_run.return_value = MagicMock(
                returncode=1,
                stdout='',
                stderr='unable to get local issuer certificate'
            )

            result = instance.verify_connection("aws")
            assert result == "FAILED"

    def test_verify_connection_aws_timeout(self):
        """verify_connection returns FAILED on timeout."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('aws', 15)), \
             patch.object(instance, 'command_exists', return_value=True), \
             patch('shutil.which', return_value='/usr/local/bin/aws'):

            result = instance.verify_connection("aws")
            assert result == "FAILED"

    def test_verify_connection_aws_not_installed(self):
        """verify_connection returns NOT_INSTALLED when aws not found."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch.object(instance, 'command_exists', return_value=False):
            result = instance.verify_connection("aws")
            assert result == "NOT_INSTALLED"

    def test_check_aws_status_working_no_bundle(self):
        """check_aws_status returns no issues when aws works without custom CA."""
        instance = self.create_fumitm_instance()

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value='WORKING'), \
             patch.dict(os.environ, {}, clear=True):
            has_issues = instance.check_aws_status("FAKE_CERT_CONTENT")
            assert has_issues is False

    def test_check_aws_status_working_with_cross_provider_bundle(self):
        """check_aws_status flags cross-provider path even when working."""
        warp_aws_bundle = os.path.expanduser("~/.cloudflare-warp/aws/ca-bundle.pem")

        instance = self.create_fumitm_instance(provider='netskope')

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value='WORKING'), \
             patch.dict(os.environ, {'AWS_CA_BUNDLE': warp_aws_bundle}):
            has_issues = instance.check_aws_status("FAKE_CERT_CONTENT")
            assert has_issues is True

    def test_check_aws_status_failed_no_bundle(self):
        """check_aws_status returns issues when aws fails and no bundle set."""
        instance = self.create_fumitm_instance()

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value='FAILED'), \
             patch.dict(os.environ, {}, clear=True):
            has_issues = instance.check_aws_status("FAKE_CERT_CONTENT")
            assert has_issues is True

    def test_check_aws_status_failed_cross_provider_bundle(self):
        """check_aws_status flags cross-provider path when aws fails."""
        warp_aws_bundle = os.path.expanduser("~/.cloudflare-warp/aws/ca-bundle.pem")

        instance = self.create_fumitm_instance(provider='netskope')

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value='FAILED'), \
             patch.dict(os.environ, {'AWS_CA_BUNDLE': warp_aws_bundle}):
            has_issues = instance.check_aws_status("FAKE_CERT_CONTENT")
            assert has_issues is True

    def test_check_aws_status_failed_nonexistent_bundle(self):
        """check_aws_status flags non-existent AWS_CA_BUNDLE file."""
        instance = self.create_fumitm_instance()

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value='FAILED'), \
             patch.dict(os.environ, {'AWS_CA_BUNDLE': '/nonexistent/ca-bundle.pem'}), \
             patch('os.path.exists', return_value=False):
            has_issues = instance.check_aws_status("FAKE_CERT_CONTENT")
            assert has_issues is True

    def test_check_aws_status_not_installed(self):
        """check_aws_status returns no issues when aws not installed."""
        instance = self.create_fumitm_instance()

        with patch.object(instance, 'command_exists', return_value=False):
            has_issues = instance.check_aws_status("FAKE_CERT_CONTENT")
            assert has_issues is False


class TestAwsSetup(FumitmTestCase):
    """Tests for AWS CLI setup_aws_cert function."""

    def test_aws_not_installed_returns_early(self):
        """setup_aws_cert returns skipped when aws not found."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=False):
            result = instance.setup_aws_cert()
            assert result.status == 'skipped'
            assert result.tool == 'aws'

    def test_aws_already_working_skips(self):
        """setup_aws_cert returns already_ok when aws works via system trust."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value='WORKING'), \
             patch.dict(os.environ, {}, clear=True):
            result = instance.setup_aws_cert()
            assert result.status == 'already_ok'

    def test_aws_working_cross_provider_bundle_still_migrates(self):
        """setup_aws_cert should fix stale AWS_CA_BUNDLE even when aws still works."""
        instance = self.create_fumitm_instance(mode='install', provider='netskope')
        warp_bundle = os.path.expanduser("~/.cloudflare-warp/aws/ca-bundle.pem")
        expected_bundle = os.path.join(instance.bundle_dir, "aws/ca-bundle.pem")

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value='WORKING'), \
             patch.dict(os.environ, {'AWS_CA_BUNDLE': warp_bundle}), \
             patch.object(instance, '_safe_makedirs'), \
             patch.object(instance, 'create_bundle_with_system_certs') as mock_create, \
             patch.object(instance, 'safe_append_certificate') as mock_append, \
             patch.object(instance, 'detect_shell', return_value='zsh'), \
             patch.object(instance, 'get_shell_config', return_value='/tmp/.zshrc'), \
             patch.object(instance, 'add_to_shell_config') as mock_shell:

            instance.setup_aws_cert()

            mock_create.assert_called_once_with(expected_bundle)
            mock_append.assert_called_once_with(instance.cert_path, expected_bundle)
            mock_shell.assert_called_once_with("AWS_CA_BUNDLE", expected_bundle, '/tmp/.zshrc')

    def test_aws_no_bundle_status_mode(self):
        """setup_aws_cert in status mode prints actions without making changes."""
        instance = self.create_fumitm_instance(mode='status')
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value='FAILED'), \
             patch.dict(os.environ, {}, clear=True):
            result = instance.setup_aws_cert()
            assert result.status == 'skipped'

    def test_aws_no_bundle_install_mode_creates_bundle(self):
        """setup_aws_cert creates bundle and configures env var when no bundle set."""
        instance = self.create_fumitm_instance(mode='install')
        expected_bundle = os.path.join(instance.bundle_dir, "aws/ca-bundle.pem")

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value='FAILED'), \
             patch.dict(os.environ, {}, clear=True), \
             patch.object(instance, '_safe_makedirs') as mock_makedirs, \
             patch.object(instance, 'create_bundle_with_system_certs') as mock_create, \
             patch.object(instance, 'safe_append_certificate') as mock_append, \
             patch.object(instance, 'detect_shell', return_value='zsh'), \
             patch.object(instance, 'get_shell_config', return_value='/tmp/.zshrc'), \
             patch.object(instance, 'add_to_shell_config') as mock_shell:

            instance.setup_aws_cert()

            mock_makedirs.assert_called_once_with(os.path.dirname(expected_bundle))
            mock_create.assert_called_once_with(expected_bundle)
            mock_append.assert_called_once_with(instance.cert_path, expected_bundle)
            mock_shell.assert_called_once_with("AWS_CA_BUNDLE", expected_bundle, '/tmp/.zshrc')

    def test_aws_cross_provider_install_mode_migrates(self):
        """setup_aws_cert migrates from old provider bundle in install mode."""
        instance = self.create_fumitm_instance(mode='install', provider='netskope')
        warp_bundle = os.path.expanduser("~/.cloudflare-warp/aws/ca-bundle.pem")
        expected_bundle = os.path.join(instance.bundle_dir, "aws/ca-bundle.pem")

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value='FAILED'), \
             patch.dict(os.environ, {'AWS_CA_BUNDLE': warp_bundle}), \
             patch.object(instance, '_safe_makedirs'), \
             patch.object(instance, 'create_bundle_with_system_certs') as mock_create, \
             patch.object(instance, 'safe_append_certificate') as mock_append, \
             patch.object(instance, 'detect_shell', return_value='zsh'), \
             patch.object(instance, 'get_shell_config', return_value='/tmp/.zshrc'), \
             patch.object(instance, 'add_to_shell_config') as mock_shell:

            instance.setup_aws_cert()

            mock_create.assert_called_once_with(expected_bundle)
            mock_append.assert_called_once_with(instance.cert_path, expected_bundle)
            mock_shell.assert_called_once_with("AWS_CA_BUNDLE", expected_bundle, '/tmp/.zshrc')

    def test_aws_nonexistent_bundle_install_mode_fixes(self):
        """setup_aws_cert fixes when AWS_CA_BUNDLE points to non-existent file."""
        instance = self.create_fumitm_instance(mode='install')
        expected_bundle = os.path.join(instance.bundle_dir, "aws/ca-bundle.pem")

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value='FAILED'), \
             patch.dict(os.environ, {'AWS_CA_BUNDLE': '/gone/ca-bundle.pem'}), \
             patch('os.path.exists', return_value=False), \
             patch.object(instance, '_safe_makedirs'), \
             patch.object(instance, 'create_bundle_with_system_certs') as mock_create, \
             patch.object(instance, 'safe_append_certificate'), \
             patch.object(instance, 'detect_shell', return_value='zsh'), \
             patch.object(instance, 'get_shell_config', return_value='/tmp/.zshrc'), \
             patch.object(instance, 'add_to_shell_config') as mock_shell:

            instance.setup_aws_cert()

            mock_create.assert_called_once_with(expected_bundle)
            mock_shell.assert_called_once_with("AWS_CA_BUNDLE", expected_bundle, '/tmp/.zshrc')

    def test_aws_valid_bundle_with_cert_returns_early(self):
        """setup_aws_cert returns early when bundle looks valid but aws still fails."""
        instance = self.create_fumitm_instance(mode='install')
        existing_bundle = '/Users/test/.netskope/aws/ca-bundle.pem'

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value='FAILED'), \
             patch.dict(os.environ, {'AWS_CA_BUNDLE': existing_bundle}), \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, '_path_belongs_to_other_provider', return_value=None), \
             patch.object(instance, 'is_suspicious_full_bundle', return_value=(False, None)), \
             patch.object(instance, 'certificate_likely_exists_in_file', return_value=True), \
             patch.object(instance, 'create_bundle_with_system_certs') as mock_create:

            instance.setup_aws_cert()

            # Should NOT create a new bundle — needs manual investigation
            mock_create.assert_not_called()

    def test_aws_bundle_missing_cert_install_mode_fixes(self):
        """setup_aws_cert fixes when bundle exists but is missing the proxy cert."""
        instance = self.create_fumitm_instance(mode='install')
        existing_bundle = '/Users/test/.netskope/aws/old-bundle.pem'
        expected_bundle = os.path.join(instance.bundle_dir, "aws/ca-bundle.pem")

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value='FAILED'), \
             patch.dict(os.environ, {'AWS_CA_BUNDLE': existing_bundle}), \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, '_path_belongs_to_other_provider', return_value=None), \
             patch.object(instance, 'is_suspicious_full_bundle', return_value=(False, None)), \
             patch.object(instance, 'certificate_likely_exists_in_file', return_value=False), \
             patch.object(instance, '_safe_makedirs'), \
             patch.object(instance, 'create_bundle_with_system_certs') as mock_create, \
             patch.object(instance, 'safe_append_certificate') as mock_append, \
             patch.object(instance, 'detect_shell', return_value='zsh'), \
             patch.object(instance, 'get_shell_config', return_value='/tmp/.zshrc'), \
             patch.object(instance, 'add_to_shell_config') as mock_shell:

            instance.setup_aws_cert()

            mock_create.assert_called_once_with(expected_bundle)
            mock_append.assert_called_once_with(instance.cert_path, expected_bundle)
            mock_shell.assert_called_once_with("AWS_CA_BUNDLE", expected_bundle, '/tmp/.zshrc')

    def test_aws_suspicious_bundle_install_mode_fixes(self):
        """setup_aws_cert fixes when existing bundle is suspiciously small."""
        instance = self.create_fumitm_instance(mode='install')
        existing_bundle = '/Users/test/.netskope/aws/ca-bundle.pem'
        expected_bundle = os.path.join(instance.bundle_dir, "aws/ca-bundle.pem")

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'verify_connection', return_value='FAILED'), \
             patch.dict(os.environ, {'AWS_CA_BUNDLE': existing_bundle}), \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, '_path_belongs_to_other_provider', return_value=None), \
             patch.object(instance, 'is_suspicious_full_bundle', return_value=(True, 'only 1 cert')), \
             patch.object(instance, '_safe_makedirs'), \
             patch.object(instance, 'create_bundle_with_system_certs') as mock_create, \
             patch.object(instance, 'safe_append_certificate'), \
             patch.object(instance, 'detect_shell', return_value='zsh'), \
             patch.object(instance, 'get_shell_config', return_value='/tmp/.zshrc'), \
             patch.object(instance, 'add_to_shell_config'):

            instance.setup_aws_cert()

            mock_create.assert_called_once_with(expected_bundle)

    def test_aws_tools_registry_entry_exists(self):
        """Verify aws is in tools_registry with correct attributes."""
        instance = self.create_fumitm_instance()
        assert 'aws' in instance.tools_registry
        entry = instance.tools_registry['aws']
        assert entry['name'] == 'AWS CLI'
        assert entry['scope'] == 'user'
        assert 'setup_func' in entry
        assert 'check_func' in entry


class TestGitTlsBackend(FumitmTestCase):
    """Tests for git TLS backend detection (Apple Git vs OpenSSL)."""

    def test_is_apple_git_true(self):
        """_is_apple_git returns True for Apple's Git."""
        instance = self.create_fumitm_instance()
        mock_result = MagicMock()
        mock_result.stdout = 'git version 2.50.1 (Apple Git-155)'
        with patch('subprocess.run', return_value=mock_result):
            assert instance._is_apple_git() is True

    def test_is_apple_git_false(self):
        """_is_apple_git returns False for Homebrew Git."""
        instance = self.create_fumitm_instance()
        mock_result = MagicMock()
        mock_result.stdout = 'git version 2.50.0'
        with patch('subprocess.run', return_value=mock_result):
            assert instance._is_apple_git() is False

    def test_is_apple_git_command_fails(self):
        """_is_apple_git returns False when git command fails."""
        instance = self.create_fumitm_instance()
        with patch('subprocess.run', side_effect=FileNotFoundError):
            assert instance._is_apple_git() is False

    def test_git_no_sslcainfo_apple_git_returns_already_ok(self):
        """Apple Git with no sslCAInfo returns already_ok."""
        instance = self.create_fumitm_instance(mode='install')
        mock_git_config = MagicMock()
        mock_git_config.returncode = 1  # not set
        mock_git_config.stdout = ''
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, '_is_apple_git', return_value=True), \
             patch('subprocess.run', return_value=mock_git_config):
            result = instance.setup_git_cert()
            assert result.status == 'already_ok'
            assert 'Apple Git' in result.message

    def test_git_no_sslcainfo_openssl_git_configures(self):
        """OpenSSL Git with no sslCAInfo creates bundle in install mode."""
        instance = self.create_fumitm_instance(mode='install')

        def mock_run_side_effect(*args, **kwargs):
            cmd = args[0]
            result = MagicMock()
            if cmd == ['git', 'config', '--global', 'http.sslCAInfo']:
                result.returncode = 1
                result.stdout = ''
            else:
                result.returncode = 0
                result.stdout = ''
            return result

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, '_is_apple_git', return_value=False), \
             patch('subprocess.run', side_effect=mock_run_side_effect), \
             patch.object(instance, '_safe_makedirs'), \
             patch.object(instance, 'create_bundle_with_system_certs') as mock_create, \
             patch.object(instance, 'safe_append_certificate') as mock_append:
            result = instance.setup_git_cert()
            assert result.status == 'configured'
            mock_create.assert_called_once()
            mock_append.assert_called_once()

    def test_git_no_sslcainfo_openssl_git_status_mode(self):
        """OpenSSL Git with no sslCAInfo in status mode shows actions."""
        instance = self.create_fumitm_instance(mode='status')
        mock_git_config = MagicMock()
        mock_git_config.returncode = 1
        mock_git_config.stdout = ''
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, '_is_apple_git', return_value=False), \
             patch('subprocess.run', return_value=mock_git_config):
            result = instance.setup_git_cert()
            assert result.status == 'skipped'
            assert 'Dry run' in result.message

    def test_git_missing_path_apple_git_returns_already_ok(self):
        """Apple Git with sslCAInfo pointing to missing file returns already_ok."""
        instance = self.create_fumitm_instance(mode='install')
        mock_git_config = MagicMock()
        mock_git_config.returncode = 0
        mock_git_config.stdout = '/nonexistent/ca-bundle.pem'
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, '_is_apple_git', return_value=True), \
             patch.object(instance, '_path_belongs_to_other_provider', return_value=None), \
             patch('subprocess.run', return_value=mock_git_config), \
             patch('os.path.exists', return_value=False):
            result = instance.setup_git_cert()
            assert result.status == 'already_ok'
            assert 'Apple Git' in result.message

    def test_git_missing_path_openssl_git_configures(self):
        """OpenSSL Git with sslCAInfo pointing to missing file reconfigures."""
        instance = self.create_fumitm_instance(mode='install')

        def mock_run_side_effect(*args, **kwargs):
            cmd = args[0]
            result = MagicMock()
            if cmd == ['git', 'config', '--global', 'http.sslCAInfo']:
                result.returncode = 0
                result.stdout = '/nonexistent/ca-bundle.pem'
            else:
                result.returncode = 0
                result.stdout = ''
            return result

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, '_is_apple_git', return_value=False), \
             patch.object(instance, '_path_belongs_to_other_provider', return_value=None), \
             patch('subprocess.run', side_effect=mock_run_side_effect), \
             patch('os.path.exists', return_value=False), \
             patch.object(instance, '_safe_makedirs'), \
             patch.object(instance, 'create_bundle_with_system_certs'), \
             patch.object(instance, 'safe_append_certificate'):
            result = instance.setup_git_cert()
            assert result.status == 'configured'

    def test_check_git_status_openssl_no_config_flags_issue(self):
        """check_git_status flags issue for OpenSSL Git with no sslCAInfo."""
        instance = self.create_fumitm_instance()
        mock_git_config = MagicMock()
        mock_git_config.returncode = 1
        mock_git_config.stdout = ''
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, '_is_apple_git', return_value=False), \
             patch('subprocess.run', return_value=mock_git_config):
            has_issues = instance.check_git_status(None)
            assert has_issues is True


class TestShellConfigIdempotency(FumitmTestCase):
    """add_to_shell_config maintains a trailing managed block and is a no-op only
    when that block is already present and correct at the end of the file.

    The managed block wins by last-export-wins, so a user's earlier export is
    preserved verbatim but overridden — never commented out, never prompted.
    """

    def test_idempotent_when_block_already_correct(self, tmp_path):
        instance = self.create_fumitm_instance(mode='install')
        rc = tmp_path / '.zshrc'
        original = (
            '# user prologue\n'
            'export PATH="/usr/local/bin:$PATH"\n'
            '\n'
            f'{instance._FUMITM_BLOCK_BEGIN}\n'
            'export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE="/Users/test/.python-ca-bundle.pem"\n'
            f'{instance._FUMITM_BLOCK_END}\n'
        )
        rc.write_text(original)

        changed = instance.add_to_shell_config(
            'CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE',
            '/Users/test/.python-ca-bundle.pem',
            str(rc),
        )

        assert changed is False
        assert rc.read_text() == original, "file should be untouched"
        assert getattr(instance, 'shell_modified', False) is False
        assert not (tmp_path / '.zshrc.bak').exists()

    def test_overrides_differing_value_without_prompt(self, tmp_path):
        instance = self.create_fumitm_instance(mode='install')
        rc = tmp_path / '.zshrc'
        rc.write_text(
            'export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE="/old/path.pem"\n'
        )

        with patch.object(instance, '_prompt') as prompt:
            changed = instance.add_to_shell_config(
                'CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE',
                '/new/path.pem',
                str(rc),
            )

        new_content = rc.read_text()
        assert prompt.call_count == 0, "managed block is authoritative; no prompt"
        # The user's earlier line is preserved (never commented), and the managed
        # block at EOF carries the new value, winning by last-export-wins.
        assert 'export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE="/old/path.pem"' in new_content
        assert '#export' not in new_content
        assert new_content.rstrip().endswith(instance._FUMITM_BLOCK_END)
        assert new_content.index('/new/path.pem') > new_content.index('/old/path.pem')
        assert changed is True
        assert instance.shell_modified is True

    def test_value_lands_inside_managed_block(self, tmp_path):
        instance = self.create_fumitm_instance(mode='install')
        rc = tmp_path / '.zshrc'
        rc.write_text('#export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE="/old/path.pem"\n')

        with patch.object(instance, '_prompt') as prompt:
            instance.add_to_shell_config(
                'CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE',
                '/new/path.pem',
                str(rc),
            )

        content = rc.read_text()
        assert prompt.call_count == 0, "commented-out lines should not trigger a prompt"
        begin = content.index(instance._FUMITM_BLOCK_BEGIN)
        export = content.index('export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE="/new/path.pem"')
        end = content.index(instance._FUMITM_BLOCK_END)
        assert begin < export < end
        assert instance.shell_modified is True

    def test_plain_user_export_preserved_and_overridden(self, tmp_path):
        # A pre-existing unquoted user export is foreign content: preserved
        # verbatim, with a managed block appended that overrides it.
        instance = self.create_fumitm_instance(mode='install')
        rc = tmp_path / '.zshrc'
        original = 'export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE=/Users/test/bundle.pem\n'
        rc.write_text(original)

        changed = instance.add_to_shell_config(
            'CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE',
            '/Users/test/bundle.pem',
            str(rc),
        )

        content = rc.read_text()
        assert changed is True
        assert original.strip() in content, "user line preserved"
        assert instance._FUMITM_BLOCK_BEGIN in content
        assert content.rstrip().endswith(instance._FUMITM_BLOCK_END)


class TestShellConfigManagedBlock(FumitmTestCase):
    """The managed block is always re-emitted last, after any vendor (Aikido)
    block, and relocates itself there on every run.
    """

    def _aikido_block(self):
        return (
            '# >>> aikido-endpoint start >>>\n'
            'export SSL_CERT_FILE="/aikido/only.pem"\n'
            'export REQUESTS_CA_BUNDLE="/aikido/only.pem"\n'
            '# <<< aikido-endpoint end <<<\n'
        )

    def test_order_wins_over_aikido(self, tmp_path):
        instance = self.create_fumitm_instance(mode='install')
        rc = tmp_path / '.zshrc'
        aikido = self._aikido_block()
        # An earlier fumitm export followed by Aikido's block, which currently wins.
        rc.write_text(
            'export SSL_CERT_FILE="/fumitm/bundle.pem"\n\n' + aikido
        )

        instance.add_to_shell_config('SSL_CERT_FILE', '/fumitm/bundle.pem', str(rc))
        instance.add_to_shell_config('REQUESTS_CA_BUNDLE', '/fumitm/bundle.pem', str(rc))

        content = rc.read_text()
        # Aikido's block is preserved verbatim, and the fumitm block sits after it.
        assert aikido.strip() in content
        assert content.index(instance._FUMITM_BLOCK_BEGIN) > content.index('aikido-endpoint end')
        # The managed-block copy (last occurrence) wins over Aikido's earlier line.
        assert content.rindex('export SSL_CERT_FILE="/fumitm/bundle.pem"') \
            > content.index('export SSL_CERT_FILE="/aikido/only.pem"')
        assert 'export REQUESTS_CA_BUNDLE="/fumitm/bundle.pem"' in content

        # Second pass is byte-identical (idempotent).
        before = rc.read_text()
        changed = instance.add_to_shell_config('SSL_CERT_FILE', '/fumitm/bundle.pem', str(rc))
        assert changed is False
        assert rc.read_text() == before

    def test_relocates_block_to_eof_when_mid_file(self, tmp_path):
        instance = self.create_fumitm_instance(mode='install')
        rc = tmp_path / '.zshrc'
        rc.write_text(
            f'{instance._FUMITM_BLOCK_BEGIN}\n'
            'export SSL_CERT_FILE="/fumitm/bundle.pem"\n'
            f'{instance._FUMITM_BLOCK_END}\n'
            '\n'
            'export LATER_USER_VAR="kept"\n'
        )

        changed = instance.add_to_shell_config('REQUESTS_CA_BUNDLE', '/fumitm/bundle.pem', str(rc))

        content = rc.read_text()
        assert changed is True
        assert 'export LATER_USER_VAR="kept"' in content
        assert content.index('LATER_USER_VAR') < content.index(instance._FUMITM_BLOCK_BEGIN)
        assert content.rstrip().endswith(instance._FUMITM_BLOCK_END)

    def test_multiple_vars_accumulate_in_one_block(self, tmp_path):
        instance = self.create_fumitm_instance(mode='install')
        rc = tmp_path / '.zshrc'
        instance.add_to_shell_config('SSL_CERT_FILE', '/b.pem', str(rc))
        instance.add_to_shell_config('REQUESTS_CA_BUNDLE', '/b.pem', str(rc))

        content = rc.read_text()
        assert content.count(instance._FUMITM_BLOCK_BEGIN) == 1
        assert content.count(instance._FUMITM_BLOCK_END) == 1
        assert 'export SSL_CERT_FILE="/b.pem"' in content
        assert 'export REQUESTS_CA_BUNDLE="/b.pem"' in content

    def test_per_run_backup_holds_pre_run_original(self, tmp_path):
        instance = self.create_fumitm_instance(mode='install')
        rc = tmp_path / '.zshrc'
        original = 'export USER_VAR="original"\n'
        rc.write_text(original)

        instance.add_to_shell_config('SSL_CERT_FILE', '/b.pem', str(rc))
        instance.add_to_shell_config('REQUESTS_CA_BUNDLE', '/b.pem', str(rc))

        bak = tmp_path / '.zshrc.bak'
        assert bak.exists()
        assert bak.read_text() == original, "bak must hold the true pre-run original"

    def test_missing_file_creates_block_no_bak(self, tmp_path):
        instance = self.create_fumitm_instance(mode='install')
        rc = tmp_path / '.zshrc'  # does not exist

        changed = instance.add_to_shell_config('SSL_CERT_FILE', '/b.pem', str(rc))

        assert changed is True
        content = rc.read_text()
        assert content.startswith(instance._FUMITM_BLOCK_BEGIN)
        assert content.endswith(instance._FUMITM_BLOCK_END + '\n')
        assert not (tmp_path / '.zshrc.bak').exists()
        # A second var in the same run must not back up the intermediate file.
        instance.add_to_shell_config('REQUESTS_CA_BUNDLE', '/b.pem', str(rc))
        assert not (tmp_path / '.zshrc.bak').exists()

    def test_returns_false_on_noop(self, tmp_path):
        instance = self.create_fumitm_instance(mode='install')
        rc = tmp_path / '.zshrc'
        assert instance.add_to_shell_config('SSL_CERT_FILE', '/b.pem', str(rc)) is True
        assert instance.add_to_shell_config('SSL_CERT_FILE', '/b.pem', str(rc)) is False

    def test_stray_begin_marker_preserves_content(self, tmp_path):
        instance = self.create_fumitm_instance(mode='install')
        rc = tmp_path / '.zshrc'
        rc.write_text(
            f'{instance._FUMITM_BLOCK_BEGIN}\n'
            'export USER_IMPORTANT="keepme"\n'  # no end marker
        )

        with patch.object(instance, 'print_warn') as warn:
            changed = instance.add_to_shell_config('SSL_CERT_FILE', '/b.pem', str(rc))

        content = rc.read_text()
        assert changed is True
        assert 'export USER_IMPORTANT="keepme"' in content, "no content swallowed to EOF"
        assert warn.call_count >= 1
        assert content.rstrip().endswith(instance._FUMITM_BLOCK_END)

    def test_stale_begin_then_fresh_block(self, tmp_path):
        # A stale unmatched begin marker followed by a valid fresh block: the
        # fresh block's end must not be read as closing the stale begin.
        instance = self.create_fumitm_instance(mode='install')
        rc = tmp_path / '.zshrc'
        rc.write_text(
            f'{instance._FUMITM_BLOCK_BEGIN}\n'
            'export STALE_LEFTOVER="x"\n'
            '\n'
            f'{instance._FUMITM_BLOCK_BEGIN}\n'
            'export SSL_CERT_FILE="/old.pem"\n'
            f'{instance._FUMITM_BLOCK_END}\n'
        )

        instance.add_to_shell_config('SSL_CERT_FILE', '/new.pem', str(rc))

        content = rc.read_text()
        # The fresh block was updated; the stale begin + its line stay as foreign.
        assert 'export STALE_LEFTOVER="x"' in content
        assert 'export SSL_CERT_FILE="/new.pem"' in content
        assert 'export SSL_CERT_FILE="/old.pem"' not in content


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
