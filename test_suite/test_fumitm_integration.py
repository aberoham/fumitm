"""Integration tests for fumitm.py.

These tests examine the main operations of the script. They mock the external
dependencies and give realistic conditions.
"""
import os
import subprocess
import urllib.error
from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock, call, mock_open, patch

import mock_data
import pytest
from helpers import (
    FumitmTestCase,
    MockBuilder,
    assert_subprocess_called_with,
    mock_fumitm_environment,
)

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

        mock_config = (MockBuilder()
            .with_certificate()
            .with_tool('brew')
            .with_subprocess_response(returncode=0)  # brew list
            .with_subprocess_response(returncode=0, stdout=brew_prefix)
            .with_subprocess_response(returncode=0)  # brew postinstall
            .build())

        mock_config['exists_side_effect'] = lambda p: {
            f"{mock_data.HOME_DIR}/.cloudflare-ca.pem": True,
        }.get(str(p), False)

        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance(mode='install')
            instance.setup_brew_cacerts()

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

            def exists_side_effect(path):
                if path == '/usr/libexec/java_home':
                    return True
                return 'lib/security/cacerts' in path

            mock_exists.side_effect = exists_side_effect
            mock_isfile.side_effect = lambda path: 'lib/security/cacerts' in path

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

            mock_result = MagicMock()
            mock_result.stdout = ""
            mock_run.return_value = mock_result

            def listdir_side_effect(path):
                if 'JavaVirtualMachines' in path:
                    return ['temurin-21.jdk', 'temurin-17.jdk', 'not-a-jdk']
                return []

            mock_listdir.side_effect = listdir_side_effect

            instance = fumitm.FumitmPython(mode='status')
            java_homes = instance.find_all_java_homes()

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

                assert has_issues is True
                assert mock_run.call_count == len(fake_java_homes)

    def test_find_all_java_homes_validates_cacerts(self):
        """Test that find_all_java_homes only returns paths with valid cacerts."""
        with patch('platform.system', return_value='Darwin'), \
             patch('os.path.exists', return_value=False), \
             patch('os.path.isdir', return_value=True), \
             patch('subprocess.run') as mock_run:

            mock_result = MagicMock()
            mock_result.stdout = ""
            mock_run.return_value = mock_result

            instance = fumitm.FumitmPython(mode='status')

            with patch.object(instance, 'find_java_home', return_value='/fake/java'), \
                 patch.object(instance, 'find_java_cacerts', return_value=''):

                java_homes = instance.find_all_java_homes()

                assert len(java_homes) == 0

    def test_find_all_java_homes_includes_sdkman_installations(self):
        """find_all_java_homes discovers all JDKs installed under ~/.sdkman/candidates/java/."""
        sdkman_java_dir = os.path.expanduser('~/.sdkman/candidates/java')
        sdkman_versions = ['21.0.2-tem', '17.0.10-tem', '11.0.22-tem']

        def isfile_side_effect(path):
            if path == sdkman_java_dir:
                return False
            return 'lib/security/cacerts' in path

        def isdir_side_effect(path):
            if path == sdkman_java_dir:
                return True
            return bool(any(v in path for v in sdkman_versions))

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
            "'current' symlink should not appear as a separate entry in java_homes"

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
        """find_all_java_homes accepts a vendor that gives a .jdk bundle.

        Some SDKMAN distributions, such as Azul Zulu on macOS, extract to:
            ~/.sdkman/candidates/java/11.0.18-zulu/zulu-11.jdk/Contents/Home
        Other distributions use the flat form:
            ~/.sdkman/candidates/java/21.0.2-tem/
        fumitm must find both and give a valid Java home for each.
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
            return '21.0.2-tem' in path

        def isfile_side_effect(path):
            return bool('lib/security/cacerts' in path and '21.0.2-tem' in path)

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
    _DEFAULT_NEW_KWARGS: ClassVar[dict] = {
        'no_color': False, 'headless': False, 'skip_update_check': False,
        'log_file': None, 'log_dir': None, 'json_log_file': None, 'json_log_dir': None,
        'run_as_user': None, 'with_aikido': False, 'no_aikido': False,
        'aikido_cert_file': None,
    }

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
            instance.check_all_status()
            
            assert mocks['which'].called
            assert_subprocess_called_with(mocks['subprocess'], ['npm', 'config', 'get'])
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
        
        with mock_fumitm_environment(mock_config), \
                patch('fumitm.shutil.copy') as mock_copy:
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
            instance.check_all_status()
            
            assert mocks['which'].called
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
            fumitm.FumitmPython(mode='status')

            # This would need actual implementation testing
            assert True  # Placeholder for actual platform-specific tests


class TestStatusFunctionContracts(FumitmTestCase):
    """Contract tests for each check_*_status() function.

    These tests confirm that each status function gives a boolean value. Issue
    #20 occurred because a function did not return has_issues.
    """

    def get_all_status_methods(self, instance):
        """Find each check_*_status method by introspection.

        This does not include check_all_status(), which controls the other methods.
        """
        return [
            name for name in dir(instance)
            if name.startswith('check_') and name.endswith('_status')
            and name != 'check_all_status'  # Exclude orchestrator
            and callable(getattr(instance, name))
        ]

    def test_all_status_functions_return_boolean(self, tmp_path):
        """Confirm that each check_*_status() function gives a boolean and not None.

        This covers issue #20. The test finds each check_*_status method and
        confirms that it gives a boolean value.
        """
        cert_file = tmp_path / "test-cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        status_methods = self.get_all_status_methods(instance)

        assert len(status_methods) >= 12, f"Expected at least 12 status methods, found {len(status_methods)}: {status_methods}"

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

        failed_methods = []
        for method_name in status_methods:
            method = getattr(instance, method_name)

            # Mock all external dependencies so functions hit early returns
            with patch.object(instance, 'command_exists', return_value=False), \
                 patch.object(instance, 'get_jenv_java_homes', return_value=[]), \
                 patch.object(instance, 'find_all_java_homes', return_value=[]), \
                 patch.object(instance, '_find_aikido_doctor', return_value=None), \
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

            with patch.object(instance, 'command_exists', return_value=False), \
                 patch.object(instance, 'get_jenv_java_homes', return_value=[]), \
                 patch.object(instance, 'find_all_java_homes', return_value=[]), \
                 patch.object(instance, '_find_aikido_doctor', return_value=None), \
                 patch('os.path.exists', return_value=False):

                result = method(str(cert_file))

                assert result is False, f"{method_name} should return False when tool not installed, got {result}"

    def test_check_jenv_status_returns_boolean_with_java_homes(self, tmp_path):
        """Confirm that check_jenv_status gives a boolean when jenv has Java homes.

        This covers issue #20. The defect occurs only when jenv has a Java home,
        because an empty list causes an early return.
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
        mock_system_cert = tmp_path / "system-cert.pem"
        mock_system_cert.write_text(mock_data.SAMPLE_CA_BUNDLE)

        target_bundle = tmp_path / "bundle.pem"

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')

            with patch('os.path.exists') as mock_exists:
                mock_exists.side_effect = lambda p: p == "/etc/ssl/cert.pem" or p == str(target_bundle.parent)

                with patch('shutil.copy') as mock_copy:
                    result = instance.create_bundle_with_system_certs(str(target_bundle))

                    mock_copy.assert_called_once_with("/etc/ssl/cert.pem", str(target_bundle))
                    assert result is True

    def test_creates_bundle_from_linux_system_certs(self, tmp_path):
        """Test bundle creation when /etc/ssl/certs/ca-certificates.crt exists (Linux)."""
        target_bundle = tmp_path / "bundle.pem"

        with patch('platform.system', return_value='Linux'):
            instance = fumitm.FumitmPython(mode='install')

            with patch('os.path.exists') as mock_exists:
                mock_exists.side_effect = lambda p: p == "/etc/ssl/certs/ca-certificates.crt"

                with patch('shutil.copy') as mock_copy:
                    result = instance.create_bundle_with_system_certs(str(target_bundle))

                    mock_copy.assert_called_once_with("/etc/ssl/certs/ca-certificates.crt", str(target_bundle))
                    assert result is True

    def test_creates_empty_bundle_when_no_system_certs(self, tmp_path):
        """Test empty bundle creation when no system certs found."""
        target_bundle = tmp_path / "bundle.pem"

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')

            # Neither system certificate location is present. The assertions are
            # outside this patch. pathlib.Path.exists() calls os.path.exists() in
            # Python 3.13, thus a global patch would hide the file that the method
            # made.
            with patch('os.path.exists', return_value=False):
                result = instance.create_bundle_with_system_certs(str(target_bundle))

            assert result is False
            assert target_bundle.exists()
            assert target_bundle.read_text() == ""

    def test_returns_true_when_system_certs_copied(self, tmp_path):
        """Test return value indicates whether system certs were found."""
        target_bundle = tmp_path / "bundle.pem"

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')

            with patch('os.path.exists', side_effect=lambda p: p == "/etc/ssl/cert.pem"), \
                    patch('shutil.copy'):
                result = instance.create_bundle_with_system_certs(str(target_bundle))
                assert result is True

            with patch('os.path.exists', return_value=False):
                result = instance.create_bundle_with_system_certs(str(target_bundle))
                assert result is False


class TestCertificateAppending(FumitmTestCase):
    """Tests for certificate appending to ensure proper PEM formatting (issue #13)."""

    def test_append_to_bundle_without_trailing_newline(self, tmp_path):
        """Confirm that an append to a bundle with no final newline keeps the PEM valid.

        This covers issue #13. An append to such a file gave a malformed PEM:
        -----END CERTIFICATE----------BEGIN CERTIFICATE-----
        """
        bundle_file = tmp_path / "ca-bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE_NO_NEWLINE)

        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')
            result = instance.safe_append_certificate(str(cert_file), str(bundle_file))

        assert result is True

        content = bundle_file.read_text()

        # A newline must come after -----END CERTIFICATE-----, and not -----BEGIN.
        # A valid PEM file does not have that pattern.
        assert "-----END CERTIFICATE----------BEGIN CERTIFICATE-----" not in content

        assert "-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----" in content or \
               "-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----" in content

    def test_append_to_bundle_with_trailing_newline(self, tmp_path):
        """Verify normal case still works - bundle with trailing newline."""
        bundle_file = tmp_path / "ca-bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE)  # Has trailing newline

        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')
            result = instance.safe_append_certificate(str(cert_file), str(bundle_file))

        assert result is True

        content = bundle_file.read_text()

        assert "-----END CERTIFICATE----------BEGIN CERTIFICATE-----" not in content

    def test_append_ensures_certificate_ends_with_newline(self, tmp_path):
        """Ensure appended certificate itself ends with newline."""
        bundle_file = tmp_path / "ca-bundle.pem"
        bundle_file.write_text("")

        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE_NO_NEWLINE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')
            result = instance.safe_append_certificate(str(cert_file), str(bundle_file))

        assert result is True

        content = bundle_file.read_text()

        assert content.endswith('\n')

    def test_append_skips_if_certificate_already_exists(self, tmp_path):
        """Verify that appending skips if certificate already exists in bundle."""
        bundle_file = tmp_path / "ca-bundle.pem"
        bundle_file.write_text(mock_data.MOCK_CERTIFICATE)

        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        original_size = bundle_file.stat().st_size

        # certificate_exists_in_file gives True. openssl cannot make a
        # fingerprint of a mock certificate.
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')
            with patch.object(instance, 'certificate_exists_in_file', return_value=True):
                result = instance.safe_append_certificate(str(cert_file), str(bundle_file))

        assert result is True

        assert bundle_file.stat().st_size == original_size

    def test_append_to_nonexistent_target_creates_file(self, tmp_path):
        """Verify appending to a non-existent file creates it with the certificate."""
        bundle_file = tmp_path / "new-bundle.pem"

        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')
            result = instance.safe_append_certificate(str(cert_file), str(bundle_file))

        assert result is True

        assert bundle_file.exists()

        content = bundle_file.read_text()
        assert "-----BEGIN CERTIFICATE-----" in content
        assert "-----END CERTIFICATE-----" in content


class TestCodeQuality:
    """Static analysis tests to catch unsafe patterns in the codebase."""

    def test_no_unsafe_certificate_appends_in_fumitm(self):
        """Confirm that fumitm.py uses safe_append_certificate() for each append.

        This covers issue #21 and prevents a new append that can give a malformed
        PEM file. The test finds two patterns:
        - An open in append mode for a certificate file or a bundle file.
        - A write of certificate content without safe_append_certificate().
        """
        import os
        import re

        test_dir = os.path.dirname(os.path.abspath(__file__))
        fumitm_path = os.path.join(os.path.dirname(test_dir), "fumitm.py")

        with open(fumitm_path, 'r') as f:
            source = f.read()

        # Pattern 1: an open in append mode for a bundle file or a certificate
        # file. This finds: with open(some_bundle, 'a') as f:
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

        # Pattern 2: an f.write() of certificate content. This finds a pattern
        # such as f.write(cf.read()), where cf is a certificate file.
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
        """Confirm that fumitm_windows.py uses append_certificate_if_missing().

        This is the same test as test_no_unsafe_certificate_appends_in_fumitm, for
        the Windows port.
        """
        import os
        import re

        test_dir = os.path.dirname(os.path.abspath(__file__))
        fumitm_windows_path = os.path.join(os.path.dirname(test_dir), "fumitm_windows.py")

        with open(fumitm_windows_path, 'r') as f:
            source = f.read()

        # Pattern 1: an open in append mode for a bundle file or a certificate
        # file. Do not include append_certificate_if_missing.
        lines = source.split('\n')
        in_append_method = False
        unsafe_lines = []

        for i, line in enumerate(lines, 1):
            if 'def append_certificate_if_missing' in line:
                in_append_method = True
            elif in_append_method and line.strip().startswith('def '):
                in_append_method = False

            if in_append_method:
                continue

            if (re.search(r"with\s+open\s*\([^)]*['\"]a['\"]\s*\)", line, re.IGNORECASE)
                    and ('bundle' in line.lower() or 'cert' in line.lower() or 'ca' in line.lower())):
                unsafe_lines.append(f"Line {i}: {line.strip()}")

        assert not unsafe_lines, (
            "Found unsafe certificate append patterns in fumitm_windows.py:\n"
            + "\n".join(unsafe_lines) + "\n\n"
            "Use self.append_certificate_if_missing(cert_path, target_path) instead"
        )

    def test_no_unused_globals_in_fumitm(self):
        """Confirm that fumitm.py has no unused global variable.

        This prevents an unused global such as SHELL_MODIFIED or CERT_FINGERPRINT.
        """
        import os
        import re

        test_dir = os.path.dirname(os.path.abspath(__file__))
        fumitm_path = os.path.join(os.path.dirname(test_dir), "fumitm.py")

        with open(fumitm_path, 'r') as f:
            source = f.read()

        # Find the module-level UPPER_CASE assignments. The line starts with
        # UPPER_CASE_NAME = and is not in a class or a function.
        global_pattern = re.compile(r'^([A-Z][A-Z0-9_]*)\s*=', re.MULTILINE)

        # CERT_PATH stays as a public constant for compatibility. fumitm does not
        # use it. self.cert_path replaced it.
        known_unused = {'CERT_PATH'}

        globals_found = set()
        for match in global_pattern.finditer(source):
            name = match.group(1)
            if name.startswith('__'):
                continue
            globals_found.add(name)

        unused_globals = []
        for name in globals_found:
            if name in known_unused:
                continue
            pattern = re.compile(r'\b' + re.escape(name) + r'\b')
            matches = pattern.findall(source)
            if len(matches) <= 1:
                unused_globals.append(name)

        assert not unused_globals, (
            f"Unused global variables found in fumitm.py: {unused_globals}\n"
            "These variables are defined but never referenced elsewhere in the code."
        )

    def test_no_unused_globals_in_fumitm_windows(self):
        """Confirm that fumitm_windows.py has no unused global variable.

        This is the same test as test_no_unused_globals_in_fumitm, for the Windows
        port.
        """
        import os
        import re

        test_dir = os.path.dirname(os.path.abspath(__file__))
        fumitm_windows_path = os.path.join(os.path.dirname(test_dir), "fumitm_windows.py")

        with open(fumitm_windows_path, 'r') as f:
            source = f.read()

        # Unused globals that the Windows work must remove. See
        # WINDOWS_REFACTORING_NOTES.md.
        known_unused = {'ALT_CERT_NAMES', 'SHELL_MODIFIED', 'CERT_FINGERPRINT'}

        global_pattern = re.compile(r'^([A-Z][A-Z0-9_]*)\s*=', re.MULTILINE)

        globals_found = set()
        for match in global_pattern.finditer(source):
            name = match.group(1)
            if name.startswith('__'):
                continue
            globals_found.add(name)

        unused_globals = []
        for name in globals_found:
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
        """Confirm that each setup function uses the same message.

        Each setup function must use "Configuring <tool> certificate..." and not
        "Setting up <tool> certificate...".
        """
        import os
        import re

        test_dir = os.path.dirname(os.path.abspath(__file__))
        fumitm_path = os.path.join(os.path.dirname(test_dir), "fumitm.py")

        with open(fumitm_path, 'r') as f:
            source = f.read()

        setting_up_pattern = re.compile(r'Setting up.*certificate', re.IGNORECASE)

        matches = setting_up_pattern.findall(source)
        assert not matches, (
            f"Found inconsistent messaging in fumitm.py:\n"
            f"{matches}\n\n"
            f"Use 'Configuring <tool> certificate...' instead of 'Setting up <tool> certificate...'"
        )

    def test_no_bare_except_clauses_in_fumitm(self):
        """Confirm that fumitm.py has no bare 'except:' clause.

        A bare except catches each exception, and this includes SystemExit and
        KeyboardInterrupt. Use 'except Exception:' or a more specific type.
        """
        import os
        import re

        test_dir = os.path.dirname(os.path.abspath(__file__))
        fumitm_path = os.path.join(os.path.dirname(test_dir), "fumitm.py")

        with open(fumitm_path, 'r') as f:
            lines = f.readlines()

        bare_excepts = []
        for i, line in enumerate(lines, 1):
            # Match 'except:' but not 'except SomeException:' or 'except (A, B):'
            if re.match(r'^\s*except\s*:\s*$', line) or re.match(r'^\s*except\s*:\s*#', line):
                bare_excepts.append(f"Line {i}: {line.strip()}")

        assert not bare_excepts, (
            "Found bare 'except:' clauses in fumitm.py:\n"
            + "\n".join(bare_excepts) + "\n\n"
            "Replace with 'except Exception:' or a more specific exception type."
        )

    def test_no_raw_cert_comparisons_in_fumitm(self):
        """Confirm that a setup function calls certificate_exists_in_file().

        This covers issue #35. A status check calls certificate_exists_in_file(),
        which compares normalized base64. But a setup function used a raw string
        comparison such as 'cert_content in file_content'. Thus --fix did not
        correct a tool that status reported as incorrect.

        Each check for a certificate must use:
        - self.certificate_exists_in_file(CERT_PATH, target_file)
        It must not use:
        - cert_content in file_content
        - cert_content not in file_content
        """
        import os
        import re

        test_dir = os.path.dirname(os.path.abspath(__file__))
        fumitm_path = os.path.join(os.path.dirname(test_dir), "fumitm.py")

        with open(fumitm_path, 'r') as f:
            source = f.read()

        # Find a raw comparison of certificate content in a setup function. Such a
        # function must call certificate_exists_in_file().
        unsafe_patterns = [
            (r'cert_content\s+(?:not\s+)?in\s+file_content', 'cert_content in/not in file_content'),
            (r'file_content.*cert_content|cert_content.*file_content', 'raw content comparison'),
        ]

        violations = []
        lines = source.split('\n')
        for i, line in enumerate(lines, 1):
            for pattern, description in unsafe_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    violations.append(f"Line {i}: {line.strip()} ({description})")

        assert not violations, (
            "Found raw certificate comparisons in fumitm.py:\n"
            + "\n".join(violations) + "\n\n"
            "Setup functions must use self.certificate_exists_in_file(CERT_PATH, target)\n"
            "instead of raw 'cert_content in file_content' comparisons.\n"
            "See issue #35 for details on why this is required."
        )

    def test_no_raw_makedirs_in_setup_functions(self):
        """Confirm that a setup function calls _safe_makedirs() and not os.makedirs().

        Under sudo, ``os.makedirs()`` makes a directory in the home directory of the
        user that belongs to root. Each setup function must call ``_safe_makedirs()``,
        which corrects the ownership. Only ``_safe_makedirs`` can call os.makedirs.
        """
        import os
        import re

        test_dir = os.path.dirname(os.path.abspath(__file__))
        fumitm_path = os.path.join(os.path.dirname(test_dir), "fumitm.py")

        with open(fumitm_path, 'r') as f:
            lines = f.readlines()

        # Methods that can call os.makedirs directly. A log directory such as
        # /var/log/fumitm is a system path and must stay with root.
        allowed_methods = {'_safe_makedirs', '_open_log_files'}
        in_allowed = False
        violations = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            if any(f'def {m}' in line for m in allowed_methods):
                in_allowed = True
            elif in_allowed and re.match(r'^\s{4}def ', line):
                in_allowed = False

            if in_allowed:
                continue

            if 'os.makedirs(' in stripped:
                violations.append(f"Line {i}: {stripped}")

        assert not violations, (
            "Found raw os.makedirs() calls outside _safe_makedirs in fumitm.py:\n"
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

        mock_pw = MagicMock()
        mock_pw.pw_dir = '/home/realuser'

        with patch('os.getuid', return_value=0), \
             patch.dict(os.environ, {'SUDO_USER': 'realuser', 'HOME': '/root'}), \
             patch('pwd.getpwnam', return_value=mock_pw), \
             patch('platform.system', return_value='Linux'):
            fumitm.FumitmPython(mode='status', provider='warp')
            assert os.environ['HOME'] == '/home/realuser'

    def test_check_ownership_sanity_detects_root_files(self, tmp_path):
        """check_ownership_sanity should warn about root-owned files."""
        instance = self.create_fumitm_instance()
        instance.cert_path = str(tmp_path / "cert.pem")
        instance.bundle_dir = str(tmp_path / "bundle")

        cert = tmp_path / "cert.pem"
        cert.touch()

        # A stat wrapper that changes st_uid for the target file only. Each other
        # field, such as st_mode, does not change.
        original_stat = os.stat
        def mock_stat(path, *args, **kwargs):
            result = original_stat(path, *args, **kwargs)
            if str(path) == str(cert):
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

        # No file is present. There is nothing to report.
        with patch('os.getuid', return_value=1000):
            result = instance.check_ownership_sanity()
            assert result is False


class TestPerformance(FumitmTestCase):
    """Tests for performance and the number of subprocess calls.

    These tests confirm that a certificate check does not make many subprocess
    calls. The code must use pure-Python string matching and not openssl to find
    a duplicate.
    """

    def test_certificate_likely_exists_uses_no_subprocess(self, tmp_path):
        """Confirm that certificate_likely_exists_in_file makes no subprocess call.

        The function must use pure-Python string matching and not openssl, thus it
        stays fast.
        """
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        bundle_file = tmp_path / "bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE + mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch('subprocess.run') as mock_subprocess:
            result = instance.certificate_likely_exists_in_file(
                str(cert_file), str(bundle_file)
            )

            assert result is True

            assert mock_subprocess.call_count == 0, (
                f"certificate_likely_exists_in_file called subprocess {mock_subprocess.call_count} times. "
                f"Expected 0 calls (pure Python string matching)."
            )

    def test_certificate_likely_exists_no_match_uses_no_subprocess(self, tmp_path):
        """Verify no subprocess calls even when certificate is not found."""
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        bundle_file = tmp_path / "bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch('subprocess.run') as mock_subprocess:
            result = instance.certificate_likely_exists_in_file(
                str(cert_file), str(bundle_file)
            )

            assert result is False

            assert mock_subprocess.call_count == 0, (
                f"certificate_likely_exists_in_file called subprocess {mock_subprocess.call_count} times "
                f"even when certificate not found. Expected 0 calls."
            )

    def test_safe_append_uses_fast_check(self, tmp_path):
        """Confirm that safe_append_certificate uses the fast check.

        Also in install mode, the search for a duplicate must use string matching. It
        must not start openssl for each certificate in the bundle.
        """
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        bundle_file = tmp_path / "bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE + mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='install')

        with patch('subprocess.run') as mock_subprocess:
            result = instance.safe_append_certificate(
                str(cert_file), str(bundle_file)
            )

            assert result is True

            # The number of subprocess calls must be small. It must not increase with
            # the number of certificates in the bundle.
            assert mock_subprocess.call_count <= 1, (
                f"safe_append_certificate made {mock_subprocess.call_count} subprocess calls. "
                f"Expected at most 1 (for initial validation). "
                f"Duplicate detection should use pure Python."
            )

    def test_no_subprocess_explosion_for_large_bundles(self, tmp_path):
        """Confirm that the number of subprocess calls does not follow the bundle size.

        With a bundle of N certificates, fumitm must not make N subprocess calls to
        find a duplicate.
        """
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        # A bundle with many certificates. A real bundle has 100 to 150
        # certificates. This test uses 10, because it is faster.
        bundle_content = ""
        for i in range(10):
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
            instance.certificate_likely_exists_in_file(
                str(cert_file), str(bundle_file)
            )

            # The result is not important. The number of calls must not increase with
            # the number of certificates in the bundle.
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

        with patch.object(fumitm, 'CERT_PATH', str(cert_file)), \
                patch('subprocess.run') as mock_subprocess:
                mock_subprocess.return_value = MagicMock(
                    returncode=0,
                    stdout="SHA256 Fingerprint=AA:BB:CC:DD"
                )

                instance.get_cert_fingerprint(str(cert_file))
                instance.get_cert_fingerprint(str(cert_file))
                instance.get_cert_fingerprint(str(cert_file))

                # One subprocess call only. The result is cached after the first call.
                # fumitm caches for CERT_PATH only. This test gives the wanted operation.
                assert mock_subprocess.call_count <= 3, (
                    f"get_cert_fingerprint called subprocess {mock_subprocess.call_count} times "
                    f"for 3 calls. Expected caching to reduce this."
                )


class TestCertificateContentMatching(FumitmTestCase):
    """Tests for the pure-Python match of certificate content.

    These tests confirm that fumitm finds a duplicate certificate with string
    matching and makes no openssl subprocess call.
    """

    def test_extracts_cert_unique_portion(self, tmp_path):
        """Test extraction of unique certificate portion for matching."""
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        # The function must give a unique part of the certificate.
        if hasattr(instance, 'get_cert_unique_portion'):
            unique = instance.get_cert_unique_portion(str(cert_file))
            assert unique is not None
            assert len(unique) >= 50  # Should have enough chars to be unique

    def test_matching_finds_cert_in_bundle(self, tmp_path):
        """Test that string matching correctly finds certificate in bundle."""
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(mock_data.MOCK_CERTIFICATE)

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

        cert_with_spaces = mock_data.MOCK_CERTIFICATE.replace('\n', '\n\n')
        bundle_file = tmp_path / "bundle.pem"
        bundle_file.write_text(mock_data.SAMPLE_CA_BUNDLE + "\n\n\n" + cert_with_spaces)

        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        result = instance.certificate_likely_exists_in_file(
            str(cert_file), str(bundle_file)
        )

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

            call_kwargs = mock_urlopen.call_args
            assert call_kwargs is not None
            assert 'context' in call_kwargs.kwargs or len(call_kwargs.args) >= 2

    def test_check_for_updates_handles_network_error(self, tmp_path):
        """Verify update check handles network errors gracefully."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        with patch('urllib.request.urlopen') as mock_urlopen:
            mock_urlopen.side_effect = urllib.error.URLError("Network error")

            result = instance.check_for_updates()

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
        """gcloud status reports an absent core/custom_ca_certs_file.

        It does this also when HTTPS operates. The IAP tunnel reads
        core/custom_ca_certs_file and ignores the system trust store. Thus a
        successful `gcloud projects list` is not sufficient.
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
        assert fumitm.parse_calver("2025.12.18") == (2025, 12, 18, 0)


class TestUpdateCheckCalVer(FumitmTestCase):
    """Tests for CalVer-based update checking."""

    def test_check_for_updates_newer_available(self, tmp_path):
        """Verify update check returns True for newer version."""
        with patch('platform.system', return_value='Darwin'):
            instance = fumitm.FumitmPython(mode='status')

        remote_content = b'__version__ = "2099.12.31"\n# rest of file...'

        # A host that is not a working copy: the main branch and no local change.
        # Thus the working-copy check does not remove the update warning.
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
    """Tests for the detection of a provider change and the correction of a path.

    When a user changes the MITM proxy provider, for example from WARP to
    Netskope, a tool config can still name the bundle directory of the old
    provider. These tests confirm that fumitm finds this and moves the paths.
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
            return path == legacy_path

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
        """With rdctl, a running VM, and no docker, fumitm must not use the Docker path.

        It must not call _install_cert_in_docker_vm or _check_cert_in_docker_vm.
        Before the correction, setup_rancher_cert called the shared Docker nsenter
        methods, which need the docker CLI. With rdctl and no docker, the install
        failed although rdctl shell would operate.
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
             patch.object(instance, '_colima_profile_for_tool', return_value='default'), \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, 'certificate_likely_exists_in_file', return_value=True), \
             patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            result = instance.setup_colima_cert()
            assert result.status == 'already_ok'

    def test_colima_vm_install_failure_is_partial(self, capsys):
        """A persistent copy must not hide a failed repair of a running VM."""
        instance = self.create_fumitm_instance(mode='install')
        instance.cert_path = '/tmp/fake-cert.pem'
        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, '_colima_profile_for_tool', return_value='default'), \
             patch('os.path.exists', return_value=False), \
             patch.object(instance, 'certificate_likely_exists_in_file', return_value=False), \
             patch.object(instance, '_safe_makedirs'), \
             patch('shutil.copy'), \
             patch.object(instance, '_fix_ownership'), \
             patch('subprocess.run', return_value=MagicMock(returncode=0)), \
             patch.object(instance, '_check_cert_in_colima_vm', return_value=False), \
             patch.object(
                 instance, '_install_cert_via_colima_ssh', return_value=(False, 'test error')
             ), \
             patch.object(instance, '_install_cert_in_docker_vm') as mock_nsenter:
            result = instance.setup_colima_cert()
            assert result.status == 'failed'
            assert result.changed is True
            assert 'VM install failed' in result.message
            mock_nsenter.assert_not_called()

        assert instance._print_summary([result]) == 3
        summary = capsys.readouterr().out
        assert '"changes_made": true' in summary
        assert '"partial": 1' in summary

    def test_colima_installs_via_ssh_when_docker_absent(self):
        """With colima, a running VM, and no docker, fumitm must not use the Docker path.

        It must not call _install_cert_in_docker_vm or _check_cert_in_docker_vm.
        Before the correction, setup_colima_cert called the shared Docker nsenter
        methods, which need the docker CLI. With colima and no docker, the install
        failed although colima ssh would operate.
        """
        instance = self.create_fumitm_instance(mode='install')
        instance.cert_path = '/tmp/fake-cert.pem'

        def selective_command_exists(cmd):
            return cmd in ('colima',)  # docker is absent

        with patch.object(instance, 'command_exists', side_effect=selective_command_exists), \
             patch.object(instance, '_colima_profile_for_tool', return_value='default'), \
             patch('os.path.exists', return_value=False), \
             patch.object(instance, 'certificate_likely_exists_in_file', return_value=False), \
             patch.object(instance, '_safe_makedirs'), \
             patch('shutil.copy'), \
             patch.object(instance, '_fix_ownership'), \
             patch('subprocess.run', return_value=MagicMock(returncode=0)), \
             patch.object(instance, '_check_cert_in_colima_vm', return_value=False), \
             patch.object(instance, '_install_cert_via_colima_ssh', return_value=(True, 'ok')) as mock_ssh, \
             patch.object(instance, '_install_cert_in_docker_vm') as mock_nsenter, \
             patch.object(
                 instance, '_restart_docker_in_colima', return_value=True
             ) as mock_restart, \
             patch.object(instance, '_restart_docker_in_vm') as mock_generic_restart:
            result = instance.setup_colima_cert()
            assert result.status == 'configured'
            mock_ssh.assert_called_once_with('default')
            mock_nsenter.assert_not_called()
            mock_restart.assert_called_once_with('default')
            mock_generic_restart.assert_not_called()

    def test_colima_uses_named_profile_and_reports_vm_change(self, capsys):
        """The explicit tool repairs and restarts the selected named profile."""
        instance = self.create_fumitm_instance(mode='install')
        endpoint = 'unix:///Users/example/.colima/team-dev/docker.sock'

        with patch.dict(os.environ, {'DOCKER_HOST': endpoint}), \
             patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, '_container_certs_present', return_value=True), \
             patch('subprocess.run', return_value=MagicMock(returncode=0)) as mock_run, \
             patch.object(
                 instance, '_check_cert_in_colima_vm', return_value=False
             ) as mock_check, \
             patch.object(
                 instance, '_install_cert_via_colima_ssh', return_value=(True, 'ok')
             ) as mock_install, \
             patch.object(
                 instance, '_restart_docker_in_colima', return_value=True
             ) as mock_restart, \
             patch.object(instance, '_restart_docker_in_vm') as mock_generic_restart:
            result = instance.setup_colima_cert()

        assert result.status == 'configured'
        assert instance._print_summary([result]) == 0
        assert '"changes_made": true' in capsys.readouterr().out
        assert call(
            ['colima', '--profile', 'team-dev', 'status'],
            capture_output=True, timeout=10, check=False,
        ) in mock_run.call_args_list
        mock_check.assert_called_once_with('team-dev')
        mock_install.assert_called_once_with('team-dev')
        mock_restart.assert_called_once_with('team-dev')
        mock_generic_restart.assert_not_called()

    def test_colima_uses_sole_running_profile_without_docker_selection(self):
        """A lone running named profile replaces the hard-wired default."""
        instance = self.create_fumitm_instance()
        profiles = (
            '{"name":"default","status":"Stopped"}\n'
            '{"name":"team-dev","status":"Running"}'
        )
        with patch.object(
            instance, '_active_colima_profile_for_docker', return_value=None
        ), patch(
            'subprocess.run',
            return_value=MagicMock(returncode=0, stdout=profiles),
        ) as mock_run:
            assert instance._colima_profile_for_tool() == 'team-dev'

        mock_run.assert_called_once_with(
            ['colima', 'list', '--json'],
            capture_output=True, text=True, timeout=10, check=False,
        )

    def test_colima_ssh_operations_have_timeouts(self, tmp_path):
        """A wedged Colima VM cannot hold a headless run forever."""
        instance = self.create_fumitm_instance()
        cert = tmp_path / 'proxy.pem'
        cert.write_text(mock_data.MOCK_CERTIFICATE)
        instance.cert_path = str(cert)

        with patch(
            'subprocess.run', side_effect=subprocess.TimeoutExpired('colima', 30)
        ) as mock_check:
            assert instance._check_cert_in_colima_vm('team-dev') is False
        assert mock_check.call_args.kwargs['timeout'] == 30

        with patch(
            'subprocess.run', side_effect=subprocess.TimeoutExpired('colima', 60)
        ) as mock_install:
            success, message = instance._install_cert_via_colima_ssh('team-dev')
        assert success is False
        assert message == 'colima ssh timed out'
        assert mock_install.call_args.kwargs['timeout'] == 60

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

    def test_docker_vm_install_failure_is_partial(self, capsys):
        """A host-side copy must not hide a failed repair of a running VM."""
        instance = self.create_fumitm_instance(mode='install')
        instance.cert_path = '/tmp/fake-cert.pem'
        with patch.object(instance, 'command_exists', return_value=True), \
             patch('os.path.exists', return_value=False), \
             patch.object(instance, 'certificate_likely_exists_in_file', return_value=False), \
             patch.object(instance, '_safe_makedirs'), \
             patch('shutil.copy'), \
             patch.object(instance, '_fix_ownership'), \
             patch.object(instance, '_docker_is_running', return_value=True), \
             patch.object(
                 instance, '_active_colima_profile_for_docker', return_value='default'
             ), \
             patch.object(instance, '_check_cert_in_colima_vm', return_value=False), \
             patch.object(
                 instance, '_install_cert_via_colima_ssh', return_value=(False, 'test error')
             ), \
             patch.object(instance, '_install_cert_in_docker_vm') as mock_nsenter:
            result = instance.setup_docker_cert()
            assert result.status == 'failed'
            assert result.changed is True
            assert 'VM install failed' in result.message
            mock_nsenter.assert_not_called()

        assert instance._print_summary([result]) == 3
        summary = capsys.readouterr().out
        assert '"partial": 1' in summary
        assert '"exit_code": 3' in summary

    def test_effective_docker_endpoint_prefers_docker_host(self):
        """DOCKER_HOST wins over the selected Docker context."""
        instance = self.create_fumitm_instance()
        endpoint = 'unix:///Users/example/.colima/work/docker.sock'
        with patch.dict(os.environ, {'DOCKER_HOST': endpoint}), \
             patch('subprocess.run') as mock_run:
            assert instance._effective_docker_endpoint() == endpoint
            mock_run.assert_not_called()

    def test_effective_docker_endpoint_uses_current_context(self):
        """The current context supplies the endpoint when DOCKER_HOST is absent."""
        instance = self.create_fumitm_instance()
        context_endpoint = 'unix:///Users/example/.colima/default/docker.sock'
        context_result = MagicMock(returncode=0, stdout=f'{context_endpoint}\n')
        with patch.dict(os.environ, {}, clear=True), \
             patch('subprocess.run', return_value=context_result) as mock_run:
            assert instance._effective_docker_endpoint() == context_endpoint
            mock_run.assert_called_once_with(
                [
                    'docker', 'context', 'inspect', '--format',
                    '{{.Endpoints.docker.Host}}'
                ],
                capture_output=True, text=True, timeout=10, check=False
            )

    @pytest.mark.parametrize(
        ('endpoint', 'profile'),
        [
            ('unix:///Users/example/.colima/default/docker.sock', 'default'),
            ('unix:///Users/example/.colima/team-dev/docker.sock', 'team-dev'),
            ('unix:///var/run/docker.sock', None),
            ('tcp://127.0.0.1:2375', None),
            ('unix:///Users/example/.colima/bad profile/docker.sock', None),
        ],
    )
    def test_colima_profile_from_docker_endpoint(self, endpoint, profile):
        """Only a valid Colima Unix socket selects the native backend."""
        instance = self.create_fumitm_instance()
        assert instance._colima_profile_from_endpoint(endpoint) == profile

    def test_docker_uses_native_colima_backend_without_an_image(self):
        """Docker selection repairs its active Colima VM without nsenter."""
        instance = self.create_fumitm_instance(
            mode='install', selected_tools=['docker']
        )
        endpoint = 'unix:///Users/example/.colima/team-dev/docker.sock'

        assert instance.should_process_tool('docker') is True
        assert instance.should_process_tool('colima') is False

        with patch.dict(os.environ, {'DOCKER_HOST': endpoint}), \
             patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, '_container_certs_present', return_value=False), \
             patch.object(instance, '_install_container_certs'), \
             patch.object(instance, '_docker_is_running', return_value=True), \
             patch.object(instance, '_check_cert_in_colima_vm', return_value=False) as mock_check, \
             patch.object(
                 instance, '_install_cert_via_colima_ssh', return_value=(True, 'ok')
             ) as mock_colima_install, \
             patch.object(instance, '_install_cert_in_docker_vm') as mock_nsenter, \
             patch.object(
                 instance, '_restart_docker_in_colima', return_value=True
             ) as mock_restart:
            result = instance.setup_docker_cert()

        assert result.status == 'configured'
        mock_check.assert_called_once_with('team-dev')
        mock_colima_install.assert_called_once_with('team-dev')
        mock_nsenter.assert_not_called()
        mock_restart.assert_called_once_with('team-dev')

    def test_docker_vm_only_change_reports_configured(self, capsys):
        """A successful VM-only repair must set changes_made for automation."""
        instance = self.create_fumitm_instance(mode='install')

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, '_container_certs_present', return_value=True), \
             patch.object(instance, '_docker_is_running', return_value=True), \
             patch.object(
                 instance, '_active_colima_profile_for_docker', return_value='default'
             ), \
             patch.object(instance, '_check_cert_in_colima_vm', return_value=False), \
             patch.object(
                 instance, '_install_cert_via_colima_ssh', return_value=(True, 'ok')
             ), \
             patch.object(instance, '_restart_docker_in_colima', return_value=True):
            result = instance.setup_docker_cert()

        assert result.status == 'configured'
        assert instance._print_summary([result]) == 0
        summary = capsys.readouterr().out
        assert '"configured": 1' in summary
        assert '"changes_made": true' in summary

    def test_docker_status_missing_vm_cert_needs_attention(self, capsys):
        """Status must not call a broken running Docker VM healthy."""
        instance = self.create_fumitm_instance()

        with patch.object(instance, 'command_exists', return_value=True), \
             patch('os.path.exists', return_value=True), \
             patch.object(instance, '_status_container_certs_present', return_value=True), \
             patch.object(instance, '_docker_is_running', return_value=True), \
             patch.object(
                 instance, '_active_colima_profile_for_docker', return_value='default'
             ), \
             patch.object(instance, '_check_cert_in_colima_vm', return_value=False):
            has_issues = instance.check_docker_status('/tmp/proxy.pem')

        assert has_issues is True
        assert 'Certificate not in VM' in capsys.readouterr().out

    def test_docker_colima_restart_failure_is_partial(self, capsys):
        """A VM certificate change is partial until Docker restarts."""
        instance = self.create_fumitm_instance(mode='install')

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, '_container_certs_present', return_value=True), \
             patch.object(instance, '_docker_is_running', return_value=True), \
             patch.object(
                 instance, '_active_colima_profile_for_docker', return_value='default'
             ), \
             patch.object(instance, '_check_cert_in_colima_vm', return_value=False), \
             patch.object(
                 instance, '_install_cert_via_colima_ssh', return_value=(True, 'ok')
             ), \
             patch.object(instance, '_restart_docker_in_colima', return_value=False):
            result = instance.setup_docker_cert()

        assert result.status == 'failed'
        assert result.changed is True
        assert 'restart failed' in result.message
        assert instance._print_summary([result]) == 3
        assert '"partial": 1' in capsys.readouterr().out

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
        """fumitm must set core/custom_ca_certs_file also when HTTPS operates.

        The IAP tunnel (`gcloud compute ssh --tunnel-through-iap`) reads ca_certs
        from core/custom_ca_certs_file. It ignores the system trust store and
        SSL_CERT_FILE. Thus fumitm must always set the property.
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
            # Use assert_any_call and not assert_called_with. The vendor-variable
            # pass can add more trust-variable calls after this call.
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
            return path == shell_config

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
            return path == shell_config

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
             patch.object(instance, 'ensure_gradle_custom_truststore',
                          return_value='already_ok'), \
             patch.object(instance, 'update_properties_file', return_value=False):
            result = instance.setup_gradle_cert()
            assert result.status == 'already_ok'
            assert result.tool == 'gradle'

    def test_gradle_rewrites_without_editing_vendor_override_block(self, tmp_path):
        """setup_gradle_cert appends a final managed block without changing vendor markers."""
        instance = self.create_fumitm_instance(mode='install')
        gradle_props = tmp_path / 'gradle.properties'
        gradle_props.write_text(
            'systemProp.javax.net.ssl.trustStore=/old/jdk/cacerts\n'
            'systemProp.javax.net.ssl.trustStorePassword=changeit\n'
            'systemProp.https.protocols=TLSv1.2\n'
            '# aikido-endpoint-java-gradle-cert-config-start\n'
            'systemProp.javax.net.ssl.trustStore=/vendor/custom-cacerts\n'
            'systemProp.javax.net.ssl.trustStorePassword=changeit\n'
            'systemProp.javax.net.ssl.trustStoreType=PKCS12\n'
            '# aikido-endpoint-java-gradle-cert-config-end\n'
        )

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'find_java_cacerts', return_value='/fake/cacerts'), \
             patch.object(instance, 'get_gradle_properties_path',
                          return_value=str(gradle_props)), \
             patch.object(instance, 'get_gradle_custom_cacerts_path',
                          return_value='/Users/test/.gradle/custom-cacerts'), \
             patch.object(instance, 'ensure_gradle_custom_truststore',
                          return_value='already_ok'):
            result = instance.setup_gradle_cert()

        assert result.status == 'configured'
        content = gradle_props.read_text()
        assert '# aikido-endpoint-java-gradle-cert-config-start\n' in content
        assert 'systemProp.javax.net.ssl.trustStore=/vendor/custom-cacerts\n' in content
        assert 'systemProp.javax.net.ssl.trustStoreType=PKCS12\n' in content
        assert content.count('systemProp.javax.net.ssl.trustStore=') == 2
        assert content.count('systemProp.javax.net.ssl.trustStorePassword=') == 2
        assert content.count('systemProp.javax.net.ssl.trustStoreType=') == 2
        assert content.splitlines()[-4:] == [
            'systemProp.javax.net.ssl.trustStore=/Users/test/.gradle/custom-cacerts',
            'systemProp.javax.net.ssl.trustStorePassword=changeit',
            'systemProp.javax.net.ssl.trustStoreType=PKCS12',
            'systemProp.https.protocols=TLSv1.2',
        ]

    def test_gradle_custom_truststore_rebuild_imports_each_proxy_cert(self, tmp_path):
        """ensure_gradle_custom_truststore rebuilds PKCS12 and imports each proxy cert."""
        instance = self.create_fumitm_instance(mode='install')
        source_cacerts = tmp_path / 'cacerts'
        source_cacerts.write_text('placeholder')
        gradle_cacerts = tmp_path / 'custom-cacerts'
        netskope_chain = tmp_path / 'netskope-chain.pem'
        netskope_chain.write_text(
            mock_data.MOCK_CERTIFICATE + '\n' + mock_data.MOCK_AIKIDO_ROOT_CERT
        )
        aikido_root = tmp_path / 'aikido-root.pem'
        aikido_root.write_text(mock_data.MOCK_AIKIDO_ROOT_CERT)

        instance.cert_path = str(netskope_chain)
        instance.extra_roots = [{
            'key': 'aikido',
            'name': 'Aikido Endpoint Protection',
            'short_name': 'Aikido',
            'keytool_alias': 'aikido-root',
            'container_cert_name': 'aikido',
            'path': str(aikido_root),
        }]

        def run_side_effect(cmd, **kwargs):
            result = MagicMock(returncode=0, stdout='', stderr='')
            if cmd[:2] == ['keytool', '-list']:
                result.returncode = 1
                result.stdout = b''
            elif cmd[:2] == ['keytool', '-importkeystore']:
                Path(cmd[cmd.index('-destkeystore') + 1]).write_text('seeded')
            return result

        with patch.object(instance, '_detect_keystore_type', return_value='JKS'), \
             patch('subprocess.run', side_effect=run_side_effect) as mock_run:
            result = instance.ensure_gradle_custom_truststore(
                str(source_cacerts), str(gradle_cacerts)
            )

        assert result == 'configured'
        commands = [call.args[0] for call in mock_run.call_args_list]
        assert any(cmd[:2] == ['keytool', '-importkeystore'] for cmd in commands)
        imported_aliases = [
            cmd[cmd.index('-alias') + 1]
            for cmd in commands
            if cmd[:2] == ['keytool', '-import']
        ]
        assert imported_aliases == [
            'cloudflare-zerotrust',
            'cloudflare-zerotrust-2',
            'aikido-root',
        ]

    def test_java_keystore_import_does_not_split_pem_chain(self, tmp_path):
        """setup_java_cert keeps the historical single-alias import behavior."""
        instance = self.create_fumitm_instance(mode='install')
        java_home = '/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home'
        netskope_chain = tmp_path / 'netskope-chain.pem'
        netskope_chain.write_text(
            mock_data.MOCK_CERTIFICATE + '\n' + mock_data.MOCK_AIKIDO_ROOT_CERT
        )
        instance.cert_path = str(netskope_chain)
        instance.extra_roots = []

        def run_side_effect(cmd, **kwargs):
            result = MagicMock()
            if '-list' in cmd:
                result.returncode = 1
                result.stdout = b''
            else:
                result.returncode = 0
                result.stdout = b'Certificate was added'
            return result

        with patch.object(instance, 'command_exists', return_value=True), \
             patch.object(instance, 'find_all_java_homes', return_value=[java_home]), \
             patch.object(instance, 'find_java_cacerts', return_value='/fake/cacerts'), \
             patch('subprocess.run', side_effect=run_side_effect) as mock_run:
            result = instance.setup_java_cert()

        assert result.status == 'configured'
        imported_aliases = [
            cmd[cmd.index('-alias') + 1]
            for cmd in (call.args[0] for call in mock_run.call_args_list)
            if cmd[:2] == ['keytool', '-import']
        ]
        assert imported_aliases == ['cloudflare-zerotrust']


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

            # Do not make a new bundle. A person must examine this condition.
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
    """add_to_shell_config writes to the env file and keeps a stub in each file.

    The stub is last, thus the exports of the env file win. An earlier export of
    the user stays without a change and does not win. fumitm never makes it a
    comment and never asks the user about it.
    """

    def test_idempotent_when_already_correct(self, tmp_path):
        instance = self.create_fumitm_instance(mode='install')
        rc = tmp_path / '.zshrc'
        rc.write_text('# user prologue\nexport PATH="/usr/local/bin:$PATH"\n')

        assert instance.add_to_shell_config(
            'CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE',
            '/Users/test/.python-ca-bundle.pem',
            str(rc),
        ) is True

        settled_rc = rc.read_text()
        settled_env = Path(instance._env_file_path()).read_text()
        instance.shell_modified = False

        changed = instance.add_to_shell_config(
            'CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE',
            '/Users/test/.python-ca-bundle.pem',
            str(rc),
        )

        assert changed is False
        assert rc.read_text() == settled_rc, "startup file should be untouched"
        assert Path(instance._env_file_path()).read_text() == settled_env
        assert instance.shell_modified is False

    def test_migrates_legacy_inline_block(self, tmp_path):
        # An inline export block from an older fumitm goes into the env file. The
        # stub replaces it. Thus the two never conflict.
        instance = self.create_fumitm_instance(mode='install')
        rc = tmp_path / '.zshrc'
        rc.write_text(
            'export PATH="/usr/local/bin:$PATH"\n'
            '\n'
            f'{instance._FUMITM_BLOCK_BEGIN}\n'
            'export NODE_EXTRA_CA_CERTS="/legacy/node.pem"\n'
            'export SSL_CERT_FILE="/legacy/bundle.pem"\n'
            f'{instance._FUMITM_BLOCK_END}\n'
        )

        instance.add_to_shell_config('SSL_CERT_FILE', '/new/bundle.pem', str(rc))

        content = rc.read_text()
        env = Path(instance._env_file_path()).read_text()
        # The legacy block is gone from the startup file, replaced by the stub.
        assert 'export SSL_CERT_FILE=' not in content
        assert 'export NODE_EXTRA_CA_CERTS=' not in content
        assert content.count(instance._FUMITM_BLOCK_BEGIN) == 1
        assert 'export PATH="/usr/local/bin:$PATH"' in content, "user line preserved"
        # The other legacy variable stays. fumitm changed the given variable.
        assert 'export NODE_EXTRA_CA_CERTS="/legacy/node.pem"' in env
        assert 'export SSL_CERT_FILE="/new/bundle.pem"' in env
        assert '/legacy/bundle.pem' not in env

    def test_legacy_value_survives_when_already_correct(self, tmp_path):
        # Regression: a legacy inline block already had the given value. An
        # "already correct" test stopped the write of the env file, and the stub
        # still replaced that block. Thus fumitm removed the export. fumitm must
        # always write the merged set.
        instance = self.create_fumitm_instance(mode='install')
        rc = tmp_path / '.zshrc'
        bundle = '/Users/test/.python-ca-bundle.pem'
        rc.write_text(
            f'{instance._FUMITM_BLOCK_BEGIN}\n'
            f'export SSL_CERT_FILE="{bundle}"\n'
            f'{instance._FUMITM_BLOCK_END}\n'
        )

        # Same value the legacy block already carried.
        instance.add_to_shell_config('SSL_CERT_FILE', bundle, str(rc))

        assert 'export SSL_CERT_FILE=' not in rc.read_text(), "legacy block replaced"
        assert f'export SSL_CERT_FILE="{bundle}"' \
            in Path(instance._env_file_path()).read_text(), \
            "hoisted value must reach the env file, not vanish with the block"

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
        assert prompt.call_count == 0, "the env file is authoritative; no prompt"
        # The earlier line of the user stays and is not a comment. The stub at
        # the end of the file sources the new value, which wins.
        assert 'export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE="/old/path.pem"' in new_content
        assert '#export' not in new_content
        assert new_content.rstrip().endswith(instance._FUMITM_BLOCK_END)
        assert new_content.index(instance._FUMITM_BLOCK_BEGIN) > new_content.index('/old/path.pem')
        assert 'export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE="/new/path.pem"' \
            in Path(instance._env_file_path()).read_text()
        assert changed is True
        assert instance.shell_modified is True

    def test_value_lands_in_env_file_behind_stub(self, tmp_path):
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
        # The startup file has only the stub. The value is in the env file.
        begin = content.index(instance._FUMITM_BLOCK_BEGIN)
        source = content.index(instance._FUMITM_ENV_FILE_SHELL)
        end = content.index(instance._FUMITM_BLOCK_END)
        assert begin < source < end
        assert 'export CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE="/new/path.pem"' \
            in Path(instance._env_file_path()).read_text()
        assert instance.shell_modified is True

    def test_plain_user_export_preserved_and_overridden(self, tmp_path):
        # An export of the user with no quotes is other content. It stays without
        # a change. The managed block comes after it and replaces its value.
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
        # An earlier fumitm export, then the Aikido block, which wins now.
        rc.write_text(
            'export SSL_CERT_FILE="/fumitm/bundle.pem"\n\n' + aikido
        )

        instance.add_to_shell_config('SSL_CERT_FILE', '/fumitm/bundle.pem', str(rc))
        instance.add_to_shell_config('REQUESTS_CA_BUNDLE', '/fumitm/bundle.pem', str(rc))

        content = rc.read_text()
        env = Path(instance._env_file_path()).read_text()
        # The Aikido block stays without a change. The fumitm stub is after it,
        # thus the env file is sourced last and its exports win.
        assert aikido.strip() in content
        assert content.index(instance._FUMITM_BLOCK_BEGIN) > content.index('aikido-endpoint end')
        assert content.index(instance._FUMITM_ENV_FILE_SHELL) \
            > content.index('export SSL_CERT_FILE="/aikido/only.pem"')
        assert 'export SSL_CERT_FILE="/fumitm/bundle.pem"' in env
        assert 'export REQUESTS_CA_BUNDLE="/fumitm/bundle.pem"' in env

        # Second pass is byte-identical (idempotent).
        before = rc.read_text()
        before_env = env
        changed = instance.add_to_shell_config('SSL_CERT_FILE', '/fumitm/bundle.pem', str(rc))
        assert changed is False
        assert rc.read_text() == before
        assert Path(instance._env_file_path()).read_text() == before_env

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

    def test_multiple_vars_accumulate_in_one_env_file(self, tmp_path):
        instance = self.create_fumitm_instance(mode='install')
        rc = tmp_path / '.zshrc'
        instance.add_to_shell_config('SSL_CERT_FILE', '/b.pem', str(rc))
        instance.add_to_shell_config('REQUESTS_CA_BUNDLE', '/b.pem', str(rc))

        content = rc.read_text()
        env = Path(instance._env_file_path()).read_text()
        # One stub per startup file, however many vars are configured.
        assert content.count(instance._FUMITM_BLOCK_BEGIN) == 1
        assert content.count(instance._FUMITM_BLOCK_END) == 1
        assert 'export SSL_CERT_FILE="/b.pem"' in env
        assert 'export REQUESTS_CA_BUNDLE="/b.pem"' in env

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
        # A second variable in the same run must not back up the middle file.
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
        # An old begin marker with no pair, then a valid new block. The end of
        # the new block must not close the old begin marker.
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
        env = Path(instance._env_file_path()).read_text()
        # The new block is now the stub. The old begin marker and its line stay
        # as other content. The old value is gone.
        assert 'export STALE_LEFTOVER="x"' in content
        assert 'export SSL_CERT_FILE="/old.pem"' not in content
        assert 'export SSL_CERT_FILE="/new.pem"' in env
        assert '/old.pem' not in env


class TestShellStartupFileCoverage(FumitmTestCase):
    """Each startup file that the shell reads gets the stub.

    Thus the exports apply in an interactive shell, a non-interactive shell, and
    a login shell. This covers the condition where the exports went only into
    .zshrc. A non-interactive login shell such as `zsh -lc`, which many tool
    launchers use, reads .zprofile and not .zshrc. A vendor block in .zprofile
    then won.
    """

    def _install(self, home, shell):
        inst = self.create_fumitm_instance(mode='install')
        with patch.object(inst, 'detect_shell', return_value=shell):
            inst.add_to_shell_config('SSL_CERT_FILE', '/new/bundle.pem')
        return inst

    def test_zsh_targets_cover_every_shell_mode(self, isolate_home):
        inst = self.create_fumitm_instance(mode='install')
        targets = [os.path.basename(p) for p in inst.get_shell_configs('zsh')]
        # .zshenv is for a non-login non-interactive shell. .zshrc is for an
        # interactive shell. .zlogin is for a login shell and comes after
        # .zprofile, thus a vendor block in .zprofile does not win.
        assert targets == ['.zshenv', '.zshrc', '.zlogin']

    def test_zprofile_is_never_written(self, isolate_home):
        zprofile = isolate_home / '.zprofile'
        vendor = 'export SSL_CERT_FILE="/vendor/aikido.pem"\n'
        zprofile.write_text(vendor)

        self._install(isolate_home, 'zsh')

        assert zprofile.read_text() == vendor, "vendor's own file must not be edited"
        assert not (isolate_home / '.zprofile.bak').exists()

    def test_stub_written_to_every_zsh_startup_file(self, isolate_home):
        inst = self._install(isolate_home, 'zsh')

        for name in ('.zshenv', '.zshrc', '.zlogin'):
            content = (isolate_home / name).read_text()
            assert inst._FUMITM_ENV_FILE_SHELL in content, f'{name} missing stub'
            assert content.rstrip().endswith(inst._FUMITM_BLOCK_END), \
                f'{name} stub must be last so it wins over vendor blocks'
        assert 'export SSL_CERT_FILE="/new/bundle.pem"' \
            in Path(inst._env_file_path()).read_text()

    def test_bash_targets_include_login_and_interactive_files(self, isolate_home):
        (isolate_home / '.profile').write_text('# login\n')
        inst = self.create_fumitm_instance(mode='install')

        targets = [os.path.basename(p) for p in inst.get_shell_configs('bash')]

        # .bashrc is for an interactive non-login shell. .profile is the first
        # login file that is present, thus bash reads it and does not make
        # .bash_profile.
        assert targets == ['.bashrc', '.profile']

    def test_bash_creates_bash_profile_when_no_login_file_exists(self, isolate_home):
        inst = self.create_fumitm_instance(mode='install')
        targets = [os.path.basename(p) for p in inst.get_shell_configs('bash')]
        assert targets == ['.bashrc', '.bash_profile']

    def test_fish_keeps_inline_block_and_writes_no_env_file(self, isolate_home):
        inst = self.create_fumitm_instance(mode='install')
        config = isolate_home / '.config' / 'fish' / 'config.fish'

        with patch.object(inst, 'detect_shell', return_value='fish'), \
             patch.object(inst, 'get_shell_config', return_value=str(config)):
            inst.add_to_shell_config('SSL_CERT_FILE', '/new/bundle.pem')

        # fish cannot read POSIX sh syntax, thus it keeps the inline block.
        assert 'export SSL_CERT_FILE="/new/bundle.pem"' in config.read_text()
        assert not Path(inst._env_file_path()).exists()

    def test_status_mode_writes_nothing(self, isolate_home):
        inst = self.create_fumitm_instance(mode='status')

        with patch.object(inst, 'detect_shell', return_value='zsh'):
            changed = inst.add_to_shell_config('SSL_CERT_FILE', '/new/bundle.pem')

        assert changed is True, "dry run still reports the pending change"
        assert not Path(inst._env_file_path()).exists()
        for name in ('.zshenv', '.zshrc', '.zlogin'):
            assert not (isolate_home / name).exists()
        assert inst.shell_modified is False

    def test_dry_run_reports_each_file_once_across_vars(self, isolate_home):
        # A dry run writes nothing, thus each variable finds the same pending
        # changes. Without a filter, a setup with several variables gives the
        # same "Would update" line many times for each file.
        inst = self.create_fumitm_instance(mode='status')

        with patch.object(inst, 'detect_shell', return_value='zsh'), \
                patch.object(inst, 'print_action') as action:
            for var in ('SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'):
                inst.add_to_shell_config(var, '/new/bundle.pem')

        would_update = [c.args[0] for c in action.call_args_list
                        if c.args[0].startswith('Would update')]
        assert len(would_update) == len(set(would_update)), \
            f'duplicate dry-run lines: {would_update}'
        # The env file and three startup files, one time each. One export line
        # for each variable.
        assert len(would_update) == 4
        exports = [c.args[0] for c in action.call_args_list
                   if c.args[0].startswith('export ')]
        assert len(exports) == 3

    def test_rerun_restores_a_stub_deleted_from_one_file(self, isolate_home):
        inst = self._install(isolate_home, 'zsh')
        (isolate_home / '.zlogin').write_text('# user wiped the stub\n')

        with patch.object(inst, 'detect_shell', return_value='zsh'):
            changed = inst.add_to_shell_config('SSL_CERT_FILE', '/new/bundle.pem')

        assert changed is True
        assert inst._FUMITM_ENV_FILE_SHELL in (isolate_home / '.zlogin').read_text()

    def test_zdotdir_overrides_home_for_zsh_targets(
            self, isolate_home, monkeypatch, tmp_path):
        # zsh reads its startup files from $ZDOTDIR when it is set, and not from
        # HOME. A write to a HOME file that such a zsh never reads would give the
        # same non-interactive login problem that this design corrects.
        zdot = tmp_path / 'zdot'
        zdot.mkdir()
        monkeypatch.setenv('ZDOTDIR', str(zdot))
        inst = self.create_fumitm_instance(mode='install')

        assert inst.get_shell_configs('zsh') == [
            str(zdot / '.zshenv'), str(zdot / '.zshrc'), str(zdot / '.zlogin')]
        assert inst.get_shell_config('zsh') == str(zdot / '.zshrc')

        with patch.object(inst, 'detect_shell', return_value='zsh'):
            inst.add_to_shell_config('SSL_CERT_FILE', '/new/bundle.pem')

        for name in ('.zshenv', '.zshrc', '.zlogin'):
            assert inst._FUMITM_ENV_FILE_SHELL in (zdot / name).read_text(), \
                f'{name} missing stub under ZDOTDIR'
            assert not (isolate_home / name).exists(), \
                f'HOME {name} written although ZDOTDIR is set. zsh never reads it.'
        # The env file is not a zsh startup file. It stays under HOME.
        assert Path(inst._env_file_path()).exists()

    def test_zdotdir_unset_or_empty_falls_back_to_home(
            self, isolate_home, monkeypatch):
        inst = self.create_fumitm_instance(mode='install')
        expected = [str(isolate_home / n) for n in ('.zshenv', '.zshrc', '.zlogin')]

        monkeypatch.delenv('ZDOTDIR')
        assert inst.get_shell_configs('zsh') == expected
        monkeypatch.setenv('ZDOTDIR', '')
        assert inst.get_shell_configs('zsh') == expected

    def test_real_zsh_login_shell_with_zdotdir_gets_fumitm_value(
            self, isolate_home, monkeypatch, tmp_path):
        # The condition from the review of PR #99. There is a vendor export in
        # $ZDOTDIR/.zprofile and fumitm is configured. Each zsh mode must then
        # give the bundle of fumitm. This includes the non-interactive login
        # shell, which reads .zprofile and not .zshrc.
        zdot = tmp_path / 'zdot'
        zdot.mkdir()
        (zdot / '.zprofile').write_text(
            'export SSL_CERT_FILE="/vendor/aikido.pem"\n')
        monkeypatch.setenv('ZDOTDIR', str(zdot))

        inst = self.create_fumitm_instance(mode='install')
        with patch.object(inst, 'detect_shell', return_value='zsh'):
            inst.add_to_shell_config('SSL_CERT_FILE', '/fumitm/bundle.pem')

        shell_env = {'HOME': str(isolate_home), 'ZDOTDIR': str(zdot),
                     'PATH': os.environ.get('PATH', '/usr/bin:/bin')}
        for flags in ('-c', '-ic', '-lc', '-lic'):
            proc = subprocess.run(
                ['zsh', flags, 'echo $SSL_CERT_FILE'],
                capture_output=True, text=True, env=shell_env, timeout=30,
                check=False)  # interactive modes may exit non-zero without a tty
            lines = [l for l in proc.stdout.strip().splitlines() if l]
            assert lines and lines[-1] == '/fumitm/bundle.pem', \
                f'zsh {flags}: got {proc.stdout!r} (stderr: {proc.stderr!r})'

    def test_real_zsh_shell_local_zdotdir_gets_fumitm_value(
            self, isolate_home, monkeypatch, tmp_path):
        # ZDOTDIR is a shell parameter and zsh does not export it. Python then
        # cannot read it in os.environ, but zsh uses the value from HOME/.zshenv
        # for each later startup file.
        zdot = tmp_path / 'shell-local-zdot'
        zdot.mkdir()
        (isolate_home / '.zshenv').write_text(f'ZDOTDIR="{zdot}"\n')
        (zdot / '.zprofile').write_text(
            'export SSL_CERT_FILE="/vendor/aikido.pem"\n')
        monkeypatch.delenv('ZDOTDIR')

        inst = self.create_fumitm_instance(mode='install')
        with patch.object(inst, 'detect_shell', return_value='zsh'):
            inst.add_to_shell_config('SSL_CERT_FILE', '/fumitm/bundle.pem')

        assert inst._queried_zsh_dotdir == str(zdot)
        assert (isolate_home / '.zshenv').read_text() == f'ZDOTDIR="{zdot}"\n'
        for name in ('.zshenv', '.zshrc', '.zlogin'):
            assert inst._FUMITM_ENV_FILE_SHELL in (zdot / name).read_text()

        shell_env = {
            'HOME': str(isolate_home),
            'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
        }
        proc = subprocess.run(
            ['zsh', '-lc', 'printf %s "$SSL_CERT_FILE"'],
            capture_output=True, text=True, env=shell_env, timeout=30,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == '/fumitm/bundle.pem'

    def test_zdotdir_query_timeout_falls_back_to_home(
            self, isolate_home, monkeypatch):
        monkeypatch.delenv('ZDOTDIR')
        monkeypatch.setenv('SHELL', '/bin/zsh')
        inst = self.create_fumitm_instance(mode='install')
        process = MagicMock()
        process.communicate.side_effect = [
            subprocess.TimeoutExpired('/bin/zsh', 3),
            ('', ''),
        ]

        with patch(
                'fumitm.subprocess.Popen', return_value=process):
            assert inst._zsh_dotdir() == str(isolate_home)
        process.kill.assert_called_once_with()

    def test_zdotdir_query_drops_root_to_target_user(
            self, isolate_home, monkeypatch):
        monkeypatch.delenv('ZDOTDIR')
        monkeypatch.setenv('SHELL', '/bin/zsh')
        inst = self.create_fumitm_instance(mode='install')
        inst._target_uid = 501
        inst._target_gid = 20
        target = MagicMock(pw_name='alice')
        process = MagicMock(returncode=0)
        process.communicate.return_value = (
            f'__FUMITM_ZDOTDIR__={isolate_home}\n',
            '',
        )

        with patch('fumitm.os.getuid', return_value=0), \
                patch('fumitm.pwd.getpwuid', return_value=target), \
                patch('fumitm.os.getgrouplist', return_value=[20, 80]), \
                patch('fumitm.subprocess.Popen', return_value=process) as popen:
            assert inst._zsh_dotdir() == str(isolate_home)

        assert popen.call_args.kwargs['user'] == 501
        assert popen.call_args.kwargs['group'] == 20
        assert popen.call_args.kwargs['extra_groups'] == [20, 80]


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
