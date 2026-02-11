"""
Test helpers and utilities for fumitm tests.

This module provides helper classes and functions to simplify test setup and assertions.
"""
from unittest.mock import MagicMock, patch, mock_open
from pathlib import Path
from contextlib import contextmanager
import mock_data


class MockBuilder:
    """Builder pattern for creating consistent mock environments."""
    
    def __init__(self):
        self.subprocess_responses = []
        self.which_mapping = {}
        self.exists_mapping = {}
        self.environ_vars = {}
        self.platform = 'Darwin'
        self.file_contents = {}
    
    def with_platform(self, platform):
        """Set the platform (Darwin, Linux, Windows)."""
        self.platform = platform
        return self
    
    def with_warp_connected(self):
        """Configure WARP as connected."""
        self.which_mapping['warp-cli'] = mock_data.TOOL_PATHS['warp-cli']
        self.subprocess_responses.extend([
            MagicMock(returncode=0, stdout=mock_data.MOCK_CERTIFICATE),  # warp-cli certs
            MagicMock(returncode=0),  # openssl verify
            MagicMock(returncode=0, stdout=mock_data.WARP_STATUS_CONNECTED),  # warp-cli status
        ])
        return self
    
    def with_warp_disconnected(self):
        """Configure WARP as disconnected."""
        self.which_mapping['warp-cli'] = mock_data.TOOL_PATHS['warp-cli']
        self.subprocess_responses.append(
            MagicMock(returncode=0, stdout=mock_data.WARP_STATUS_DISCONNECTED)
        )
        return self
    
    def with_warp_not_installed(self):
        """Configure system without WARP installed."""
        self.which_mapping['warp-cli'] = None
        return self

    def with_netskope_installed(self, cert_path=None):
        """Configure Netskope as installed with cert at a known path."""
        path = cert_path or mock_data.NETSKOPE_CERT_PATHS_MACOS[0]
        self.exists_mapping[path] = True
        self.file_contents[path] = mock_data.MOCK_NETSKOPE_CERTIFICATE
        return self

    def with_netskope_not_installed(self):
        """Configure system without Netskope installed."""
        for path in mock_data.NETSKOPE_CERT_PATHS_MACOS + mock_data.NETSKOPE_CERT_PATHS_LINUX:
            self.exists_mapping[path] = False
            self.exists_mapping[path + '.enc'] = False
        return self
    
    def with_certificate(self, path=None):
        """Configure certificate file to exist."""
        cert_path = path or f"{mock_data.HOME_DIR}/.cloudflare-ca.pem"
        self.exists_mapping[cert_path] = True
        self.file_contents[cert_path] = mock_data.MOCK_CERTIFICATE
        return self
    
    def with_tool(self, tool_name):
        """Configure a tool to be available."""
        if tool_name in mock_data.TOOL_PATHS:
            self.which_mapping[tool_name] = mock_data.TOOL_PATHS[tool_name]
        return self
    
    def with_tools(self, *tools):
        """Configure multiple tools to be available."""
        for tool in tools:
            self.with_tool(tool)
        return self
    
    def with_env_var(self, key, value):
        """Set an environment variable."""
        self.environ_vars[key] = value
        return self
    
    def with_file(self, path, content):
        """Configure a file to exist with specific content."""
        self.exists_mapping[path] = True
        self.file_contents[path] = content
        return self
    
    def with_subprocess_response(self, returncode=0, stdout="", stderr=""):
        """Add a subprocess response to the queue."""
        self.subprocess_responses.append(
            MagicMock(returncode=returncode, stdout=stdout, stderr=stderr)
        )
        return self
    
    def build(self):
        """Build and return the mock configuration."""
        def which_side_effect(cmd):
            return self.which_mapping.get(cmd)
        
        def exists_side_effect(path):
            return self.exists_mapping.get(str(path), False)
        
        def open_side_effect(path, *args, **kwargs):
            content = self.file_contents.get(str(path), "")
            return mock_open(read_data=content)()
        
        return {
            'platform': self.platform,
            'which_side_effect': which_side_effect,
            'exists_side_effect': exists_side_effect,
            'subprocess_side_effect': self.subprocess_responses,
            'environ': self.environ_vars,
            'open_side_effect': open_side_effect,
        }


@contextmanager
def mock_fumitm_environment(mock_config):
    """Context manager to set up a complete mock environment for fumitm."""
    with patch('platform.system', return_value=mock_config['platform']), \
         patch('fumitm.shutil.which') as mock_which, \
         patch('fumitm.os.path.exists') as mock_exists, \
         patch('fumitm.subprocess.run') as mock_subprocess, \
         patch('fumitm.os.environ', mock_config['environ']), \
         patch('fumitm.os.makedirs'), \
         patch('fumitm.shutil.copy'), \
         patch('builtins.open', side_effect=mock_config['open_side_effect']):
        
        mock_which.side_effect = mock_config['which_side_effect']
        mock_exists.side_effect = mock_config['exists_side_effect']
        
        if mock_config['subprocess_side_effect']:
            mock_subprocess.side_effect = mock_config['subprocess_side_effect']
        
        yield {
            'which': mock_which,
            'exists': mock_exists,
            'subprocess': mock_subprocess,
        }


def assert_subprocess_called_with(mock_subprocess, command_parts):
    """Assert that subprocess was called with specific command parts."""
    for call in mock_subprocess.call_args_list:
        args = call[0][0] if call[0] else []
        if all(part in args for part in command_parts):
            return True
    
    # If not found, provide helpful error message
    actual_calls = []
    for call in mock_subprocess.call_args_list:
        args = call[0][0] if call[0] else []
        actual_calls.append(' '.join(args))
    
    raise AssertionError(
        f"Expected subprocess call with {command_parts}\n"
        f"Actual calls:\n" + '\n'.join(f"  - {call}" for call in actual_calls)
    )


def assert_file_written(mock_open_calls, filepath, content_includes=None):
    """Assert that a file was written with optional content check."""
    for call in mock_open_calls:
        if str(filepath) in str(call):
            if content_includes:
                # Check write calls for content
                write_calls = [c for c in call.mock_calls if 'write' in str(c)]
                content = ''.join(str(c) for c in write_calls)
                if content_includes not in content:
                    raise AssertionError(
                        f"File {filepath} was written but didn't contain '{content_includes}'"
                    )
            return True
    
    raise AssertionError(f"File {filepath} was not written")


def create_temp_cert_file(tmp_path):
    """Create a temporary certificate file for testing."""
    cert_path = tmp_path / "test-cert.pem"
    cert_path.write_text(mock_data.MOCK_CERTIFICATE)
    return str(cert_path)


class FumitmTestCase:
    """Base class providing common test functionality."""

    @staticmethod
    def create_fumitm_instance(mode='status', debug=False, selected_tools=None, provider='warp'):
        """Create a FumitmPython instance with proper mocking.

        Defaults to provider='warp' to skip auto-detection, which would
        otherwise trigger subprocess calls (pgrep) that consume mock responses.
        """
        import fumitm
        with patch('platform.system', return_value='Darwin'):
            return fumitm.FumitmPython(
                mode=mode,
                debug=debug,
                selected_tools=selected_tools or [],
                provider=provider
            )


def import_fumitm_windows():
    """Import the Windows version of fumitm.

    Since fumitm_windows.py is in the parent directory, we need to use
    importlib to load it as a module.
    """
    import importlib.util
    import os

    # Get path to fumitm_windows.py relative to test_suite directory
    test_suite_dir = os.path.dirname(os.path.abspath(__file__))
    module_path = os.path.join(os.path.dirname(test_suite_dir), "fumitm_windows.py")

    spec = importlib.util.spec_from_file_location("fumitm_windows", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module