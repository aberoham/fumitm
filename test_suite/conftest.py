"""
Pytest configuration for fumitm integration tests.

This module provides shared fixtures and configuration for all tests.
"""
import sys
from pathlib import Path

import pytest

# Add parent directory to path so we can import fumitm.py
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import mock data
import mock_data
from helpers import MockBuilder, create_temp_cert_file


@pytest.fixture
def sample_cert_path():
    """Path to sample certificate file."""
    return Path(__file__).parent / "fixtures" / "sample_cert.pem"


@pytest.fixture
def sample_cert_content(sample_cert_path):
    """Content of the sample certificate."""
    return sample_cert_path.read_text()


@pytest.fixture
def temp_warp_cert(tmp_path):
    """Create a temporary WARP certificate for testing."""
    return create_temp_cert_file(tmp_path)


@pytest.fixture
def mock_home_dir(tmp_path, monkeypatch):
    """Mock home directory for testing."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return home


@pytest.fixture
def basic_mock_environment():
    """Basic mock environment with WARP installed and connected."""
    return (MockBuilder()
        .with_platform('Darwin')
        .with_warp_connected()
        .with_certificate()
        .with_tools('openssl')
        .build())


@pytest.fixture
def full_mock_environment():
    """Full mock environment with all common tools installed."""
    return (MockBuilder()
        .with_platform('Darwin')
        .with_warp_connected()
        .with_certificate()
        .with_tools('openssl', 'node', 'npm', 'python3', 'java', 'gcloud', 'wget')
        .with_env_var('HOME', mock_data.HOME_DIR)
        .build())


# Legacy fixtures for backward compatibility
@pytest.fixture
def mock_warp_cert_output():
    """Mock output from warp-cli certs command."""
    return mock_data.MOCK_CERTIFICATE


@pytest.fixture
def mock_warp_status_connected():
    """Mock output from warp-cli status when connected."""
    return mock_data.WARP_STATUS_CONNECTED


@pytest.fixture
def mock_warp_status_disconnected():
    """Mock output from warp-cli status when disconnected."""
    return mock_data.WARP_STATUS_DISCONNECTED


# Test configuration
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )


# Shared assertion helpers
def assert_status_contains(status_dict, tool, expected_fields):
    """Assert that a tool's status contains expected fields."""
    assert tool in status_dict
    for field, value in expected_fields.items():
        assert status_dict[tool].get(field) == value, \
            f"Expected {tool}.{field} to be {value}, got {status_dict[tool].get(field)}"