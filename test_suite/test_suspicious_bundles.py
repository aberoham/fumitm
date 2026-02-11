"""
Tests for detecting suspiciously small CA bundles.

These tests focus on the helper heuristics introduced to catch cases where
users accidentally point full-bundle env vars at a single WARP CA cert.
"""
import pytest

from helpers import MockBuilder, mock_fumitm_environment, FumitmTestCase
from unittest.mock import patch, ANY
import mock_data


class TestSuspiciousBundles(FumitmTestCase):
    def test_is_suspicious_when_single_cert_file(self):
        """A file with a single PEM certificate is suspicious as a full bundle."""
        small_path = f"{mock_data.HOME_DIR}/small-bundle.pem"

        mock_config = (
            MockBuilder()
            .with_file(small_path, mock_data.MOCK_CERTIFICATE)
            .build()
        )

        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance()
            suspicious, reason = instance.is_suspicious_full_bundle(small_path, None)
            assert suspicious is True
            assert "contains 1 certificate" in reason

    def test_is_not_suspicious_when_many_certs(self):
        """A bundle containing many certs should not be flagged suspicious."""
        bundle_path = f"{mock_data.HOME_DIR}/big-bundle.pem"
        # Build a bundle with 5 certs and some extra size
        content = (mock_data.SAMPLE_CA_BUNDLE + "\n") * 5

        mock_config = (
            MockBuilder()
            .with_file(bundle_path, content)
            .build()
        )

        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance()
            suspicious, reason = instance.is_suspicious_full_bundle(bundle_path, None)
            assert suspicious is False

    def test_npm_repoint_on_suspicious_existing(self):
        """When npm cafile is a suspicious single-cert file, repoint to managed bundle in install mode."""
        npm_current = f"{mock_data.HOME_DIR}/npm-cafile.pem"
        npm_managed = f"{mock_data.HOME_DIR}/.cloudflare-warp/npm/ca-bundle.pem"

        mock_config = (
            MockBuilder()
            .with_env_var('HOME', mock_data.HOME_DIR)
            .with_tools('node', 'npm')
            .with_file(npm_current, mock_data.MOCK_CERTIFICATE)
            .with_file('/etc/ssl/cert.pem', mock_data.SAMPLE_CA_BUNDLE)
            # npm config get cafile
            .with_subprocess_response(stdout=npm_current)
            # npm config set cafile <managed>
            .with_subprocess_response(returncode=0)
            .build()
        )

        with mock_fumitm_environment(mock_config) as mocks:
            instance = self.create_fumitm_instance(mode='install')
            instance.setup_node_cert()  # calls setup_npm_cafile internally
            # Assert npm set called with managed path
            from helpers import assert_subprocess_called_with
            assert_subprocess_called_with(
                mocks['subprocess'],
                ['npm', 'config', 'set', 'cafile', npm_managed]
            )

    def test_gcloud_repoint_on_suspicious_existing(self):
        """When gcloud custom_ca_certs_file is suspicious, repoint to managed bundle in install mode."""
        gcloud_current = f"{mock_data.HOME_DIR}/gcloud-ca.pem"
        gcloud_managed = f"{mock_data.HOME_DIR}/.config/gcloud/certs/combined-ca-bundle.pem"

        mock_config = (
            MockBuilder()
            .with_env_var('HOME', mock_data.HOME_DIR)
            .with_tools('gcloud')
            .with_file(gcloud_current, mock_data.MOCK_CERTIFICATE)
            .with_file('/etc/ssl/cert.pem', mock_data.SAMPLE_CA_BUNDLE)
            # verify_connection("gcloud") → gcloud projects list --limit=1
            # Return an SSL error so verify_connection returns "FAILED" and
            # setup_gcloud_cert continues to the suspicious-bundle check.
            .with_subprocess_response(returncode=1, stderr='ssl certificate problem')
            # gcloud config get
            .with_subprocess_response(stdout=gcloud_current)
            # gcloud config set
            .with_subprocess_response(returncode=0)
            .build()
        )

        with mock_fumitm_environment(mock_config) as mocks:
            instance = self.create_fumitm_instance(mode='install')
            instance.setup_gcloud_cert()
            from helpers import assert_subprocess_called_with
            assert_subprocess_called_with(
                mocks['subprocess'],
                ['gcloud', 'config', 'set', 'core/custom_ca_certs_file', gcloud_managed]
            )

    def test_git_setup_repoint_on_suspicious_existing(self):
        """When git http.sslCAInfo is suspicious, configure it to managed bundle in install mode."""
        git_current = f"{mock_data.HOME_DIR}/git-ca.pem"
        git_managed = f"{mock_data.HOME_DIR}/.cloudflare-warp/git/ca-bundle.pem"

        mock_config = (
            MockBuilder()
            .with_env_var('HOME', mock_data.HOME_DIR)
            .with_tools('git')
            .with_file(git_current, mock_data.MOCK_CERTIFICATE)
            .with_file('/etc/ssl/cert.pem', mock_data.SAMPLE_CA_BUNDLE)
            # git config --global http.sslCAInfo (get)
            .with_subprocess_response(stdout=git_current)
            # git config --global http.sslCAInfo <managed>
            .with_subprocess_response(returncode=0)
            .build()
        )

        with mock_fumitm_environment(mock_config) as mocks:
            instance = self.create_fumitm_instance(mode='install')
            instance.setup_git_cert()
            from helpers import assert_subprocess_called_with
            assert_subprocess_called_with(
                mocks['subprocess'],
                ['git', 'config', '--global', 'http.sslCAInfo', git_managed]
            )

    def test_curl_repoint_on_suspicious_existing(self):
        """When CURL_CA_BUNDLE is suspicious, repoint to managed bundle in install mode."""
        curl_current = f"{mock_data.HOME_DIR}/curl-ca.pem"
        curl_managed = f"{mock_data.HOME_DIR}/.cloudflare-warp/curl/ca-bundle.pem"

        mock_config = (
            MockBuilder()
            .with_env_var('HOME', mock_data.HOME_DIR)
            .with_env_var('SHELL', '/bin/zsh')
            .with_env_var('CURL_CA_BUNDLE', curl_current)
            .with_tools('curl')
            .with_file(curl_current, mock_data.MOCK_CERTIFICATE)
            .with_file('/etc/ssl/cert.pem', mock_data.SAMPLE_CA_BUNDLE)
            .build()
        )

        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance(mode='install')
            with patch.object(type(instance), 'add_to_shell_config', wraps=instance.add_to_shell_config) as add_cfg:
                instance.setup_curl_cert()
                # Ensure we repointed CURL_CA_BUNDLE to managed path
                add_cfg.assert_any_call('CURL_CA_BUNDLE', curl_managed, ANY)

    def test_git_status_suspicious_returns_issue(self):
        """Git status returns an issue when http.sslCAInfo is a suspicious bundle."""
        git_current = f"{mock_data.HOME_DIR}/git-ca.pem"

        mock_config = (
            MockBuilder()
            .with_env_var('HOME', mock_data.HOME_DIR)
            .with_tools('git')
            .with_file(git_current, mock_data.MOCK_CERTIFICATE)
            # git config --global http.sslCAInfo (get)
            .with_subprocess_response(stdout=git_current)
            .build()
        )

        with mock_fumitm_environment(mock_config):
            instance = self.create_fumitm_instance(mode='status')
            has_issues = instance.check_git_status(None)
            assert has_issues is True

    def test_npm_repoint_even_when_node_extra_ca_certs_already_has_cert(self):
        """Regression test for issue #37: npm cafile fix should run even when
        NODE_EXTRA_CA_CERTS already contains the WARP certificate.

        Previously, setup_node_cert() would early-return when the certificate
        was already in NODE_EXTRA_CA_CERTS, skipping the call to setup_npm_cafile().
        This left npm with a suspicious single-cert bundle.
        """
        node_extra_ca = f"{mock_data.HOME_DIR}/.cloudflare-warp/cloudflare-warp.pem"
        npm_current = node_extra_ca  # npm cafile points to same small file
        npm_managed = f"{mock_data.HOME_DIR}/.cloudflare-warp/npm/ca-bundle.pem"
        cert_path = f"{mock_data.HOME_DIR}/.cloudflare-ca.pem"

        mock_config = (
            MockBuilder()
            .with_env_var('HOME', mock_data.HOME_DIR)
            .with_env_var('SHELL', '/bin/zsh')
            # NODE_EXTRA_CA_CERTS already set to a file with the cert
            .with_env_var('NODE_EXTRA_CA_CERTS', node_extra_ca)
            .with_tools('node', 'npm')
            # Set up CERT_PATH with the certificate (so certificate_exists_in_file works)
            .with_file(cert_path, mock_data.MOCK_CERTIFICATE)
            # The node bundle contains the same WARP cert (suspicious, but has cert)
            .with_file(node_extra_ca, mock_data.MOCK_CERTIFICATE)
            # System CA bundle for creating full npm bundle
            .with_file('/etc/ssl/cert.pem', mock_data.SAMPLE_CA_BUNDLE)
            # npm config get cafile returns the same suspicious file
            .with_subprocess_response(stdout=npm_current)
            # npm config set cafile <managed>
            .with_subprocess_response(returncode=0)
            .build()
        )

        with mock_fumitm_environment(mock_config) as mocks:
            # Patch CERT_PATH to match our mocked home directory
            # (CERT_PATH is set at module import time before mocks)
            import fumitm
            with patch.object(fumitm, 'CERT_PATH', cert_path):
                instance = self.create_fumitm_instance(mode='install')
                with patch('pathlib.Path.touch'):
                    instance.setup_node_cert()
                # Key assertion: npm should be repointed to managed bundle
                # even though NODE_EXTRA_CA_CERTS already had the cert
                from helpers import assert_subprocess_called_with
                assert_subprocess_called_with(
                    mocks['subprocess'],
                    ['npm', 'config', 'set', 'cafile', npm_managed]
                )
