"""Tests for the cacert directive in curlrc (issue #90).

A cacert directive in the config file of curl has more authority than
CURL_CA_BUNDLE. Thus fumitm must find it and keep its own managed cacert block
last in the file.
"""
import os
from unittest.mock import patch

from helpers import FumitmTestCase

AIKIDO_BLOCK = (
    '# aikido-endpoint-curl-cert-config-start\n'
    '# Trust the Aikido MITM CA for every curl invocation.\n'
    'cacert "/Library/Application Support/AikidoSecurity/aikido-ca.pem"\n'
    '# aikido-endpoint-curl-cert-config-end\n'
)


class TestFindEffectiveCurlrc(FumitmTestCase):
    def test_lookup_order(self, tmp_path, monkeypatch):
        fumitm = self.create_fumitm_instance()
        home = tmp_path / 'home'
        curl_home = tmp_path / 'curlhome'
        xdg = tmp_path / 'xdg'
        for d in (home, curl_home, xdg):
            d.mkdir()
        monkeypatch.setenv('HOME', str(home))
        monkeypatch.setenv('CURL_HOME', str(curl_home))
        monkeypatch.setenv('XDG_CONFIG_HOME', str(xdg))

        (home / '.curlrc').write_text('cacert /home.pem\n')
        assert fumitm._find_effective_curlrc() == str(home / '.curlrc')

        (xdg / 'curlrc').write_text('cacert /xdg.pem\n')
        assert fumitm._find_effective_curlrc() == str(xdg / 'curlrc')

        (curl_home / '.curlrc').write_text('cacert /curlhome.pem\n')
        assert fumitm._find_effective_curlrc() == str(curl_home / '.curlrc')

    def test_no_curlrc(self, tmp_path, monkeypatch):
        fumitm = self.create_fumitm_instance()
        monkeypatch.setenv('HOME', str(tmp_path))
        monkeypatch.delenv('CURL_HOME', raising=False)
        monkeypatch.delenv('XDG_CONFIG_HOME', raising=False)
        assert fumitm._find_effective_curlrc() is None


class TestParseCurlrcCacert(FumitmTestCase):
    def setup_method(self):
        self.fumitm = self.create_fumitm_instance()

    def test_syntax_variants(self):
        for line in ('cacert "/a b/ca.pem"', "cacert '/a b/ca.pem'",
                     'cacert = "/a b/ca.pem"', '--cacert "/a b/ca.pem"',
                     'cacert:"/a b/ca.pem"'):
            path, in_block = self.fumitm._parse_curlrc_cacert(line)
            assert path == '/a b/ca.pem', line
            assert in_block is False

    def test_last_directive_wins(self):
        path, _ = self.fumitm._parse_curlrc_cacert('cacert /first.pem\ncacert /last.pem\n')
        assert path == '/last.pem'

    def test_comments_and_other_options_ignored(self):
        content = '# cacert /commented.pem\nsilent\nuser-agent "x"\n'
        assert self.fumitm._parse_curlrc_cacert(content) == (None, False)

    def test_fumitm_block_detection(self):
        content = AIKIDO_BLOCK + (
            f'{self.fumitm._FUMITM_BLOCK_BEGIN}\n'
            'cacert "/managed.pem"\n'
            f'{self.fumitm._FUMITM_BLOCK_END}\n'
        )
        path, in_block = self.fumitm._parse_curlrc_cacert(content)
        assert path == '/managed.pem'
        assert in_block is True

    def test_vendor_block_not_marked_managed(self):
        path, in_block = self.fumitm._parse_curlrc_cacert(AIKIDO_BLOCK)
        assert path == '/Library/Application Support/AikidoSecurity/aikido-ca.pem'
        assert in_block is False


class TestSetCurlrcCacert(FumitmTestCase):
    def setup_method(self):
        self.fumitm = self.create_fumitm_instance(mode='install')

    def test_appends_block_after_vendor_content(self, tmp_path):
        curlrc = tmp_path / '.curlrc'
        curlrc.write_text(AIKIDO_BLOCK)
        assert self.fumitm._set_curlrc_cacert(str(curlrc), '/managed.pem') is True
        content = curlrc.read_text()
        assert content.startswith('# aikido-endpoint-curl-cert-config-start')
        path, in_block = self.fumitm._parse_curlrc_cacert(content)
        assert (path, in_block) == ('/managed.pem', True)
        assert (tmp_path / '.curlrc.bak').read_text() == AIKIDO_BLOCK

    def test_idempotent(self, tmp_path):
        curlrc = tmp_path / '.curlrc'
        curlrc.write_text(AIKIDO_BLOCK)
        self.fumitm._set_curlrc_cacert(str(curlrc), '/managed.pem')
        after_first = curlrc.read_text()
        assert self.fumitm._set_curlrc_cacert(str(curlrc), '/managed.pem') is False
        assert curlrc.read_text() == after_first

    def test_reemits_block_last_after_vendor_drift(self, tmp_path):
        curlrc = tmp_path / '.curlrc'
        curlrc.write_text(AIKIDO_BLOCK)
        self.fumitm._set_curlrc_cacert(str(curlrc), '/managed.pem')
        with open(curlrc, 'a') as f:
            f.write('cacert "/vendor-came-back.pem"\n')
        assert self.fumitm._set_curlrc_cacert(str(curlrc), '/managed.pem') is True
        path, in_block = self.fumitm._parse_curlrc_cacert(curlrc.read_text())
        assert (path, in_block) == ('/managed.pem', True)

    def test_dry_run_does_not_write(self, tmp_path):
        fumitm = self.create_fumitm_instance(mode='status')
        curlrc = tmp_path / '.curlrc'
        curlrc.write_text(AIKIDO_BLOCK)
        assert fumitm._set_curlrc_cacert(str(curlrc), '/managed.pem') is True
        assert curlrc.read_text() == AIKIDO_BLOCK


class TestSetupCurlCurlrcOverride(FumitmTestCase):
    def _run_setup(self, fumitm, tmp_path, env_bundle):
        with patch.object(fumitm, 'command_exists', return_value=True), \
             patch.object(fumitm, 'verify_connection', return_value='FAILED'), \
             patch.object(fumitm, '_path_belongs_to_other_provider', return_value=None), \
             patch.object(fumitm, 'is_suspicious_full_bundle', return_value=(False, '')), \
             patch.dict(os.environ, {'CURL_CA_BUNDLE': env_bundle, 'HOME': str(tmp_path)}, clear=False):
            os.environ.pop('CURL_HOME', None)
            os.environ.pop('XDG_CONFIG_HOME', None)
            return fumitm.setup_curl_cert()

    def test_override_fixed(self, tmp_path):
        fumitm = self.create_fumitm_instance(mode='install')
        env_bundle = tmp_path / 'bundle.pem'
        env_bundle.write_text('cert')
        curlrc = tmp_path / '.curlrc'
        curlrc.write_text(AIKIDO_BLOCK)
        result = self._run_setup(fumitm, tmp_path, str(env_bundle))
        assert result.status == 'configured'
        path, in_block = fumitm._parse_curlrc_cacert(curlrc.read_text())
        assert (path, in_block) == (str(env_bundle), True)

    def test_no_curlrc_keeps_existing_behavior(self, tmp_path):
        fumitm = self.create_fumitm_instance(mode='install')
        env_bundle = tmp_path / 'bundle.pem'
        env_bundle.write_text('cert')
        result = self._run_setup(fumitm, tmp_path, str(env_bundle))
        assert result.status == 'already_ok'
        assert 'manual investigation' in result.message

    def test_managed_block_already_winning(self, tmp_path):
        fumitm = self.create_fumitm_instance(mode='install')
        env_bundle = tmp_path / 'bundle.pem'
        env_bundle.write_text('cert')
        curlrc = tmp_path / '.curlrc'
        curlrc.write_text(AIKIDO_BLOCK)
        fumitm._set_curlrc_cacert(str(curlrc), str(env_bundle))
        result = self._run_setup(fumitm, tmp_path, str(env_bundle))
        assert result.status == 'already_ok'
