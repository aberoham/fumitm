"""Tests for gcloud CA trust across named configuration files.

fumitm exports CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE, which overrides every gcloud
configuration file. `gcloud config get-value` therefore reports the export, so
a configuration file pointing at a stale bundle went unnoticed while every
process started outside a shell, which reads the file, failed TLS. These tests
pin the replacement: each configuration file is read on its own and repaired.
"""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import mock_data
from helpers import FumitmTestCase, gcloud_listing

import fumitm

GCLOUD_ENV_VAR = 'CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE'

# Three certificates without the proxy root: large enough not to be suspicious,
# yet unable to verify an intercepted connection.
STALE_BUNDLE = (mock_data.SAMPLE_CA_BUNDLE + mock_data.MOCK_AIKIDO_ROOT_CERT
                + mock_data.MOCK_AIKIDO_INTERMEDIATE_CERT)
GOOD_BUNDLE = STALE_BUNDLE + mock_data.MOCK_CERTIFICATE
ROTATED_ROOT = mock_data.MOCK_CERTIFICATE.replace('MI', 'AA', 1)


def _listing(*configs):
    """Mock result of `gcloud config configurations list` for (name, active, ca) tuples."""
    return MagicMock(returncode=0, stdout=gcloud_listing(*configs), stderr='')


class GcloudFake:
    """Route gcloud subprocess calls: listing, `config set`, everything else.

    Records each `config set` with the environment it ran in, and fails the
    configurations named in fail_for.
    """

    def __init__(self, listing, fail_for=()):
        self.listing = listing
        self.fail_for = set(fail_for)
        self.sets = []

    def __call__(self, cmd, **kwargs):
        if cmd[:4] == ['gcloud', 'config', 'configurations', 'list']:
            return self.listing
        if cmd == ['gcloud', 'config', 'get-value', 'core/custom_ca_certs_file']:
            # Production no longer calls this. The fake answers as real gcloud
            # does, with the effective value in which the export wins, so a
            # revert to get-value fails the masking tests instead of passing
            # them on an empty answer.
            env = kwargs.get('env', os.environ)
            return MagicMock(returncode=0, stdout=env.get(GCLOUD_ENV_VAR, ''), stderr='')
        if 'set' in cmd and 'core/custom_ca_certs_file' in cmd:
            name = cmd[cmd.index('--configuration') + 1] if '--configuration' in cmd else None
            self.sets.append((name, cmd[-1], kwargs.get('env')))
            if name in self.fail_for:
                return MagicMock(returncode=1, stdout='', stderr='permission denied')
        return MagicMock(returncode=0, stdout='', stderr='')

    @property
    def set_names(self):
        return [name for name, _, _ in self.sets]


class GcloudConfigTestCase(FumitmTestCase):
    """Common fixture: a proxy root on disk and bundles of known content."""

    def _instance(self, tmp_path, mode='install', auto_yes=True):
        inst = self.create_fumitm_instance(mode=mode, auto_yes=auto_yes)
        with open(inst.cert_path, 'w') as f:
            f.write(mock_data.MOCK_CERTIFICATE)
        self.stale = tmp_path / 'stale.pem'
        self.stale.write_text(STALE_BUNDLE)
        self.good = tmp_path / 'good.pem'
        self.good.write_text(GOOD_BUNDLE)
        self.managed = os.path.expanduser('~/.config/gcloud/certs/combined-ca-bundle.pem')
        return inst

    def _setup(self, inst, fake):
        with patch.object(inst, 'command_exists', return_value=True), \
             patch.object(inst, 'is_devcontainer', return_value=True), \
             patch('fumitm.subprocess.run', side_effect=fake):
            result = inst.setup_gcloud_cert()
        assert inst._compute_changes_made([result]) is (
            result.status == 'configured' or result.changed is True)
        return result


class TestGcloudConfigListing(GcloudConfigTestCase):
    """_gcloud_configurations parses the listing and fails closed to None."""

    def _configs(self, tmp_path, result):
        inst = self._instance(tmp_path)
        with patch('fumitm.subprocess.run', return_value=result) as run:
            return inst._gcloud_configurations(), run

    def test_reads_each_file_value(self, tmp_path):
        configs, _ = self._configs(tmp_path, _listing(
            ('default', True, '/a.pem'), ('other', False, None)))
        assert configs == [fumitm.GcloudConfig('default', True, '/a.pem'),
                           fumitm.GcloudConfig('other', False, '')]

    def test_listing_runs_without_the_export(self, tmp_path, monkeypatch):
        monkeypatch.setenv(GCLOUD_ENV_VAR, '/exported.pem')
        _, run = self._configs(tmp_path, _listing(('default', True, '/a.pem')))
        assert GCLOUD_ENV_VAR not in run.call_args.kwargs['env']
        assert os.environ[GCLOUD_ENV_VAR] == '/exported.pem'
        assert run.call_args.args[0] == [
            'gcloud', 'config', 'configurations', 'list',
            '--format=json(name,is_active,properties.core.custom_ca_certs_file)',
        ]

    def test_empty_listing_stands_in_the_active_configuration(self, tmp_path):
        configs, _ = self._configs(tmp_path, MagicMock(returncode=0, stdout='[]'))
        assert configs == [fumitm.GcloudConfig(None, True, '')]

    def test_entry_without_properties_reads_as_unset(self, tmp_path):
        result = MagicMock(returncode=0, stdout=json.dumps([{'name': 'x', 'is_active': True}]))
        configs, _ = self._configs(tmp_path, result)
        assert configs == [fumitm.GcloudConfig('x', True, '')]

    def test_nonzero_exit_returns_none(self, tmp_path):
        configs, _ = self._configs(tmp_path, MagicMock(returncode=1, stdout='', stderr='boom'))
        assert configs is None

    def test_malformed_json_returns_none(self, tmp_path):
        configs, _ = self._configs(tmp_path, MagicMock(returncode=0, stdout='not json'))
        assert configs is None

    def test_non_list_json_returns_none(self, tmp_path):
        configs, _ = self._configs(tmp_path, MagicMock(returncode=0, stdout='{}'))
        assert configs is None

    def test_timeout_returns_none(self, tmp_path):
        inst = self._instance(tmp_path)
        with patch('fumitm.subprocess.run',
                   side_effect=fumitm.subprocess.TimeoutExpired('gcloud', 30)):
            assert inst._gcloud_configurations() is None


class TestGcloudConfigSetup(GcloudConfigTestCase):
    """setup_gcloud_cert repairs every stale configuration file."""

    def test_stale_file_repaired_although_export_is_correct(self, tmp_path, monkeypatch):
        """The bug: a correct export masked a stale configuration file."""
        inst = self._instance(tmp_path)
        monkeypatch.setenv(GCLOUD_ENV_VAR, str(self.good))
        fake = GcloudFake(_listing(('default', True, str(self.stale))))
        result = self._setup(inst, fake)
        assert result.status == 'configured'
        assert fake.sets == [('default', self.managed, fake.sets[0][2])]
        assert GCLOUD_ENV_VAR not in fake.sets[0][2]
        assert os.environ[GCLOUD_ENV_VAR] == str(self.good)
        assert mock_data.MOCK_CERTIFICATE.strip() in open(self.managed).read()

    def test_only_stale_configurations_are_repointed(self, tmp_path):
        inst = self._instance(tmp_path)
        fake = GcloudFake(_listing(
            ('good', True, str(self.good)),
            ('missing', False, str(tmp_path / 'gone.pem')),
            ('unset', False, None),
        ))
        result = self._setup(inst, fake)
        assert result.status == 'configured'
        assert fake.set_names == ['missing', 'unset']

    def test_all_configurations_good_is_already_ok(self, tmp_path):
        inst = self._instance(tmp_path)
        fake = GcloudFake(_listing(('a', True, str(self.good)), ('b', False, str(self.good))))
        result = self._setup(inst, fake)
        assert result.status == 'already_ok'
        assert fake.sets == []

    def test_suspicious_bundle_repointed_without_asking(self, tmp_path):
        inst = self._instance(tmp_path, auto_yes=False)
        single = tmp_path / 'single.pem'
        single.write_text(mock_data.MOCK_CERTIFICATE)
        fake = GcloudFake(_listing(('default', True, str(single))))
        with patch.object(inst, '_prompt') as prompt:
            result = self._setup(inst, fake)
        prompt.assert_not_called()
        assert result.status == 'configured'
        assert fake.set_names == ['default']

    def test_declining_keeps_custom_files_and_repairs_the_rest(self, tmp_path):
        inst = self._instance(tmp_path, auto_yes=False)
        fake = GcloudFake(_listing(('custom', True, str(self.stale)), ('unset', False, None)))
        with patch.object(inst, '_prompt', return_value='n') as prompt:
            result = self._setup(inst, fake)
        prompt.assert_called_once()
        assert result.status == 'configured'
        assert fake.set_names == ['unset']

    def test_declining_the_only_stale_file_skips(self, tmp_path):
        inst = self._instance(tmp_path, auto_yes=False)
        fake = GcloudFake(_listing(('custom', True, str(self.stale))))
        with patch.object(inst, '_prompt', return_value='n'):
            result = self._setup(inst, fake)
        assert result.status == 'skipped'
        assert fake.sets == []

    def test_stale_managed_bundle_is_rebuilt_without_asking(self, tmp_path):
        inst = self._instance(tmp_path, auto_yes=False)
        os.makedirs(os.path.dirname(self.managed))
        with open(self.managed, 'w') as f:
            f.write(STALE_BUNDLE)
        fake = GcloudFake(_listing(('default', True, self.managed)))
        with patch.object(inst, '_prompt') as prompt:
            result = self._setup(inst, fake)
        prompt.assert_not_called()
        assert result.status == 'configured'
        assert mock_data.MOCK_CERTIFICATE.strip() in open(self.managed).read()

    def test_listing_failure_repairs_the_active_configuration(self, tmp_path):
        inst = self._instance(tmp_path)
        fake = GcloudFake(MagicMock(returncode=1, stdout='', stderr='boom'))
        result = self._setup(inst, fake)
        assert result.status == 'configured'
        assert fake.set_names == [None]

    def test_one_failed_set_still_attempts_the_others(self, tmp_path):
        inst = self._instance(tmp_path)
        fake = GcloudFake(_listing(('a', True, None), ('b', False, None)), fail_for={'a'})
        result = self._setup(inst, fake)
        assert fake.set_names == ['a', 'b']
        assert result.status == 'failed'
        assert "'a'" in result.message
        assert result.changed is True

    def test_every_set_failing_reports_no_change(self, tmp_path):
        inst = self._instance(tmp_path)
        fake = GcloudFake(_listing(('a', True, None)), fail_for={'a'})
        result = self._setup(inst, fake)
        assert result.status == 'failed'
        assert result.changed is False

    def test_failed_sets_after_a_pre_bootstrap_write_report_a_change(self, tmp_path):
        inst = self._instance(tmp_path)
        fake = GcloudFake(_listing(('a', True, None)), fail_for={'a'})
        with patch.object(inst, '_gcloud_pre_bootstrap', return_value=True):
            result = self._setup(inst, fake)
        assert result.status == 'failed'
        assert result.changed is True

    def test_declining_after_a_pre_bootstrap_write_reports_a_change(self, tmp_path):
        inst = self._instance(tmp_path, auto_yes=False)
        fake = GcloudFake(_listing(('custom', True, str(self.stale))))
        with patch.object(inst, '_gcloud_pre_bootstrap', return_value=True), \
             patch.object(inst, '_prompt', return_value='n'):
            result = self._setup(inst, fake)
        assert result.status == 'skipped'
        assert result.changed is True

    def test_root_append_failure_keeps_the_existing_bundle(self, tmp_path):
        """A bundle that other configurations rely on must not lose the root."""
        inst = self._instance(tmp_path)
        os.makedirs(os.path.dirname(self.managed))
        with open(self.managed, 'w') as f:
            f.write(GOOD_BUNDLE)
        fake = GcloudFake(_listing(('in-use', True, self.managed), ('unset', False, None)))
        with patch.object(inst, '_append_all_proxy_roots', return_value=False):
            result = self._setup(inst, fake)
        assert result.status == 'failed'
        assert fake.sets == []
        assert open(self.managed).read() == GOOD_BUNDLE
        assert os.listdir(os.path.dirname(self.managed)) == ['combined-ca-bundle.pem']

    @pytest.mark.parametrize('stage', ['create', 'append'])
    @pytest.mark.parametrize('raises', [False, True])
    def test_bundle_build_failure_cleans_staging(self, tmp_path, stage, raises):
        inst = self._instance(tmp_path)
        os.makedirs(os.path.dirname(self.managed))
        Path(self.managed).write_text(GOOD_BUNDLE)
        fake = GcloudFake(_listing(('in-use', True, self.managed), ('unset', False, None)))

        def fail(path):
            Path(path).write_text('partial bundle')
            if raises:
                raise OSError('write failed')
            return False

        method = ('create_bundle_with_system_certs' if stage == 'create'
                  else '_append_all_proxy_roots')
        with patch.object(inst, method, side_effect=fail):
            result = self._setup(inst, fake)
        assert result.status == 'failed'
        assert result.changed is False
        assert fake.sets == []
        assert Path(self.managed).read_text() == GOOD_BUNDLE
        assert os.listdir(os.path.dirname(self.managed)) == ['combined-ca-bundle.pem']

    def test_dry_run_changes_nothing(self, tmp_path):
        inst = self._instance(tmp_path, mode='status')
        fake = GcloudFake(_listing(('custom', True, str(self.stale)), ('unset', False, None)))
        with patch.object(inst, '_prompt') as prompt:
            result = self._setup(inst, fake)
        prompt.assert_not_called()
        assert result.status == 'skipped'
        assert fake.sets == []
        assert not os.path.exists(self.managed)

    @pytest.mark.parametrize('ca', ['custom', 'good', 'unset', 'missing', 'suspicious'])
    @pytest.mark.parametrize('installed', [False, True])
    def test_dry_run_with_pre_bootstrap_writes_nothing(self, tmp_path, ca, installed):
        inst = self._instance(tmp_path, mode='status', auto_yes=False)
        home = Path(os.path.expanduser('~'))
        (home / '.python-ca-bundle.pem').write_text(GOOD_BUNDLE)
        inst.extra_roots = [{'path': str(self.good)}]
        paths = {'custom': str(self.stale), 'good': str(self.good), 'unset': None,
                 'missing': str(tmp_path / 'gone.pem'), 'suspicious': inst.cert_path}
        fake = GcloudFake(_listing(('default', True, paths[ca])))

        def snapshot():
            return {str(p.relative_to(home)): p.read_bytes() if p.is_file() else None
                    for p in home.rglob('*')}

        before = snapshot()
        with patch.object(inst, 'command_exists', return_value=installed), \
             patch.object(inst, '_prompt') as prompt, \
             patch('fumitm.subprocess.run', side_effect=fake):
            inst.setup_gcloud_cert()
        prompt.assert_not_called()
        assert fake.sets == []
        assert snapshot() == before


class TestGcloudConfigStatus(GcloudConfigTestCase):
    """check_gcloud_status judges each configuration file, not the export."""

    def _status(self, inst, fake, verify):
        with patch.object(inst, 'command_exists', return_value=True), \
             patch.object(inst, 'verify_connection', return_value=verify), \
             patch('fumitm.subprocess.run', side_effect=fake):
            return inst.check_gcloud_status(inst.cert_path)

    def test_stale_file_is_an_issue_although_connection_works(
            self, tmp_path, monkeypatch, capsys):
        inst = self._instance(tmp_path, mode='status')
        monkeypatch.setenv(GCLOUD_ENV_VAR, str(self.good))
        fake = GcloudFake(_listing(('default', True, str(self.stale))))
        assert self._status(inst, fake, 'WORKING') is True
        out = capsys.readouterr().out
        assert "gcloud configuration 'default'" in out
        assert 'apps started outside a shell' in out

    def test_good_files_have_no_issue(self, tmp_path):
        inst = self._instance(tmp_path, mode='status')
        fake = GcloudFake(_listing(('a', True, str(self.good)), ('b', False, str(self.good))))
        assert self._status(inst, fake, 'WORKING') is False

    @pytest.mark.parametrize('primary', ['same', 'rotated', 'missing'])
    def test_status_uses_the_fresh_primary_root(self, tmp_path, primary):
        inst = self._instance(tmp_path, mode='status')
        fresh = tmp_path / 'fresh.pem'
        fresh.write_text(mock_data.MOCK_CERTIFICATE)
        if primary == 'rotated':
            Path(inst.cert_path).write_text(ROTATED_ROOT)
        elif primary == 'missing':
            os.remove(inst.cert_path)
        assert inst._status_roots_present(str(fresh), str(self.good)) is True
        assert inst._all_roots_present_in_file(str(self.good)) is (primary == 'same')

    def test_both_matchers_require_supplemental_roots(self, tmp_path):
        inst = self._instance(tmp_path, mode='status')
        extra = tmp_path / 'extra.pem'
        extra.write_text(ROTATED_ROOT)
        inst.extra_roots = [{'path': str(extra)}]
        assert inst._status_roots_present(inst.cert_path, str(self.good)) is False
        assert inst._all_roots_present_in_file(str(self.good)) is False
        with self.good.open('a') as f:
            f.write(ROTATED_ROOT)
        assert inst._status_roots_present(inst.cert_path, str(self.good)) is True
        assert inst._all_roots_present_in_file(str(self.good)) is True

    def test_unset_is_an_issue_when_verification_skipped(self, tmp_path):
        """Setup repairs an unset file whatever verification did; status agrees."""
        inst = self._instance(tmp_path, mode='status')
        fake = GcloudFake(_listing(('default', True, None)))
        assert self._status(inst, fake, 'SKIPPED') is True

    def test_good_files_with_verification_skipped_have_no_issue(self, tmp_path):
        inst = self._instance(tmp_path, mode='status')
        fake = GcloudFake(_listing(('default', True, str(self.good))))
        assert self._status(inst, fake, 'SKIPPED') is False

    def test_unset_is_an_issue_when_connection_works(self, tmp_path):
        inst = self._instance(tmp_path, mode='status')
        fake = GcloudFake(_listing(('default', True, None)))
        assert self._status(inst, fake, 'WORKING') is True

    def test_failed_connection_is_an_issue_with_good_files(self, tmp_path):
        inst = self._instance(tmp_path, mode='status')
        fake = GcloudFake(_listing(('default', True, str(self.good))))
        assert self._status(inst, fake, 'FAILED') is True

    def test_listing_failure_is_an_issue(self, tmp_path):
        inst = self._instance(tmp_path, mode='status')
        fake = GcloudFake(MagicMock(returncode=1, stdout='', stderr='boom'))
        assert self._status(inst, fake, 'WORKING') is True
