"""
Tests for the passive generation-aware shell refresh (issue #100, Option B).

Covers the self-guarding env files (generation digest, managed-variable
manifest, unset-on-removal), the interactive prompt hook blocks for zsh and
bash, the fish env.fish/stub/conf.d migration, atomic env-file writes, and
real-shell behavior where the shells are available.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from helpers import FumitmTestCase

import fumitm
from fumitm import ToolResult


class TestEnvGeneration(FumitmTestCase):
    """The env files self-guard on a deterministic content generation."""

    def test_generation_deterministic_and_order_independent(self):
        gen = fumitm.FumitmPython._env_generation
        a = gen({'A': '1', 'B': '2'})
        b = gen({'B': '2', 'A': '1'})
        assert a == b
        assert len(a) == 12

    def test_generation_changes_with_values(self):
        gen = fumitm.FumitmPython._env_generation
        assert gen({'A': '1'}) != gen({'A': '2'})
        assert gen({'A': '1'}) != gen({'A': '1', 'B': '2'})

    def test_env_file_structure(self):
        inst = self.create_fumitm_instance(mode='install')
        inst._write_env_file({'SSL_CERT_FILE': '/b.pem'})
        content = Path(inst._env_file_path()).read_text()
        gen = inst._env_generation({'SSL_CERT_FILE': '/b.pem'})
        assert '# fumitm-managed-vars: SSL_CERT_FILE' in content
        assert (f'if [ "${{_FUMITM_ENV_GENERATION:-}}" != "{gen}" ] || '
                '[ "${_FUMITM_ENV_FORCE:-}" = "1" ]; then') in content
        assert '  unset SSL_CERT_FILE' in content
        assert '  export SSL_CERT_FILE="/b.pem"' in content
        assert f'  export _FUMITM_ENV_GENERATION="{gen}"' in content

    def test_read_env_file_skips_internal_vars(self):
        inst = self.create_fumitm_instance(mode='install')
        managed = {'SSL_CERT_FILE': '/b.pem', 'CURL_CA_BUNDLE': '/b.pem'}
        inst._write_env_file(managed)
        assert inst._read_env_file() == managed

    def test_manifest_retains_removed_vars_for_unset(self):
        inst = self.create_fumitm_instance(mode='install')
        inst._write_env_file({'A_VAR': '1', 'B_VAR': '2'})
        inst._write_env_file({'A_VAR': '1'})
        content = Path(inst._env_file_path()).read_text()
        assert '# fumitm-managed-vars: A_VAR B_VAR' in content
        assert '  unset A_VAR B_VAR' in content
        assert '  export B_VAR' not in content

    def test_unchanged_set_is_noop(self):
        inst = self.create_fumitm_instance(mode='install')
        assert inst._write_env_file({'A_VAR': '1'}) is True
        assert inst._write_env_file({'A_VAR': '1'}) is False

    def test_env_write_leaves_no_temp_files(self, isolate_home):
        inst = self.create_fumitm_instance(mode='install')
        inst._write_env_file({'A_VAR': '1'})
        env_dir = Path(inst._env_file_path()).parent
        assert [p.name for p in env_dir.iterdir()] == ['env.sh']


class TestRefreshHookPosix(FumitmTestCase):
    """Prompt hook installation for zsh and bash."""

    def _install(self, shell, **kwargs):
        inst = self.create_fumitm_instance(mode='install', **kwargs)
        with patch.object(inst, 'detect_shell', return_value=shell):
            inst.add_to_shell_config('SSL_CERT_FILE', '/b.pem')
        return inst

    def test_zsh_hook_only_in_zshrc(self, isolate_home):
        self._install('zsh')
        assert fumitm.FumitmPython._FUMITM_REFRESH_BEGIN in \
            (isolate_home / '.zshrc').read_text()
        for name in ('.zshenv', '.zlogin'):
            assert fumitm.FumitmPython._FUMITM_REFRESH_BEGIN not in \
                (isolate_home / name).read_text()

    def test_bash_hook_only_in_bashrc(self, isolate_home):
        self._install('bash')
        assert fumitm.FumitmPython._FUMITM_REFRESH_BEGIN in \
            (isolate_home / '.bashrc').read_text()
        assert fumitm.FumitmPython._FUMITM_REFRESH_BEGIN not in \
            (isolate_home / '.bash_profile').read_text()

    def test_hook_install_is_idempotent(self, isolate_home):
        inst = self._install('zsh')
        first = (isolate_home / '.zshrc').read_text()
        with patch.object(inst, 'detect_shell', return_value='zsh'):
            changed = inst.add_to_shell_config('SSL_CERT_FILE', '/b.pem')
        assert changed is False
        assert (isolate_home / '.zshrc').read_text() == first
        assert first.count(fumitm.FumitmPython._FUMITM_REFRESH_BEGIN) == 1

    def test_stale_hook_block_upgraded_in_place(self, isolate_home):
        (isolate_home / '.zshrc').write_text(
            'alias ll="ls -l"\n'
            f'{fumitm.FumitmPython._FUMITM_REFRESH_BEGIN}\n'
            'obsolete_hook_content\n'
            f'{fumitm.FumitmPython._FUMITM_REFRESH_END}\n'
        )
        self._install('zsh')
        content = (isolate_home / '.zshrc').read_text()
        assert 'obsolete_hook_content' not in content
        assert '_fumitm_refresh()' in content
        assert 'alias ll="ls -l"' in content
        assert content.count(fumitm.FumitmPython._FUMITM_REFRESH_BEGIN) == 1

    def test_no_refresh_hook_flag_skips_hook(self, isolate_home):
        self._install('zsh', no_refresh_hook=True)
        assert fumitm.FumitmPython._FUMITM_REFRESH_BEGIN not in \
            (isolate_home / '.zshrc').read_text()
        # Persistence is unaffected: stub and env file still land.
        assert fumitm.FumitmPython._FUMITM_BLOCK_BEGIN in \
            (isolate_home / '.zshrc').read_text()

    def test_source_stub_stays_last(self, isolate_home):
        self._install('zsh')
        content = (isolate_home / '.zshrc').read_text()
        assert content.index(fumitm.FumitmPython._FUMITM_REFRESH_BEGIN) < \
            content.index(fumitm.FumitmPython._FUMITM_BLOCK_BEGIN)

    def test_managed_block_rewrite_preserves_hook(self, isolate_home):
        """An old fumitm rewriting the managed block must not erase the hook."""
        inst = self._install('zsh')
        # Simulate what an older copy does to the file: replace its own
        # managed block. The refresh block uses different markers, so it is
        # foreign content the old parser leaves verbatim.
        inst._ensure_stub(str(isolate_home / '.zshrc'))
        assert fumitm.FumitmPython._FUMITM_REFRESH_BEGIN in \
            (isolate_home / '.zshrc').read_text()

    def test_sh_gets_no_hook(self, isolate_home):
        self._install('sh')
        profile = isolate_home / '.profile'
        assert fumitm.FumitmPython._FUMITM_REFRESH_BEGIN not in \
            profile.read_text()


class TestHookReconciliation(FumitmTestCase):
    """The install loop converges the hook independently of tool outcomes.

    A fully converged system returns already_ok from every tool without
    reaching add_to_shell_config, so an upgrade from a pre-hook fumitm
    must still install the hook; conversely --no-refresh-hook must remove
    an already-installed hook, not merely skip adding one.
    """

    def _converged_pre_hook_state(self, isolate_home):
        """An existing healthy installation from a pre-hook fumitm: env
        file and stubs current, no refresh hook anywhere."""
        inst = self.create_fumitm_instance(
            mode='install', no_refresh_hook=True)
        with patch.object(inst, 'detect_shell', return_value='zsh'):
            inst.add_to_shell_config('SSL_CERT_FILE', '/b.pem')
        assert fumitm.FumitmPython._FUMITM_REFRESH_BEGIN not in \
            (isolate_home / '.zshrc').read_text()

    def _run_main(self, instance):
        with patch.object(instance, 'check_for_updates'), \
                patch.object(instance, 'is_devcontainer',
                             return_value=False), \
                patch.object(instance, 'check_environment_sanity'), \
                patch.object(instance, 'check_ownership_sanity'), \
                patch.object(instance, 'download_certificate',
                             return_value=True), \
                patch.object(instance, '_prepare_extra_roots'), \
                patch.object(instance, '_announce_extra_roots'):
            return instance.main()

    @staticmethod
    def _parse_result(output):
        line = next(l for l in output.splitlines()
                    if l.startswith('FUMITM_RESULT: '))
        return json.loads(line[len('FUMITM_RESULT: '):])

    def _healthy_instance(self):
        """Install-mode instance whose only tool is already converged."""
        instance = self.create_fumitm_instance(mode='install', auto_yes=True)
        instance.tools_registry = {
            'fake': {
                'name': 'Fake Tool', 'tags': [], 'scope': 'user',
                'setup_func': lambda: ToolResult('fake', 'already_ok', ''),
                'check_func': None,
            }
        }
        return instance

    def test_converged_run_installs_hook(self, isolate_home, capsys):
        """The primary upgrade case: cert and env exports already correct,
        every tool already_ok — the run must still install the hook."""
        self._converged_pre_hook_state(isolate_home)
        instance = self._healthy_instance()
        with patch.object(instance, 'detect_shell', return_value='zsh'):
            exit_code = self._run_main(instance)
        assert exit_code == 0
        assert fumitm.FumitmPython._FUMITM_REFRESH_BEGIN in \
            (isolate_home / '.zshrc').read_text()
        data = self._parse_result(capsys.readouterr().out)
        assert data['changes_made'] is True

    def test_converged_run_with_hook_is_idempotent(self, isolate_home,
                                                   capsys):
        self._converged_pre_hook_state(isolate_home)
        for _ in range(2):
            instance = self._healthy_instance()
            with patch.object(instance, 'detect_shell', return_value='zsh'):
                assert self._run_main(instance) == 0
            output = capsys.readouterr().out
        data = self._parse_result(output)
        assert data['changes_made'] is False
        content = (isolate_home / '.zshrc').read_text()
        assert content.count(fumitm.FumitmPython._FUMITM_REFRESH_BEGIN) == 1

    def test_opt_out_removes_installed_posix_hook(self, isolate_home):
        inst = self.create_fumitm_instance(mode='install')
        with patch.object(inst, 'detect_shell', return_value='zsh'):
            inst.add_to_shell_config('SSL_CERT_FILE', '/b.pem')
        assert fumitm.FumitmPython._FUMITM_REFRESH_BEGIN in \
            (isolate_home / '.zshrc').read_text()

        opt_out = self.create_fumitm_instance(
            mode='install', no_refresh_hook=True)
        with patch.object(opt_out, 'detect_shell', return_value='zsh'):
            result = opt_out._reconcile_refresh_hook()
        assert result.status == 'configured'
        content = (isolate_home / '.zshrc').read_text()
        assert fumitm.FumitmPython._FUMITM_REFRESH_BEGIN not in content
        # Persistence stubs and everything else stay untouched.
        assert fumitm.FumitmPython._FUMITM_BLOCK_BEGIN in content

        with patch.object(opt_out, 'detect_shell', return_value='zsh'):
            again = opt_out._reconcile_refresh_hook()
        assert again.status == 'already_ok'

    def test_opt_out_removes_fish_conf_d_hook(self, isolate_home):
        inst = self.create_fumitm_instance(mode='install')
        inst._ensure_fish_refresh_hook()
        hook = isolate_home / '.config' / 'fish' / 'conf.d' / \
            'fumitm_refresh.fish'
        assert hook.exists()

        opt_out = self.create_fumitm_instance(
            mode='install', no_refresh_hook=True)
        with patch.object(opt_out, 'detect_shell', return_value='fish'):
            result = opt_out._reconcile_refresh_hook()
        assert result.status == 'configured'
        assert not hook.exists()

    def test_reconcile_none_for_hookless_shell(self, isolate_home):
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'detect_shell', return_value='sh'):
            assert instance._reconcile_refresh_hook() is None

    def test_hook_reconciliation_boundary_preserves_none(self, isolate_home):
        """The exception boundary must pass a hookless shell's None
        through untouched, not coerce it into a 'completed' entry that
        would poison changes_made."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'detect_shell', return_value='sh'):
            assert instance._run_hook_reconciliation() is None

    def test_all_tools_failed_stays_hard_failure_despite_hook(
            self, isolate_home, capsys):
        """The hook is not a certificate tool: its successful install must
        not soften an all-tools-failed run from exit 1 to partial exit 3,
        though its 'configured' status still drives changes_made."""
        instance = self.create_fumitm_instance(mode='install', auto_yes=True)
        instance.tools_registry = {
            'fake': {
                'name': 'Fake Tool', 'tags': [], 'scope': 'user',
                'setup_func': lambda: ToolResult('fake', 'failed', 'boom'),
                'check_func': None,
            }
        }
        with patch.object(instance, 'detect_shell', return_value='zsh'):
            exit_code = self._run_main(instance)
        assert exit_code == 1
        assert fumitm.FumitmPython._FUMITM_REFRESH_BEGIN in \
            (isolate_home / '.zshrc').read_text()
        data = self._parse_result(capsys.readouterr().out)
        assert data['exit_code'] == 1
        assert data['changes_made'] is True

    def test_hook_failure_keeps_summary_and_partial_exit(
            self, isolate_home, capsys):
        """A hook I/O failure degrades to a failed refresh-hook entry: the
        machine summary still prints and a run with a configured tool
        exits 3 (partial), instead of escaping to the unexpected-error
        handler and returning 1 with no FUMITM_RESULT line."""
        instance = self.create_fumitm_instance(mode='install', auto_yes=True)
        instance.tools_registry = {
            'fake': {
                'name': 'Fake Tool', 'tags': [], 'scope': 'user',
                'setup_func': lambda: ToolResult('fake', 'configured', ''),
                'check_func': None,
            }
        }
        with patch.object(instance, 'detect_shell', return_value='zsh'), \
                patch.object(instance, '_reconcile_refresh_hook',
                             side_effect=OSError('read-only file system')):
            exit_code = self._run_main(instance)
        assert exit_code == 3
        data = self._parse_result(capsys.readouterr().out)
        assert data['exit_code'] == 3
        assert data['configured'] == 1
        assert data['failed'] == 1


class TestFishEnvFile(FumitmTestCase):
    """fish migration: env.fish, config.fish stub, conf.d prompt hook."""

    def _install(self, isolate_home, **kwargs):
        inst = self.create_fumitm_instance(mode='install', **kwargs)
        config = isolate_home / '.config' / 'fish' / 'config.fish'
        with patch.object(inst, 'detect_shell', return_value='fish'), \
                patch.object(inst, 'get_shell_config',
                             return_value=str(config)):
            inst.add_to_shell_config('SSL_CERT_FILE', '/b.pem')
        return inst, config

    def test_legacy_inline_block_hoisted_to_env_fish(self, isolate_home):
        config = isolate_home / '.config' / 'fish' / 'config.fish'
        config.parent.mkdir(parents=True)
        config.write_text(
            'set -g fish_greeting ""\n'
            f'{fumitm.FumitmPython._FUMITM_BLOCK_BEGIN}\n'
            'export CURL_CA_BUNDLE="/old/bundle.pem"\n'
            f'{fumitm.FumitmPython._FUMITM_BLOCK_END}\n'
        )
        inst, config = self._install(isolate_home)
        env_fish = Path(inst._env_fish_path()).read_text()
        assert 'set -gx CURL_CA_BUNDLE "/old/bundle.pem"' in env_fish
        assert 'set -gx SSL_CERT_FILE "/b.pem"' in env_fish
        content = config.read_text()
        assert 'export CURL_CA_BUNDLE' not in content
        assert 'set -g fish_greeting ""' in content

    def test_env_fish_guard_structure(self, isolate_home):
        inst, _ = self._install(isolate_home)
        content = Path(inst._env_fish_path()).read_text()
        gen = inst._env_generation({'SSL_CERT_FILE': '/b.pem'})
        assert (f'if test "$_FUMITM_ENV_GENERATION" != "{gen}"; '
                'or test "$_FUMITM_ENV_FORCE" = "1"') in content
        # -eg: erase global scope only, so a user's persisted universal
        # value (set -Ux) is never deleted from fish's variable store.
        assert '    set -eg SSL_CERT_FILE' in content
        assert f'    set -gx _FUMITM_ENV_GENERATION "{gen}"' in content
        assert content.rstrip().endswith('end')

    def test_stub_forces_and_clears(self, isolate_home):
        _, config = self._install(isolate_home)
        content = config.read_text()
        assert 'set -g _FUMITM_ENV_FORCE 1' in content
        assert 'source "$HOME/.config/fumitm/env.fish"' in content
        assert 'set -e _FUMITM_ENV_FORCE' in content

    def test_conf_d_hook_created(self, isolate_home):
        self._install(isolate_home)
        hook = isolate_home / '.config' / 'fish' / 'conf.d' / \
            'fumitm_refresh.fish'
        content = hook.read_text()
        assert 'if status is-interactive' in content
        assert '--on-event fish_prompt' in content

    def test_no_refresh_hook_flag_skips_conf_d(self, isolate_home):
        self._install(isolate_home, no_refresh_hook=True)
        hook = isolate_home / '.config' / 'fish' / 'conf.d' / \
            'fumitm_refresh.fish'
        assert not hook.exists()

    def test_shared_generation_across_shell_families(self, isolate_home):
        """The same var set hashes identically for env.sh and env.fish, so a
        fish child of a current POSIX shell skips the re-export and vice
        versa."""
        inst, _ = self._install(isolate_home)
        env_fish = Path(inst._env_fish_path()).read_text()
        inst2 = self.create_fumitm_instance(mode='install')
        with patch.object(inst2, 'detect_shell', return_value='zsh'):
            inst2.add_to_shell_config('SSL_CERT_FILE', '/b.pem')
        env_sh = Path(inst2._env_file_path()).read_text()
        gen = inst._env_generation({'SSL_CERT_FILE': '/b.pem'})
        assert gen in env_fish
        assert gen in env_sh


@pytest.mark.skipif(shutil.which('zsh') is None, reason='zsh not installed')
class TestRealZshRefresh(FumitmTestCase):
    """End-to-end hook behavior in a real zsh."""

    def _setup(self, isolate_home):
        inst = self.create_fumitm_instance(mode='install')
        with patch.object(inst, 'detect_shell', return_value='zsh'):
            inst.add_to_shell_config('SSL_CERT_FILE', '/fumitm/bundle.pem')
        env = {'HOME': str(isolate_home), 'TERM': 'dumb',
               'PATH': os.environ.get('PATH', '/usr/bin:/bin')}
        return inst, env

    def _zsh(self, env, script):
        proc = subprocess.run(['zsh', '-c', script], capture_output=True,
                              text=True, env=env, timeout=30, check=False)
        return proc.stdout.strip().splitlines()

    def test_generated_files_pass_syntax_check(self, isolate_home):
        self._setup(isolate_home)
        for name in ('.zshenv', '.zshrc', '.zlogin'):
            subprocess.run(['zsh', '-n', str(isolate_home / name)],
                           check=True)
        subprocess.run(
            ['sh', '-n', str(isolate_home / '.config/fumitm/env.sh')],
            check=True)

    def test_hook_registers_once_and_preserves_status(self, isolate_home):
        _, env = self._setup(isolate_home)
        lines = self._zsh(env, (
            'source ~/.zshrc\n'
            'source ~/.zshrc\n'
            'echo "count:${#precmd_functions}"\n'
            'false\n'
            '_fumitm_refresh\n'
            'echo "status:$?"\n'
        ))
        assert 'count:1' in lines
        assert 'status:1' in lines

    def test_hook_applies_out_of_band_generation_change(self, isolate_home):
        inst, env = self._setup(isolate_home)
        # A shell loads the current generation, then another fumitm run (any
        # copy, any invocation path) rewrites the env file. The hook must
        # apply the new value at the next prompt without re-running fumitm.
        script = (
            'source ~/.zshrc\n'
            'echo "before:$SSL_CERT_FILE"\n'
            'touch "$HOME/loaded"\n'
            'until [ -f "$HOME/updated" ]; do sleep 0.1; done\n'
            '_fumitm_refresh\n'
            'echo "after:$SSL_CERT_FILE"\n'
        )
        proc = subprocess.Popen(['zsh', '-c', script],
                                stdout=subprocess.PIPE, text=True, env=env)
        try:
            import time
            deadline = time.time() + 15
            while not (isolate_home / 'loaded').exists():
                assert time.time() < deadline, 'shell never loaded env'
                time.sleep(0.05)
            with patch.object(inst, 'detect_shell', return_value='zsh'):
                inst.add_to_shell_config('SSL_CERT_FILE',
                                         '/fumitm/bundle2.pem')
            (isolate_home / 'updated').touch()
            out, _ = proc.communicate(timeout=15)
        finally:
            if proc.poll() is None:
                proc.kill()
        assert 'before:/fumitm/bundle.pem' in out
        assert 'after:/fumitm/bundle2.pem' in out

    def test_same_generation_does_not_fight_manual_export(self, isolate_home):
        _, env = self._setup(isolate_home)
        lines = self._zsh(env, (
            'source ~/.zshrc\n'
            'export SSL_CERT_FILE=/user/manual.pem\n'
            '_fumitm_refresh\n'
            'echo "value:$SSL_CERT_FILE"\n'
        ))
        assert 'value:/user/manual.pem' in lines


@pytest.mark.skipif(shutil.which('bash') is None, reason='bash not installed')
class TestRealBashRefresh(FumitmTestCase):
    """End-to-end hook behavior in a real bash."""

    def _setup(self, isolate_home):
        inst = self.create_fumitm_instance(mode='install')
        with patch.object(inst, 'detect_shell', return_value='bash'):
            inst.add_to_shell_config('SSL_CERT_FILE', '/fumitm/bundle.pem')
        env = {'HOME': str(isolate_home), 'TERM': 'dumb',
               'PATH': os.environ.get('PATH', '/usr/bin:/bin')}
        return inst, env

    def test_generated_files_pass_syntax_check(self, isolate_home):
        self._setup(isolate_home)
        for name in ('.bashrc', '.bash_profile'):
            subprocess.run(['bash', '-n', str(isolate_home / name)],
                           check=True)

    def test_hook_registered_idempotently_in_prompt_command(
            self, isolate_home):
        _, env = self._setup(isolate_home)
        proc = subprocess.run(
            ['bash', '-i', '-c',
             ('source ~/.bashrc; source ~/.bashrc; '
              'echo "pc:[$PROMPT_COMMAND]"')],
            capture_output=True, text=True, env=env, timeout=30, check=False)
        assert 'pc:[_fumitm_refresh]' in proc.stdout

    def test_non_interactive_bash_skips_registration(self, isolate_home):
        _, env = self._setup(isolate_home)
        proc = subprocess.run(
            ['bash', '-c', 'source ~/.bashrc; echo "pc:[$PROMPT_COMMAND]"'],
            capture_output=True, text=True, env=env, timeout=30, check=False)
        assert 'pc:[]' in proc.stdout


@pytest.mark.skipif(shutil.which('fish') is None, reason='fish not installed')
class TestRealFishRefresh(FumitmTestCase):
    """End-to-end env.fish behavior in a real fish."""

    def test_new_fish_shell_gets_exports(self, isolate_home):
        inst = self.create_fumitm_instance(mode='install')
        config = isolate_home / '.config' / 'fish' / 'config.fish'
        with patch.object(inst, 'detect_shell', return_value='fish'), \
                patch.object(inst, 'get_shell_config',
                             return_value=str(config)):
            inst.add_to_shell_config('SSL_CERT_FILE', '/fumitm/bundle.pem')
        env = {'HOME': str(isolate_home), 'TERM': 'dumb',
               'XDG_CONFIG_HOME': str(isolate_home / '.config'),
               'PATH': os.environ.get('PATH', '/usr/bin:/bin')}
        proc = subprocess.run(['fish', '-c', 'echo $SSL_CERT_FILE'],
                              capture_output=True, text=True, env=env,
                              timeout=30, check=False)
        assert proc.stdout.strip().splitlines()[-1] == '/fumitm/bundle.pem'

    def test_universal_variable_survives_install(self, isolate_home):
        """A user's persisted universal value (set -Ux) must survive the
        generation refresh. An unscoped `set -e` erases from the smallest
        existing scope, so the first source of env.fish would delete the
        universal value from fish's persistent variable store — permanent
        configuration loss. The -eg erase touches only fumitm's globals,
        leaving the universal value shadowed underneath."""
        env = {'HOME': str(isolate_home), 'TERM': 'dumb',
               'XDG_CONFIG_HOME': str(isolate_home / '.config'),
               'PATH': os.environ.get('PATH', '/usr/bin:/bin')}
        subprocess.run(
            ['fish', '-c', 'set -Ux SSL_CERT_FILE /user/universal.pem'],
            env=env, timeout=30, check=True)

        inst = self.create_fumitm_instance(mode='install')
        config = isolate_home / '.config' / 'fish' / 'config.fish'
        with patch.object(inst, 'detect_shell', return_value='fish'), \
                patch.object(inst, 'get_shell_config',
                             return_value=str(config)):
            inst.add_to_shell_config('SSL_CERT_FILE', '/fumitm/bundle.pem')

        # The session value is fumitm's global (it shadows the universal);
        # this first shell is also the one whose sourcing would have
        # erased the universal store under the old unscoped erase.
        proc = subprocess.run(
            ['fish', '-c', 'echo "session:$SSL_CERT_FILE"'],
            capture_output=True, text=True, env=env, timeout=30,
            check=False)
        assert 'session:/fumitm/bundle.pem' in proc.stdout

        proc = subprocess.run(
            ['fish', '-c',
             'set -qU SSL_CERT_FILE; and echo universal-present'],
            capture_output=True, text=True, env=env, timeout=30,
            check=False)
        assert 'universal-present' in proc.stdout, \
            'universal variable was erased from the persistent store'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
