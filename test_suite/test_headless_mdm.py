"""
Tests for headless/MDM deployment features (issue #50).

Covers color control, log files, JSON-lines logging, --headless flag,
NonInteractiveError, --run-as-user, ToolResult wrapper, changes_made
accuracy, exit codes, and orchestrator environment simulations.
"""
import json
import os
import sys
import tempfile
from unittest.mock import patch, MagicMock

import pytest

from helpers import FumitmTestCase
import fumitm
from fumitm import NonInteractiveError, ToolResult


class TestColorControl(FumitmTestCase):
    """No color when --no-color, NO_COLOR env, --headless, or non-TTY stdout."""

    def test_no_color_flag(self):
        instance = self.create_fumitm_instance(no_color=True)
        assert instance._use_color is False

    def test_no_color_env(self):
        with patch.dict(os.environ, {'NO_COLOR': '1'}):
            instance = self.create_fumitm_instance()
            assert instance._use_color is False

    def test_no_color_env_empty_string(self):
        """NO_COLOR spec says presence of the variable is enough, even if empty."""
        with patch.dict(os.environ, {'NO_COLOR': ''}):
            instance = self.create_fumitm_instance()
            assert instance._use_color is False

    def test_headless_disables_color(self):
        instance = self.create_fumitm_instance(headless=True)
        assert instance._use_color is False

    def test_non_tty_disables_color(self):
        with patch('sys.stdout') as mock_stdout:
            mock_stdout.isatty.return_value = False
            instance = self.create_fumitm_instance()
            assert instance._use_color is False

    def test_tty_enables_color_by_default(self):
        with patch('sys.stdout') as mock_stdout:
            mock_stdout.isatty.return_value = True
            # Remove NO_COLOR if present
            env = os.environ.copy()
            env.pop('NO_COLOR', None)
            with patch.dict(os.environ, env, clear=True):
                instance = self.create_fumitm_instance()
                assert instance._use_color is True

    def test_strip_ansi(self):
        text = '\033[0;32m[INFO]\033[0m hello'
        assert fumitm.FumitmPython._strip_ansi(text) == '[INFO] hello'

    def test_strip_ansi_no_codes(self):
        text = 'plain text'
        assert fumitm.FumitmPython._strip_ansi(text) == 'plain text'


class TestHeadlessFlag(FumitmTestCase):
    """--headless disables color and update check but NOT --yes."""

    def test_headless_disables_color_and_update_check(self):
        instance = self.create_fumitm_instance(
            headless=True, skip_update_check=True
        )
        assert instance._use_color is False
        assert instance.skip_update_check is True
        assert instance.auto_yes is False

    def test_headless_does_not_imply_yes(self):
        instance = self.create_fumitm_instance(headless=True)
        assert instance.auto_yes is False

    def test_headless_env_var(self):
        """FUMITM_HEADLESS=1 should be equivalent to --headless."""
        with patch('fumitm.sys.argv', ['fumitm.py']), \
             patch.dict(os.environ, {'FUMITM_HEADLESS': '1'}), \
             patch('fumitm.FumitmPython') as mock_class:
            mock_instance = MagicMock()
            mock_instance.main.return_value = 0
            mock_class.return_value = mock_instance
            with patch('fumitm.sys.exit'):
                fumitm.main()
            call_kwargs = mock_class.call_args[1]
            assert call_kwargs['headless'] is True
            assert call_kwargs['no_color'] is True
            assert call_kwargs['skip_update_check'] is True


class TestNonInteractiveError(FumitmTestCase):
    """Non-TTY without --yes raises NonInteractiveError, caught as exit 2."""

    def test_prompt_raises_when_no_tty(self):
        """_prompt raises NonInteractiveError when stdin is not a TTY."""
        instance = self.create_fumitm_instance()
        instance.auto_yes = False
        with patch('sys.stdin') as mock_stdin:
            mock_stdin.isatty.return_value = False
            with pytest.raises(NonInteractiveError):
                instance._prompt("Continue? (y/N) ")

    def test_prompt_auto_yes_bypasses_tty_check(self):
        """--yes always returns 'y' regardless of TTY status."""
        instance = self.create_fumitm_instance(auto_yes=True)
        with patch('sys.stdin') as mock_stdin:
            mock_stdin.isatty.return_value = False
            result = instance._prompt("Continue? (y/N) ")
            assert result == 'y'

    def test_main_catches_non_interactive_error(self):
        """NonInteractiveError in main() returns exit code 2."""
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(instance, 'check_for_updates'), \
             patch.object(instance, 'is_devcontainer', return_value=False), \
             patch.object(instance, 'check_environment_sanity'), \
             patch.object(instance, 'check_ownership_sanity'), \
             patch.object(instance, 'download_certificate', return_value=True), \
             patch.object(
                 instance, '_prompt',
                 side_effect=NonInteractiveError("stdin not a TTY")
             ), \
             patch('sys.stdin') as mock_stdin:
            mock_stdin.isatty.return_value = False
            # Force a code path that calls _prompt
            exit_code = instance.main()
            assert exit_code == 2


class TestLogFile(FumitmTestCase):
    """Tests for --log-file and --log-dir text logging."""

    def test_log_file_created(self):
        with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
            path = f.name
        try:
            instance = self.create_fumitm_instance(
                no_color=True, log_file=path
            )
            instance._open_log_files()
            instance.print_info("test message")
            instance._close_log_files()

            content = open(path).read()
            assert '[INFO] test message' in content
            assert '\033[' not in content
        finally:
            os.unlink(path)

    def test_log_file_has_timestamp(self):
        with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as f:
            path = f.name
        try:
            instance = self.create_fumitm_instance(
                no_color=True, log_file=path
            )
            instance._open_log_files()
            instance.print_info("hello")
            instance._close_log_files()

            line = open(path).readline()
            # Format: 2026-03-03T14:30:00 [INFO] hello
            assert line[4] == '-' and line[10] == 'T'
        finally:
            os.unlink(path)

    def test_log_dir_creates_files_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            instance = self.create_fumitm_instance(
                no_color=True, log_dir=tmpdir
            )
            instance._open_log_files()
            instance.print_info("run one")
            instance._close_log_files()

            symlink = os.path.join(tmpdir, 'fumitm-latest.log')
            assert os.path.islink(symlink)

            # Symlink points to a real file with content
            target = os.path.join(tmpdir, os.readlink(symlink))
            assert os.path.isfile(target)
            content = open(target).read()
            assert 'run one' in content

    def test_log_dir_symlink_updates_on_second_run(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # First run
            inst1 = self.create_fumitm_instance(
                no_color=True, log_dir=tmpdir
            )
            inst1._open_log_files()
            inst1.print_info("first")
            inst1._close_log_files()
            first_target = os.readlink(
                os.path.join(tmpdir, 'fumitm-latest.log')
            )

            # Second run (different PID-derived name since same second)
            import time
            time.sleep(0.01)  # Ensure different timestamp possible
            inst2 = self.create_fumitm_instance(
                no_color=True, log_dir=tmpdir
            )
            inst2._open_log_files()
            inst2.print_info("second")
            inst2._close_log_files()
            second_target = os.readlink(
                os.path.join(tmpdir, 'fumitm-latest.log')
            )

            # Symlink should point to second run's file
            target_path = os.path.join(tmpdir, second_target)
            assert 'second' in open(target_path).read()


class TestJsonLogFile(FumitmTestCase):
    """Tests for --json-log-file and --json-log-dir JSON-lines logging."""

    def test_json_log_valid_lines(self):
        with tempfile.NamedTemporaryFile(
            suffix='.jsonl', delete=False
        ) as f:
            path = f.name
        try:
            instance = self.create_fumitm_instance(
                no_color=True, json_log_file=path
            )
            instance._open_log_files()
            instance.print_info("test msg")
            instance.print_error("bad thing")
            instance._close_log_files()

            lines = open(path).readlines()
            assert len(lines) == 2
            for line in lines:
                event = json.loads(line)
                assert 'ts' in event
                assert 'level' in event
                assert 'message' in event
                assert 'phase' in event
                assert 'tool' in event
                assert 'action' in event
                assert 'result' in event
                assert 'error_code' in event
        finally:
            os.unlink(path)

    def test_json_log_levels(self):
        with tempfile.NamedTemporaryFile(
            suffix='.jsonl', delete=False
        ) as f:
            path = f.name
        try:
            instance = self.create_fumitm_instance(
                no_color=True, json_log_file=path
            )
            instance._open_log_files()
            instance.print_info("info msg")
            instance.print_warn("warn msg")
            instance.print_error("error msg")
            instance._close_log_files()

            lines = [json.loads(l) for l in open(path)]
            assert lines[0]['level'] == 'info'
            assert lines[1]['level'] == 'warn'
            assert lines[2]['level'] == 'error'
        finally:
            os.unlink(path)

    def test_json_log_dir_creates_symlink(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            instance = self.create_fumitm_instance(
                no_color=True, json_log_dir=tmpdir
            )
            instance._open_log_files()
            instance.print_info("hello json")
            instance._close_log_files()

            symlink = os.path.join(tmpdir, 'fumitm-latest.jsonl')
            assert os.path.islink(symlink)
            target = os.path.join(tmpdir, os.readlink(symlink))
            event = json.loads(open(target).readline())
            assert 'hello json' in event['message']

    def test_json_log_no_ansi(self):
        with tempfile.NamedTemporaryFile(
            suffix='.jsonl', delete=False
        ) as f:
            path = f.name
        try:
            instance = self.create_fumitm_instance(json_log_file=path)
            instance._open_log_files()
            instance.print_info("clean")
            instance._close_log_files()

            event = json.loads(open(path).readline())
            assert '\033[' not in event['message']
        finally:
            os.unlink(path)


class TestToolResultWrapper(FumitmTestCase):
    """_run_setup() wraps legacy functions and infers results."""

    def test_completed_when_no_errors(self):
        instance = self.create_fumitm_instance()

        def good_setup():
            instance.print_info("all good")

        result = instance._run_setup('test-tool', good_setup)
        assert result.status == 'completed'
        assert result.tool == 'test-tool'

    def test_failed_when_print_error_called(self):
        instance = self.create_fumitm_instance()

        def bad_setup():
            instance.print_error("something broke")

        result = instance._run_setup('test-tool', bad_setup)
        assert result.status == 'failed'

    def test_failed_on_exception(self):
        instance = self.create_fumitm_instance()

        def crashing_setup():
            raise RuntimeError("oops")

        result = instance._run_setup('test-tool', crashing_setup)
        assert result.status == 'failed'
        assert 'oops' in result.message

    def test_passes_through_explicit_tool_result(self):
        instance = self.create_fumitm_instance()

        def explicit_setup():
            return ToolResult('test-tool', 'configured', 'Set env var')

        result = instance._run_setup('test-tool', explicit_setup)
        assert result.status == 'configured'
        assert result.message == 'Set env var'

    def test_error_count_resets_between_calls(self):
        instance = self.create_fumitm_instance()

        def erroring():
            instance.print_error("fail")

        def succeeding():
            instance.print_info("ok")

        r1 = instance._run_setup('tool1', erroring)
        r2 = instance._run_setup('tool2', succeeding)
        assert r1.status == 'failed'
        assert r2.status == 'completed'

    def test_non_interactive_error_propagates(self):
        """NonInteractiveError must not be caught by _run_setup."""
        instance = self.create_fumitm_instance()

        def needs_input():
            raise NonInteractiveError("stdin not a TTY")

        with pytest.raises(NonInteractiveError):
            instance._run_setup('test-tool', needs_input)

    def test_error_counting_scoped_to_setup_context(self):
        """Errors outside _run_setup must not affect the counter."""
        instance = self.create_fumitm_instance()
        instance.print_error("unrelated error before setup")

        def clean_setup():
            pass

        result = instance._run_setup('test-tool', clean_setup)
        assert result.status == 'completed'


class TestChangesmadeAccuracy(FumitmTestCase):
    """changes_made: null for legacy, true when configured, false when all ok."""

    def test_null_for_all_legacy(self):
        results = [
            ToolResult('a', 'completed', ''),
            ToolResult('b', 'completed', ''),
        ]
        assert fumitm.FumitmPython._compute_changes_made(results) is None

    def test_true_when_any_configured(self):
        results = [
            ToolResult('a', 'configured', ''),
            ToolResult('b', 'already_ok', ''),
        ]
        assert fumitm.FumitmPython._compute_changes_made(results) is True

    def test_false_when_all_already_ok(self):
        results = [
            ToolResult('a', 'already_ok', ''),
            ToolResult('b', 'already_ok', ''),
        ]
        assert fumitm.FumitmPython._compute_changes_made(results) is False

    def test_null_when_mixed_completed_and_already_ok(self):
        """Presence of legacy 'completed' makes it unknown."""
        results = [
            ToolResult('a', 'completed', ''),
            ToolResult('b', 'already_ok', ''),
        ]
        assert fumitm.FumitmPython._compute_changes_made(results) is None


class TestExitCodes(FumitmTestCase):
    """Exit codes: 0 success, 1 hard failure, 2 non-interactive, 3 partial."""

    def test_exit_0_all_success(self):
        instance = self.create_fumitm_instance()
        results = [
            ToolResult('a', 'completed', ''),
            ToolResult('b', 'already_ok', ''),
        ]
        code = instance._print_summary(results)
        assert code == 0

    def test_exit_1_all_failed(self):
        instance = self.create_fumitm_instance()
        results = [
            ToolResult('a', 'failed', 'err'),
        ]
        code = instance._print_summary(results)
        assert code == 1

    def test_exit_3_partial_success(self):
        instance = self.create_fumitm_instance()
        results = [
            ToolResult('a', 'completed', ''),
            ToolResult('b', 'failed', 'err'),
        ]
        code = instance._print_summary(results)
        assert code == 3

    def test_exit_0_with_skipped(self):
        instance = self.create_fumitm_instance()
        results = [
            ToolResult('a', 'completed', ''),
            ToolResult('b', 'skipped', 'no user context'),
        ]
        code = instance._print_summary(results)
        assert code == 0

    def test_fumitm_result_line_printed(self, capsys):
        instance = self.create_fumitm_instance()
        results = [ToolResult('a', 'configured', 'done')]
        instance._print_summary(results)
        captured = capsys.readouterr()
        assert 'FUMITM_RESULT:' in captured.out
        # Parse the JSON
        for line in captured.out.splitlines():
            if line.startswith('FUMITM_RESULT:'):
                data = json.loads(line.split(':', 1)[1].strip())
                assert data['changes_made'] is True
                assert data['configured'] == 1
                assert data['exit_code'] == 0

    def test_exit_130_keyboard_interrupt(self):
        instance = self.create_fumitm_instance(mode='install')
        with patch.object(
            instance, '_open_log_files'
        ), patch.object(
            instance, '_close_log_files'
        ), patch.object(
            instance, '_main_inner',
            side_effect=KeyboardInterrupt
        ):
            # KeyboardInterrupt is caught inside _main_inner, so we
            # need to test the actual _main_inner method
            pass

        # Test directly via _main_inner
        with patch.object(instance, 'check_for_updates'), \
             patch.object(
                 instance, 'is_devcontainer', return_value=False
             ), \
             patch.object(instance, 'check_environment_sanity'), \
             patch.object(instance, 'check_ownership_sanity'), \
             patch.object(
                 instance, 'download_certificate',
                 side_effect=KeyboardInterrupt
             ):
            code = instance._main_inner()
            assert code == 130


class TestRunAsUser(FumitmTestCase):
    """Tests for --run-as-user user targeting."""

    def test_run_as_user_requires_root(self):
        """--run-as-user from non-root must fail at argparse level."""
        with patch('fumitm.sys.argv', ['fumitm.py', '--run-as-user', 'bob']):
            with patch('os.getuid', return_value=1000):
                with pytest.raises(SystemExit):
                    fumitm.main()

    def test_apply_target_user_sets_home(self):
        """_apply_target_user sets HOME to target user's home dir."""
        instance = self.create_fumitm_instance()
        mock_pw = MagicMock()
        mock_pw.pw_uid = 501
        mock_pw.pw_gid = 20
        mock_pw.pw_dir = '/Users/testuser'
        with patch('fumitm.pwd.getpwnam', return_value=mock_pw), \
             patch.dict(os.environ, {}, clear=False):
            instance._apply_target_user('testuser')
            assert instance._target_uid == 501
            assert instance._target_gid == 20
            assert os.environ['HOME'] == '/Users/testuser'

    def test_apply_target_user_auto_macos(self):
        """auto mode detects console user via /dev/console ownership."""
        instance = self.create_fumitm_instance()
        mock_stat = MagicMock()
        mock_stat.st_uid = 501
        mock_pw = MagicMock()
        mock_pw.pw_name = 'jdoe'
        mock_pw.pw_uid = 501
        mock_pw.pw_gid = 20
        mock_pw.pw_dir = '/Users/jdoe'
        with patch('fumitm.platform.system', return_value='Darwin'), \
             patch('fumitm.os.stat', return_value=mock_stat), \
             patch('fumitm.pwd.getpwuid', return_value=mock_pw), \
             patch('fumitm.pwd.getpwnam', return_value=mock_pw), \
             patch.dict(os.environ, {}, clear=False):
            instance._apply_target_user('auto')
            assert instance._target_uid == 501

    def test_detect_console_user_returns_none_on_linux(self):
        with patch('fumitm.platform.system', return_value='Linux'):
            result = fumitm.FumitmPython._detect_console_user()
            assert result is None

    def test_detect_console_user_skips_root(self):
        mock_stat = MagicMock()
        mock_stat.st_uid = 0
        mock_pw = MagicMock()
        mock_pw.pw_name = 'root'
        with patch('fumitm.platform.system', return_value='Darwin'), \
             patch('fumitm.os.stat', return_value=mock_stat), \
             patch('fumitm.pwd.getpwuid', return_value=mock_pw):
            result = fumitm.FumitmPython._detect_console_user()
            assert result is None

    def test_has_user_context_false_for_root_without_target(self):
        """Root without --run-as-user or SUDO_USER has no user context."""
        instance = self.create_fumitm_instance()
        instance._target_uid = None
        with patch('os.getuid', return_value=0):
            assert instance._has_user_context() is False

    def test_has_user_context_true_for_normal_user(self):
        instance = self.create_fumitm_instance()
        with patch('os.getuid', return_value=501):
            assert instance._has_user_context() is True

    def test_has_user_context_true_when_target_set(self):
        instance = self.create_fumitm_instance()
        instance._target_uid = 501
        instance._target_gid = 20
        with patch('os.getuid', return_value=0):
            assert instance._has_user_context() is True


class TestSkipUpdateCheck(FumitmTestCase):
    """--skip-update-check prevents the GitHub HTTP call."""

    def test_skip_update_check_flag(self):
        instance = self.create_fumitm_instance(skip_update_check=True)
        assert instance.skip_update_check is True

    def test_headless_implies_skip_update_check(self):
        """--headless sets skip_update_check via module-level main()."""
        with patch('fumitm.sys.argv', ['fumitm.py', '--headless']), \
             patch('fumitm.FumitmPython') as mock_class:
            mock_instance = MagicMock()
            mock_instance.main.return_value = 0
            mock_class.return_value = mock_instance
            with patch('fumitm.sys.exit'):
                fumitm.main()
            call_kwargs = mock_class.call_args[1]
            assert call_kwargs['skip_update_check'] is True


class TestUserScopeGating(FumitmTestCase):
    """User-scoped tools are skipped when running as root without user context."""

    def test_user_scoped_tools_skipped_without_context(self):
        """Root without --run-as-user skips user-scoped tools."""
        instance = self.create_fumitm_instance(mode='install')
        instance._target_uid = None

        results = []
        with patch('os.getuid', return_value=0):
            no_user = (os.getuid() == 0 and not instance._has_user_context())
            assert no_user is True

            for tool_key, tool_info in instance.tools_registry.items():
                if tool_info.get('scope') == 'user' and no_user:
                    results.append(
                        ToolResult(tool_key, 'skipped', 'No user context')
                    )

        # All user-scoped tools should be skipped
        user_tools = [
            k for k, v in instance.tools_registry.items()
            if v.get('scope') == 'user'
        ]
        skipped = [r.tool for r in results]
        for tool in user_tools:
            assert tool in skipped

    def test_system_scoped_tools_run_without_context(self):
        """System-scoped tools still run when there's no user context."""
        instance = self.create_fumitm_instance()
        system_tools = [
            k for k, v in instance.tools_registry.items()
            if v.get('scope') == 'system'
        ]
        assert 'brew-cacerts' in system_tools


class TestSudoHelperUpdates(FumitmTestCase):
    """Updated sudo helpers use _target_uid when set."""

    def test_is_running_as_sudo_with_target_uid(self):
        """_is_running_as_sudo returns True when _target_uid is set to non-root."""
        instance = self.create_fumitm_instance()
        instance._target_uid = 501
        instance._target_gid = 20
        assert instance._is_running_as_sudo() is True

    def test_get_real_user_ids_prefers_target(self):
        """_get_real_user_ids returns _target_uid/gid when set."""
        instance = self.create_fumitm_instance()
        instance._target_uid = 501
        instance._target_gid = 20
        uid, gid = instance._get_real_user_ids()
        assert uid == 501
        assert gid == 20

    def test_get_real_user_ids_falls_back_to_sudo_env(self):
        """Without _target_uid, falls back to SUDO_UID."""
        instance = self.create_fumitm_instance()
        instance._target_uid = None
        with patch('os.getuid', return_value=0), \
             patch.dict(os.environ, {'SUDO_UID': '1000', 'SUDO_GID': '1000'}):
            uid, gid = instance._get_real_user_ids()
            assert uid == 1000
            assert gid == 1000

    def test_detect_shell_uses_target_uid(self):
        """detect_shell looks up target user's shell when _target_uid is set."""
        instance = self.create_fumitm_instance()
        instance._target_uid = 501
        mock_pw = MagicMock()
        mock_pw.pw_shell = '/bin/zsh'
        with patch.dict(os.environ, {}, clear=False), \
             patch('fumitm.pwd.getpwuid', return_value=mock_pw) as mock_getpwuid:
            # Clear SHELL so it falls through to pwd lookup
            env = os.environ.copy()
            env.pop('SHELL', None)
            with patch.dict(os.environ, env, clear=True):
                shell = instance.detect_shell()
                assert shell == 'zsh'
                mock_getpwuid.assert_called_with(501)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
