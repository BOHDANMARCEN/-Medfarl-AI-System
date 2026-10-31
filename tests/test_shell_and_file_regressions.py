import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch

from config import settings
from core.coder import CoderSession
from core.file_ops import copy_path, move_path, _create_backup, _read_text_file
from core.shell_runner import run_shell
from tools.tools import _run_shell_command, _resolve_allowed_path
from ui.cli import CLI


class FileRegressions(unittest.TestCase):
    def test_eof_exits_multiline_shell_instead_of_buffering_exit(self):
        with patch('builtins.input', side_effect=EOFError):
            self.assertEqual(CLI().prompt(strip_input=False), '/quit')

    def test_overlapping_copy_move_never_delete_source(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(settings, 'unsafe_full_access', True):
            parent = Path(temp) / 'parent'
            parent.mkdir()
            child = parent / 'data.txt'
            child.write_text('preserve', encoding='utf-8')
            for action in (copy_path, move_path):
                for source, dest in ((child, child), (child, parent), (parent, parent / 'nested')):
                    with self.subTest(action=action.__name__, source=source, dest=dest):
                        result = action(str(source), str(dest), overwrite=True)
                        self.assertIn('error', result)
                        self.assertEqual(child.read_text(), 'preserve')

    def test_backups_are_unique_and_preserve_versions(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'a.txt'
            path.write_text('one')
            first = _create_backup(path)
            path.write_text('two')
            second = _create_backup(path)
            self.assertNotEqual(first, second)
            self.assertEqual(first.read_text(), 'one')
            self.assertEqual(second.read_text(), 'two')

    def test_non_utf8_is_not_silently_corrupted(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'a.txt'
            path.write_bytes(b'\xffabc')
            text, error = _read_text_file(path)
            self.assertIsNone(text)
            self.assertIn('UTF-8', error)

    def test_read_paths_expand_environment(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, MEDFARL_TEST_PATH=temp), patch.object(settings, 'unsafe_full_access', True):
            variable = '%MEDFARL_TEST_PATH%' if os.name == 'nt' else '$MEDFARL_TEST_PATH'
            self.assertEqual(_resolve_allowed_path(variable), Path(temp).resolve())

    def test_explicit_coder_full_access_skips_prompts_but_plan_blocks_commands(self):
        with tempfile.TemporaryDirectory() as temp:
            confirm = Mock(return_value=False)
            session = CoderSession(Mock(), temp, confirm=confirm, unsafe_full_access=True)
            self.addCleanup(session.close)
            self.assertTrue(session.full_access)
            self.assertTrue(session.write_file('hello.txt', 'hello')['changed'])
            with patch('core.coder.run_shell', return_value={'returncode': 0, 'stdout': 'ok', 'stderr': '', 'timed_out': False, 'truncated': False}) as run:
                self.assertEqual(session.run_command('echo ok')['exit_code'], 0)
                run.assert_called_once()
            confirm.assert_not_called()
            session.plan_mode = True
            with self.assertRaises(PermissionError):
                session.run_command('echo blocked')


@unittest.skipUnless(os.name == 'nt', 'Windows shells required')
class WindowsShellRegressions(unittest.TestCase):
    def test_powershell_unicode_quotes_and_multiline(self):
        result = run_shell("$x = 'Україна';\nWrite-Output ($x + ' та ' + '\"Windows\"')", 'powershell', Path.cwd(), 10)
        self.assertEqual(result['returncode'], 0)
        self.assertIn('Україна та "Windows"', result['stdout'])

    def test_cmd_multiline_unicode(self):
        result = run_shell('echo перший\necho другий', 'cmd', Path.cwd(), 10)
        self.assertEqual(result['returncode'], 0)
        self.assertIn('перший', result['stdout'])
        self.assertIn('другий', result['stdout'])

    def test_exit_code(self):
        for shell, command in [('powershell', 'exit 7'), ('cmd', 'exit /b 7')]:
            self.assertEqual(run_shell(command, shell, Path.cwd(), 10)['returncode'], 7)

    def test_output_limit(self):
        result = run_shell("Write-Output ('x' * 10000)", 'powershell', Path.cwd(), 10, limit=100)
        self.assertTrue(result['truncated'])
        self.assertEqual(len(result['stdout']), 100)

    def test_timeout_preserves_output(self):
        result = run_shell("Write-Output 'started'; Start-Sleep 20", 'powershell', Path.cwd(), 1)
        self.assertTrue(result['timed_out'])
        self.assertIn('started', result['stdout'])

    def test_timeout_stops_child_process(self):
        import psutil
        result = run_shell("$p = Start-Process powershell.exe -ArgumentList '-NoProfile -Command Start-Sleep 30' -WindowStyle Hidden -PassThru; Write-Output $p.Id; Start-Sleep 30", 'powershell', Path.cwd(), 2)
        self.assertTrue(result['timed_out'])
        pid = int(result['stdout'].strip())
        self.assertFalse(psutil.pid_exists(pid))

    def test_cwd_environment_variable(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, MEDFARL_TEST_CWD=temp), patch.object(settings, 'unsafe_full_access', True):
            result = _run_shell_command('(Get-Location).Path', cwd='%MEDFARL_TEST_CWD%')
            self.assertEqual(result['returncode'], 0)
            self.assertEqual(Path(result['stdout'].strip()), Path(temp))

    def test_invalid_shell_and_cwd_return_errors(self):
        with patch.object(settings, 'unsafe_full_access', True):
            self.assertIn('error', _run_shell_command('echo ok', shell='typo'))
            self.assertIn('error', _run_shell_command('echo ok', cwd='Z:/nonexistent-medfarl'))

    def test_guarded_shell_is_disabled(self):
        with patch.object(settings, 'unsafe_full_access', False):
            self.assertIn('error', _run_shell_command('echo blocked'))

    @unittest.skipUnless(shutil.which('pwsh'), 'PowerShell 7 not installed')
    def test_pwsh(self):
        self.assertEqual(run_shell('exit 0', 'pwsh', Path.cwd(), 10)['returncode'], 0)
