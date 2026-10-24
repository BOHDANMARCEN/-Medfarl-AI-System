from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import main
from core.coder import CoderSession, _workspace_command


class ProjectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.approve = Mock(return_value=True)
        self.client = Mock(model='test-model')
        self.coder = CoderSession(self.client, str(self.root), confirm=self.approve)

    def test_python_project_runs_tests_and_uses_one_approval(self):
        result = self.coder.create_project('my app', template='python')
        self.assertTrue(result['changed'])
        self.approve.assert_called_once()
        self.assertEqual(len(result['files']), 4)
        project = self.root / 'my app'
        checked = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests'],
                                 cwd=project, capture_output=True, text=True, timeout=15)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        started = subprocess.run([sys.executable, 'main.py', '--name', 'Medfarl'], cwd=project,
                                 capture_output=True, timeout=15)
        self.assertEqual(started.returncode, 0, started.stderr)
        self.assertIn('Medfarl', started.stdout.decode('utf-8', errors='replace'))

    def test_web_project_links_to_created_assets(self):
        self.coder.create_project('site', template='web')
        html = (self.root / 'site/index.html').read_text(encoding='utf-8')
        self.assertIn('href="styles.css"', html)
        self.assertIn('src="app.js"', html)
        self.assertTrue((self.root / 'site/styles.css').is_file())
        self.assertTrue((self.root / 'site/app.js').is_file())

    def test_custom_project_creates_nested_and_empty_files(self):
        result = self.coder.create_project('custom', files=[
            {'path': 'src/app.txt', 'content': 'custom content'},
            {'path': 'tests/__init__.py', 'content': ''},
        ])
        self.assertTrue(result['changed'])
        self.assertEqual((self.root / 'custom/src/app.txt').read_text(), 'custom content')
        self.assertEqual((self.root / 'custom/tests/__init__.py').read_bytes(), b'')

    def test_invalid_project_has_no_side_effects(self):
        invalid_entries = [
            [{'path': '../escape.txt', 'content': 'bad'}],
            [{'path': str(self.root / 'escape.txt'), 'content': 'bad'}],
            [{'path': '.', 'content': 'bad'}],
            [{'path': '.git/config', 'content': 'bad'}],
            [{'path': 'same', 'content': '1'}, {'path': 'same', 'content': '2'}],
            [{'path': 'same', 'content': '1'}, {'path': 'same/child', 'content': '2'}],
        ]
        for files in invalid_entries:
            with self.subTest(files=files), self.assertRaises((PermissionError, ValueError)):
                self.coder.create_project('bad', files=files)
            self.assertFalse((self.root / 'bad').exists())
        self.approve.assert_not_called()

    def test_denied_project_does_not_create_parent_directories(self):
        self.approve.return_value = False
        self.assertTrue(self.coder.create_project('nested/project', 'python')['denied'])
        self.assertFalse((self.root / 'nested').exists())

    def test_existing_project_is_preserved(self):
        project = self.root / 'app'
        project.mkdir()
        (project / 'existing.txt').write_text('user work')
        with self.assertRaises(ValueError):
            self.coder.create_project('app', 'web')
        self.assertEqual((project / 'existing.txt').read_text(), 'user work')
        self.approve.assert_not_called()

    def test_full_rewrite_requires_current_file_hash(self):
        target = self.root / 'a.py'
        target.write_text('before\n')
        sha = self.coder.read_file('a.py')['sha256']
        self.coder.write_file('a.py', 'after\n', expected_sha256=sha)
        self.assertEqual(target.read_text(), 'after\n')
        with self.assertRaises(ValueError):
            self.coder.write_file('a.py', 'clobber', expected_sha256=sha)
        self.assertEqual(target.read_text(), 'after\n')

    def test_batch_edit_preview_and_diff_track_original_across_reset(self):
        target = self.root / 'a.py'
        target.write_text('before\n')
        sha = self.coder.read_file('a.py')['sha256']
        result = self.coder.edit_files([
            {'path': 'a.py', 'content': 'after\n', 'expected_sha256': sha},
            {'path': 'src/new.py', 'content': 'created\n'},
        ])
        self.assertEqual(len(result['files']), 2)
        self.approve.assert_called_once()
        self.coder.replace_text('a.py', 'after', 'final')
        self.coder.reset()
        diff = self.coder.show_diff()
        self.assertIn('-before', diff)
        self.assertIn('+final', diff)
        self.assertIn('+created', diff)
        self.assertNotIn('+after', diff)

    def test_late_conflict_prevents_entire_batch_write(self):
        target = self.root / 'existing.txt'
        target.write_text('before')
        sha = self.coder.read_file('existing.txt')['sha256']
        def change_during_approval(_):
            target.write_text('user changed it')
            return True
        self.coder.confirm = change_during_approval
        with self.assertRaises(RuntimeError):
            self.coder.edit_files([
                {'path': 'new.txt', 'content': 'new'},
                {'path': 'existing.txt', 'content': 'after', 'expected_sha256': sha},
            ])
        self.assertFalse((self.root / 'new.txt').exists())
        self.assertEqual(target.read_text(), 'user changed it')

    def test_io_failure_reports_already_written_files(self):
        save = self.coder._save
        def fail_second(target, content, original):
            if target.name == 'b':
                raise OSError('simulated disk failure')
            save(target, content, original)
        with patch.object(self.coder, '_save', side_effect=fail_second):
            result = self.coder.edit_files([{'path': 'a', 'content': 'one'}, {'path': 'b', 'content': 'two'}])
        self.assertTrue(result['partial'])
        self.assertEqual(result['files'], [str(self.root / 'a')])
        self.assertEqual((self.root / 'a').read_text(), 'one')
        self.assertFalse((self.root / 'b').exists())

    def test_command_cwd_is_project_subdirectory_and_outside_is_blocked(self):
        (self.root / 'subproject').mkdir()
        command, shell = ('(Get-Location).Path', 'powershell') if os.name == 'nt' else ('pwd', 'sh')
        result = self.coder.run_command(command, shell=shell, cwd='subproject', timeout=10)
        self.assertEqual(result['exit_code'], 0)
        self.assertIn('subproject', result['output'])
        with self.assertRaises(PermissionError):
            self.coder.run_command('echo blocked', cwd='..')

    def test_empty_directory_creation_and_denial(self):
        self.assertTrue(self.coder.create_directory('src/empty')['created'])
        self.approve.return_value = False
        self.assertTrue(self.coder.create_directory('blocked')['denied'])
        self.assertFalse((self.root / 'blocked').exists())

    def test_new_command_creates_and_selects_project_with_spaces(self):
        with contextlib.redirect_stdout(io.StringIO()):
            _workspace_command(self.coder, '/new python "My App"')
        self.assertEqual(self.coder.workspace, self.root / 'My App')
        self.approve.assert_called_once()
        self.assertIn('+import argparse', self.coder.show_diff())
        self.assertFalse(self.coder.full_access)

    def test_open_changes_workspace_only_after_confirmation_and_revokes_full_access(self):
        self.coder.full_access = True
        self.coder.history = [{'role': 'user', 'content': 'old project'}]
        with tempfile.TemporaryDirectory() as other:
            self.approve.return_value = False
            self.assertFalse(self.coder.open_workspace(other))
            self.assertEqual(self.coder.workspace, self.root)
            self.approve.return_value = True
            self.assertTrue(self.coder.open_workspace(other))
            self.assertEqual(self.coder.workspace, Path(other).resolve())
        self.assertFalse(self.coder.full_access)
        self.assertEqual(self.coder.history, [])

    def test_missing_workspace_is_created_only_after_approval(self):
        location = self.root / 'new workspace'
        with self.assertRaises(PermissionError):
            CoderSession(self.client, str(location), confirm=lambda _: False)
        self.assertFalse(location.exists())
        created = CoderSession(self.client, str(location), confirm=lambda _: True)
        self.assertEqual(created.workspace, location)
        self.assertTrue(location.is_dir())

    def test_project_instructions_are_loaded_and_tools_have_structured_schemas(self):
        (self.root / 'QWEN.md').write_text('Use unittest for this project.', encoding='utf-8')
        self.client.chat.return_value = {'assistant_message': {'role': 'assistant', 'content': 'Ready'}}
        self.coder.handle_user_message('Inspect')
        request = self.client.chat.call_args.kwargs
        self.assertIn('Use unittest', request['messages'][0]['content'])
        schema = next(t['function']['parameters'] for t in request['tools'] if t['function']['name'] == 'edit_files')
        self.assertEqual(schema['properties']['changes']['items']['required'], ['path', 'content'])

    def test_project_tool_cycle_creates_and_edits_files_without_mocks_for_disk(self):
        def tool_response(name, args, identifier):
            return {'assistant_message': {'role': 'assistant', 'content': ''}, 'tool_calls': [
                {'id': identifier, 'type': 'function', 'function': {'name': name, 'arguments': json.dumps(args)}}]}
        self.client.chat.side_effect = [
            tool_response('create_project', {'path': 'calc', 'files': [
                {'path': 'main.py', 'content': 'print(1 + 1)\n'},
                {'path': 'README.md', 'content': '# Calculator\n'}]}, 'create'),
            tool_response('replace_text', {'path': 'calc/main.py', 'old_text': '1 + 1', 'new_text': '2 + 2'}, 'edit'),
            {'assistant_message': {'role': 'assistant', 'content': 'Created and edited.'}},
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            self.coder.handle_user_message('Create calculator and update it')
        self.assertEqual((self.root / 'calc/main.py').read_text(), 'print(2 + 2)\n')
        self.assertTrue((self.root / 'calc/README.md').exists())

    def test_empty_final_reply_reports_actual_tool_outcomes(self):
        self.client.chat.side_effect = [
            {'assistant_message': {'role': 'assistant', 'content': ''}, 'tool_calls': [
                {'id': 'write', 'type': 'function', 'function': {'name': 'write_file',
                 'arguments': json.dumps({'path': 'a.txt', 'content': 'saved'})}},
                {'id': 'fail', 'type': 'function', 'function': {'name': 'read_file',
                 'arguments': json.dumps({'path': 'missing.txt'})}},
            ]},
            {'assistant_message': {'role': 'assistant', 'content': ''}},
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            reply = self.coder.handle_user_message('Create a file', stream=True)
        self.assertIn('write_file: збережено', reply)
        self.assertIn('read_file: помилка:', reply)
        self.assertFalse(self.coder.last_response_streamed())
        self.assertEqual(self.coder.history[-1]['content'], reply)
        self.assertEqual((self.root / 'a.txt').read_text(), 'saved')

    def test_coder_opens_from_chat_and_returns_to_chat(self):
        inputs = [f'/coder "{self.root}"', '/quit', '/status', '/quit']
        with patch('sys.argv', ['main.py', '--no-warmup', '--skip-healthcheck']), \
                patch.object(main.settings, 'unsafe_full_access', False), \
                patch('main.configure_console'), patch('ui.cli.prompt_user', side_effect=inputs[1:2]), \
                patch('main.prompt_user', side_effect=[inputs[0], *inputs[2:]]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            main.main()
        self.assertIn('Medfarl', output.getvalue())
        self.assertIn('mode: direct chat', output.getvalue())


if __name__ == '__main__':
    unittest.main()
