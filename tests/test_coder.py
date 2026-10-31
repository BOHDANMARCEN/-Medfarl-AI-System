from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import main
from core.coder import CoderSession, confirm_action
from core.llm_client import LLMClient


def call(name, arguments, identifier='c1'):
    return {'id': identifier, 'type': 'function',
            'function': {'name': name, 'arguments': json.dumps(arguments)}}


class CoderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.approve = Mock(return_value=True)
        self.client = Mock(model='test-model')
        self.coder = CoderSession(self.client, self.temp.name, confirm=self.approve)

    def test_file_creation_replacement_and_rejection(self):
        self.assertTrue(self.coder.write_file('src/a.py', 'print(1)\n')['changed'])
        self.assertIn('+print(1)', self.approve.call_args.args[0])
        self.coder.replace_text('src/a.py', 'print(1)', 'print(2)')
        self.assertEqual((self.root / 'src/a.py').read_text(), 'print(2)\n')
        self.approve.return_value = False
        self.assertTrue(self.coder.replace_text('src/a.py', 'print(2)', 'print(3)')['denied'])
        self.assertEqual((self.root / 'src/a.py').read_text(), 'print(2)\n')
        with self.assertRaises(ValueError):
            self.coder.write_file('src/a.py', 'overwrite')

    def test_conflicting_external_edit_is_preserved(self):
        target = self.root / 'a.txt'
        target.write_text('before')
        def change_while_approving(_):
            target.write_text('external edit')
            return True
        self.coder.confirm = change_while_approving
        with self.assertRaises(RuntimeError):
            self.coder.replace_text('a.txt', 'before', 'after')
        self.assertEqual(target.read_text(), 'external edit')

    def test_scope_requires_explicit_approval_and_can_be_revoked(self):
        with self.assertRaises(PermissionError):
            self.coder.read_file('../outside.txt')
        self.approve.return_value = False
        self.assertFalse(self.coder.set_full_access(True))
        self.assertFalse(self.coder.full_access)
        self.approve.return_value = True
        self.assertTrue(self.coder.set_full_access(True))
        self.coder.set_full_access(False)
        with self.assertRaises(PermissionError):
            self.coder.write_file('../outside.txt', 'blocked')

    def test_symlink_escape_blocked(self):
        with tempfile.TemporaryDirectory() as outside:
            link = self.root / 'escape'
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest('Symlink creation unavailable for this Windows user')
            with self.assertRaises(PermissionError):
                self.coder.write_file('escape/a.txt', 'blocked')

    def test_search_and_paginated_read(self):
        (self.root / 'a.py').write_text('one\nneedle\nthree\n', encoding='utf-8')
        (self.root / '.git').mkdir()
        (self.root / '.git' / 'secret').write_text('needle')
        self.assertEqual(self.coder.search_text('NEEDLE')['matches'][0]['line'], 2)
        self.assertEqual(self.coder.list_files()['files'], ['a.py'])
        self.assertEqual(self.coder.read_file('a.py', 2, 1)['text'], '2: needle')

    def test_command_denial_never_starts_process_even_with_full_access(self):
        self.coder.full_access = True
        self.approve.return_value = False
        with patch('core.coder.shutil.which', return_value='pwsh'), patch('core.coder.subprocess.Popen') as process:
            self.assertTrue(self.coder.run_command('echo denied')['denied'])
            process.assert_not_called()

    def test_approved_command_runs_in_workspace(self):
        command, shell = ('Write-Output "coder-ok"', 'powershell') if os.name == 'nt' else ('echo coder-ok', 'sh')
        result = self.coder.run_command(command, shell=shell, timeout=10)
        self.assertEqual(result['exit_code'], 0)
        self.assertIn('coder-ok', result['output'])
        self.assertIn(str(self.root.resolve()), self.approve.call_args.args[0])

    def test_timeout_stops_command(self):
        command, shell = ('Start-Sleep -Seconds 20', 'powershell') if os.name == 'nt' else ('sleep 20', 'sh')
        result = self.coder.run_command(command, shell=shell, timeout=1)
        self.assertTrue(result['timed_out'])

    def test_tool_loop_sends_results_back_to_model(self):
        self.client.chat.side_effect = [
            {'assistant_message': {'role': 'assistant', 'content': ''}, 'tool_calls': [
                call('write_file', {'path': 'a.py', 'content': 'print(1)\n'}),
                call('read_file', {'path': 'a.py'}, 'c2')]},
            {'assistant_message': {'role': 'assistant', 'content': 'Готово.'}},
        ]
        self.assertEqual(self.coder.handle_user_message('Створи файл'), 'Готово.')
        messages = self.client.chat.call_args.kwargs['messages']
        self.assertEqual([m['tool_call_id'] for m in messages if m['role'] == 'tool'], ['c1', 'c2'])
        self.assertTrue(json.loads(messages[-2]['content'])['changed'])

    def test_denial_stops_batch_and_model_loop(self):
        self.approve.return_value = False
        self.client.chat.return_value = {'assistant_message': {'role': 'assistant', 'content': ''},
            'tool_calls': [call('write_file', {'path': 'a', 'content': 'x'}),
                           call('write_file', {'path': 'b', 'content': 'x'}, 'c2')]}
        self.coder.handle_user_message('create')
        self.client.chat.assert_called_once()
        self.approve.assert_called_once()
        self.assertFalse((self.root / 'a').exists())
        self.assertFalse((self.root / 'b').exists())

    def test_invalid_arguments_return_error_without_execution(self):
        self.client.chat.side_effect = [
            {'assistant_message': {'role': 'assistant', 'content': ''}, 'tool_calls': [
                {'id': 'bad', 'type': 'function', 'function': {'name': 'write_file', 'arguments': '{bad'}}]},
            {'assistant_message': {'role': 'assistant', 'content': 'Помилка аргументів.'}},
        ]
        self.coder.handle_user_message('create')
        self.approve.assert_not_called()
        self.assertIn('error', json.loads(self.coder.history[-2]['content']))

    def test_coder_launch_uses_project_and_no_diagnostics(self):
        with patch('sys.argv', ['main.py', '--coder', '--workspace', self.temp.name,
                                '--no-warmup', '--skip-healthcheck']), \
                patch('main.configure_console'), patch('main.run_coder_cli') as run, \
                patch('main.MedfarlAgent') as diagnostic:
            main.main()
        self.assertEqual(run.call_args.args[0].workspace, self.root.resolve())
        self.assertFalse(run.call_args.args[0].full_access)
        diagnostic.assert_not_called()

    def test_unsafe_flag_enables_coder_without_reconfirmation(self):
        with patch('sys.argv', ['main.py', '--coder', '--workspace', self.temp.name,
                               '--unsafe-full-access', '--no-warmup', '--skip-healthcheck']), \
                patch('main.configure_console'), patch('builtins.input', return_value='n'), \
                patch('main.run_coder_cli') as run, patch.object(main.settings, 'enable_unsafe_full_access') as enable:
            main.main()
        enable.assert_not_called()
        self.assertTrue(run.call_args.args[0].full_access)
        self.assertTrue(run.call_args.args[0].unsafe_full_access)
        self.assertTrue(run.call_args.args[0].confirm("requested command"))

    def test_eof_is_denial(self):
        with patch('builtins.input', side_effect=EOFError):
            self.assertFalse(confirm_action('preview'))


class StreamingToolTests(unittest.TestCase):
    def test_fragmented_multiple_tool_calls_preserve_arguments(self):
        chunks = [
            {'tool_calls': [{'index': 0, 'id': 'c1', 'function': {'name': 'read_file', 'arguments': '{"pa'}}]},
            {'tool_calls': [{'index': 0, 'function': {'arguments': 'th":"a.py"}'}},
                            {'index': 1, 'id': 'c2', 'function': {'name': 'list_files', 'arguments': '{}'}}]},
        ]
        response = Mock()
        response.iter_lines.return_value = [
            'data: ' + json.dumps({'choices': [{'delta': delta}]}) for delta in chunks
        ] + ['data: [DONE]']
        with patch('core.llm_client.httpx.stream') as stream:
            stream.return_value.__enter__.return_value = response
            result = LLMClient('http://localhost:11434', 'test').chat([], stream=True)
        self.assertEqual(result['tool_call']['arguments'], {'path': 'a.py'})
        self.assertEqual([c['id'] for c in result['tool_calls']], ['c1', 'c2'])
        self.assertEqual(json.loads(result['tool_calls'][0]['function']['arguments']), {'path': 'a.py'})


if __name__ == '__main__':
    with contextlib.redirect_stdout(io.StringIO()):
        unittest.main()
