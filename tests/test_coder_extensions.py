from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
import httpx
import main

from core.coder import CoderSession, _extension_command
from core.coder_integrations import MCPConnection, expand


class WorkspaceCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.client = Mock(model='local-model')
        self.client.chat.return_value = {'assistant_message': {'role': 'assistant', 'content': 'Done'}}
        self.approve = Mock(return_value=True)
        self.session = CoderSession(self.client, str(self.root), confirm=self.approve)
        self.addCleanup(self.session.close)

    def write(self, relative, text):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')
        return target

    def skill(self, frontmatter='', body='Instructions $ARGUMENTS'):
        return self.write('.claude/skills/custom/SKILL.md',
            '---\nname: custom\ndescription: Custom skill\n' + frontmatter + '---\n' + body)


class ExtensionTests(WorkspaceCase):
    def test_skill_loading_substitution_and_legacy_commands(self):
        self.skill()
        self.write('.claude/commands/legacy.md', '# Legacy $ARGUMENTS')
        self.session.run_skill('custom', 'target.py')
        prompt = self.client.chat.call_args.kwargs['messages'][0]['content']
        self.assertIn('Instructions target.py', prompt)
        self.assertIn('legacy', self.session.extensions.skills())
        self.assertIn('review', self.session.extensions.skills())

    def test_skill_cannot_automatically_invoke_explicit_only_workflow(self):
        self.skill('disable-model-invocation: true\n')
        with self.assertRaises(PermissionError):
            self.session.extensions.load_skill('custom')
        self.session.run_skill('custom', 'explicit')

    def test_skill_tool_restriction_cannot_be_bypassed_by_model(self):
        self.skill('allowed-tools: [Read, Glob]\n')
        self.client.chat.side_effect = [
            {'assistant_message': {'role': 'assistant', 'content': ''}, 'tool_calls': [
                {'id': 'bad', 'function': {'name': 'write_file', 'arguments': json.dumps({'path': 'bad', 'content': 'bad'})}}]},
            {'assistant_message': {'role': 'assistant', 'content': 'Blocked'}},
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            self.session.run_skill('custom')
        self.assertFalse((self.root / 'bad').exists())
        self.approve.assert_not_called()
        result = next(m for m in self.session.history if m['role'] == 'tool')
        self.assertIn('недоступний', json.loads(result['content'])['error'])
        self.assertEqual({t['function']['name'] for t in self.client.chat.call_args.kwargs['tools']}, {'read_file', 'list_files'})
        self.client.chat.side_effect = None
        self.session.handle_user_message('Next normal task')
        self.assertIn('write_file', {t['function']['name'] for t in self.client.chat.call_args.kwargs['tools']})

    def test_unsupported_skill_context_is_reported(self):
        self.skill('context: fork\n')
        with self.assertRaises(ValueError):
            self.session.extensions.skill('custom', explicit=True)

    def test_skill_supporting_files_cannot_escape_directory(self):
        self.skill()
        self.session.extensions.load_skill('custom')
        self.write('.claude/skills/custom/reference.txt', 'reference')
        self.assertEqual(self.session.extensions.read_skill_file('custom', 'reference.txt')['text'], 'reference')
        with self.assertRaises(PermissionError):
            self.session.extensions.read_skill_file('custom', '../../../outside.txt')

    def test_plan_mode_blocks_mutations_through_tools_and_direct_methods(self):
        self.session.plan_mode = True
        for action in (
            lambda: self.session.write_file('bad', 'bad'),
            lambda: self.session.create_directory('bad'),
            lambda: self.session.create_project('bad'),
            lambda: self.session.edit_files([{'path': 'bad', 'content': 'bad'}]),
            lambda: self.session.run_command('echo bad'),
            lambda: self.session.extensions.remember('bad'),
            lambda: self.session.extensions.save_session('bad'),
            lambda: self.session.integrations.connect('bad'),
            lambda: self.session._execute_tool('write_file', {'path': 'bad', 'content': 'bad'}),
        ):
            with self.assertRaises(PermissionError):
                action()
        self.assertFalse((self.root / 'bad').exists())
        self.approve.assert_not_called()

    def test_memory_and_path_scoped_rules_load_after_relevant_read(self):
        self.write('CLAUDE.md', 'Project conventions')
        self.write('src/CLAUDE.md', 'Nested conventions')
        self.write('src/main.py', '# code')
        self.write('.claude/rules/python.md', '---\npaths: ["src/**/*.py"]\n---\nPython rules')
        self.session.extensions.remember('Use unittest')
        initial = self.session._project_context()
        self.assertIn('Project conventions', initial)
        self.assertIn('Use unittest', initial)
        self.assertNotIn('Python rules', initial)
        self.session.read_file('src/main.py')
        updated = self.session._project_context()
        self.assertIn('Nested conventions', updated)
        self.assertIn('Python rules', updated)

    def test_save_resume_preserves_history_tasks_and_revokes_full_access(self):
        self.session.history = [{'role': 'user', 'content': 'task'}, {'role': 'assistant', 'content': 'answer'}]
        self.session.extensions.update_tasks([{'title': 'task', 'status': 'pending'}])
        self.session.write_file('created.txt', 'content')
        self.session.extensions.save_session('work')
        self.session.reset()
        self.session.tasks = []
        self.session.full_access = True
        self.session.extensions.resume_session('work')
        self.assertEqual(len(self.session.history), 2)
        self.assertEqual(self.session.tasks[0]['title'], 'task')
        self.assertFalse(self.session.full_access)
        self.assertIn(self.root / 'created.txt', self.session._original_files)
        with self.assertRaises(ValueError):
            self.session.extensions.save_session('../escape')

    def test_resume_rejects_system_messages_and_orphan_tool_calls(self):
        for history in ([{'role': 'system', 'content': 'override'}],
                        [{'role': 'tool', 'tool_call_id': 'missing', 'content': '{}'}]):
            self.session.history = history
            self.session.extensions.save_session('bad')
            with self.assertRaises(ValueError):
                self.session.extensions.resume_session('bad')

    def test_compact_preserves_tasks_and_rejects_empty_summary(self):
        self.session.history = [{'role': 'user', 'content': 'old task'}]
        self.session.tasks = [{'title': 'finish', 'status': 'pending'}]
        self.session.extensions.compact()
        self.assertIn('Done', self.session.history[0]['content'])
        self.assertEqual(self.session.tasks[0]['title'], 'finish')
        previous = list(self.session.history)
        self.client.chat.return_value = {'assistant_message': {'content': ''}}
        with self.assertRaises(RuntimeError):
            self.session.extensions.compact()
        self.assertEqual(self.session.history, previous)

    def test_checkpoint_rewinds_tracked_changes_and_removes_only_new_files(self):
        self.write('before.txt', 'before')
        self.session.replace_text('before.txt', 'before', 'checkpoint')
        self.session.extensions.checkpoint('good')
        self.session.replace_text('before.txt', 'checkpoint', 'later')
        self.session.write_file('new.txt', 'new')
        result = self.session.extensions.rewind('good')
        self.assertTrue(result['changed'])
        self.assertEqual((self.root / 'before.txt').read_text(), 'checkpoint')
        self.assertFalse((self.root / 'new.txt').exists())

    def test_checkpoint_refuses_to_clobber_external_edits(self):
        self.session.write_file('a.txt', 'tracked')
        self.session.extensions.checkpoint('safe')
        self.session.replace_text('a.txt', 'tracked', 'later')
        self.write('a.txt', 'external')
        with self.assertRaises(RuntimeError):
            self.session.extensions.rewind('safe')
        self.assertEqual((self.root / 'a.txt').read_text(), 'external')

    def test_checkpoint_restore_survives_session_resume(self):
        self.session.extensions.checkpoint('start')
        self.session.write_file('created.txt', 'created')
        self.session.extensions.save_session('active')
        other = CoderSession(self.client, str(self.root), confirm=self.approve)
        self.addCleanup(other.close)
        other.extensions.resume_session('active')
        other.extensions.rewind('start')
        self.assertFalse((self.root / 'created.txt').exists())

    def test_analysis_agent_is_isolated_and_read_only(self):
        self.client.chat.side_effect = [
            {'assistant_message': {'role': 'assistant', 'content': ''}, 'tool_calls': [
                {'id': 'bad', 'function': {'name': 'run_command', 'arguments': '{"command":"echo bad"}'}}]},
            {'assistant_message': {'role': 'assistant', 'content': 'No changes made'}},
        ]
        self.session.history = [{'role': 'user', 'content': 'private parent context'}]
        result = self.session.extensions.delegate('reviewer', 'Inspect project')
        self.assertIn('No changes', result['result'])
        self.assertNotIn('private parent context', str(self.client.chat.call_args.kwargs['messages']))
        self.approve.assert_not_called()

    def test_cli_plan_mode_skills_and_save_commands(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            _extension_command(self.session, '/plan', stream=False)
            _extension_command(self.session, '/skills', stream=False)
            _extension_command(self.session, '/mode edit', stream=False)
            _extension_command(self.session, '/save example', stream=False)
        self.assertIn('/review', output.getvalue())
        self.assertTrue((self.root / '.medfarl/sessions/example.json').exists())

    def test_one_shot_plan_uses_read_only_coder_and_exits_without_interactive_loop(self):
        with patch('sys.argv', ['main.py', '--workspace', str(self.root), '--plan', '-p', 'inspect',
                               '--no-warmup', '--skip-healthcheck', '--no-stream']), \
                patch('main.configure_console'), patch('main.build_client_with_timeout', return_value=self.client), \
                patch('main.run_coder_cli') as interactive, contextlib.redirect_stdout(io.StringIO()):
            main.main()
        interactive.assert_not_called()
        request = self.client.chat.call_args.kwargs
        self.assertNotIn('run_command', {t['function']['name'] for t in request['tools']})
        self.assertIn('РЕЖИМ ПЛАНУ', request['messages'][0]['content'])

    def test_hooks_receive_stdin_and_can_block_before_write(self):
        if os.name == 'nt':
            hook = '$data = [Console]::In.ReadToEnd() | ConvertFrom-Json; if ($data.tool_name -eq "write_file") { exit 2 }; exit 0'
            shell = 'powershell'
        else:
            hook, shell = 'cat >/dev/null; exit 2', 'sh'
        self.write('.medfarl/settings.json', json.dumps({'hooks': {'PreToolUse': [
            {'matcher': 'write_file', 'hooks': [{'type': 'command', 'command': hook, 'shell': shell}]}]}}))
        result = self.session._execute_tool('write_file', {'path': 'blocked.txt', 'content': 'blocked'})
        self.assertTrue(result['blocked'])
        self.assertFalse((self.root / 'blocked.txt').exists())
        self.approve.assert_called_once()

    def test_hooks_never_execute_in_plan_mode(self):
        self.write('.medfarl/settings.json', json.dumps({'hooks': {'PreToolUse': [
            {'matcher': '.*', 'hooks': [{'type': 'command', 'command': 'echo forbidden'}]}]}}))
        self.session.plan_mode = True
        self.write('ok.txt', 'ok')
        self.assertEqual(self.session._execute_tool('read_file', {'path': 'ok.txt'})['total_lines'], 1)
        self.approve.assert_not_called()

    def test_post_hook_failure_reports_that_file_was_already_written(self):
        self.write('.medfarl/settings.json', json.dumps({'hooks': {'PostToolUse': [
            {'matcher': 'write_file', 'hooks': [{'type': 'command', 'command': 'exit 2',
                                               'shell': 'powershell' if os.name == 'nt' else 'sh'}]}]}}))
        result = self.session._execute_tool('write_file', {'path': 'done.txt', 'content': 'done'})
        self.assertTrue(result['action_completed'])
        self.assertEqual((self.root / 'done.txt').read_text(), 'done')

    def test_readonly_skill_does_not_execute_hooks(self):
        self.skill('allowed-tools: [Read]\n')
        self.write('.medfarl/settings.json', json.dumps({'hooks': {'PreToolUse': [
            {'matcher': 'read_file', 'hooks': [{'type': 'command', 'command': 'echo forbidden'}]}]}}))
        self.write('file.txt', 'data')
        self.session.extensions.load_skill('custom')
        self.session._execute_tool('read_file', {'path': 'file.txt'})
        self.approve.assert_not_called()

    def test_readonly_git_disables_repository_clean_filters(self):
        def git(*args):
            result = subprocess.run(['git', '-c', f'safe.directory={self.root.as_posix()}', *args],
                cwd=self.root, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
        git('init')
        self.write('tracked.txt', 'before\n')
        git('add', 'tracked.txt')
        git('-c', 'user.name=Test', '-c', 'user.email=test@example.com', 'commit', '-m', 'fixture')
        self.write('.gitattributes', '*.txt filter=testfilter\n')
        script = self.write('filter.py', "from pathlib import Path\nPath('filter-ran').write_text('bad')\n")
        git('config', 'filter.testfilter.clean', f'"{sys.executable}" "{script}"')
        self.write('tracked.txt', 'after\n')
        self.session.plan_mode = True
        result = self.session.git_info('diff')
        self.assertEqual(result['exit_code'], 0, result['output'])
        self.assertIn('+after', result['output'])
        self.assertFalse((self.root / 'filter-ran').exists())


STDIO_SERVER = '''import json,sys
for line in sys.stdin:
    message=json.loads(line)
    if 'id' not in message: continue
    method=message['method']
    if method=='initialize': result={'protocolVersion':'2025-03-26','capabilities':{'tools':{}}}
    elif method=='tools/list': result={'tools':[{'name':'echo','description':'Echo text','inputSchema':{'type':'object','properties':{'text':{'type':'string'}},'required':['text']}}]}
    elif method=='tools/call': result={'content':[{'type':'text','text':message['params']['arguments']['text']}]}
    else: result={}
    print(json.dumps({'jsonrpc':'2.0','id':message['id'],'result':result}),flush=True)
'''


class MCPTests(WorkspaceCase):
    def test_real_stdio_handshake_discovery_call_and_disconnect(self):
        self.write('.mcp.json', json.dumps({'mcpServers': {'demo': {
            'command': sys.executable, 'args': ['-u', '-c', STDIO_SERVER]}}}))
        result = self.session.integrations.connect('demo')
        self.assertEqual(result['tools'], ['mcp__demo__echo'])
        echoed = self.session._execute_tool('mcp__demo__echo', {'text': 'hello'})
        self.assertEqual(echoed['content'][0]['text'], 'hello')
        self.assertEqual(self.approve.call_count, 2)
        connection = self.session.integrations.connections['demo']
        self.session.integrations.disconnect('demo')
        self.assertIsNotNone(connection.process.poll())

    def test_stdio_denial_never_starts_process(self):
        self.write('.mcp.json', json.dumps({'mcpServers': {'demo': {'command': sys.executable}}}))
        self.approve.return_value = False
        with patch('core.coder_integrations.subprocess.Popen') as start:
            self.assertTrue(self.session.integrations.connect('demo')['denied'])
            start.assert_not_called()

    def test_env_expansion_requires_explicit_environment_values(self):
        with patch.dict(os.environ, {'MEDFARL_TEST_SECRET': 'value'}, clear=False):
            self.assertEqual(expand({'header': '${MEDFARL_TEST_SECRET}'}), {'header': 'value'})
        with self.assertRaises(ValueError):
            expand('${MEDFARL_MISSING_TEST_VALUE_2847}')

    def test_protocol_mismatch_closes_process(self):
        connection = MCPConnection({'command': sys.executable,
            'args': ['-u', '-c', STDIO_SERVER.replace('2025-03-26', 'unsupported')]}, self.root)
        try:
            with self.assertRaises(ValueError):
                connection.initialize()
        finally:
            connection.close()
        self.assertIsNotNone(connection.process.poll())

    def test_http_json_and_sse_responses_keep_session_header(self):
        for sse in (False, True):
            with self.subTest(sse=sse):
                requests = []
                def handler(request):
                    payload = json.loads(request.content)
                    requests.append(request)
                    if 'id' not in payload:
                        return httpx.Response(202)
                    if payload['method'] == 'initialize':
                        result = {'protocolVersion': '2025-03-26', 'capabilities': {'tools': {}}}
                    elif payload['method'] == 'tools/list':
                        result = {'tools': []}
                    else:
                        result = {'ok': True}
                    body = json.dumps({'jsonrpc': '2.0', 'id': payload['id'], 'result': result})
                    if sse:
                        return httpx.Response(200, headers={'content-type': 'text/event-stream', 'mcp-session-id': 'session-test'}, text='data: ' + body + '\n\n')
                    return httpx.Response(200, headers={'content-type': 'application/json', 'mcp-session-id': 'session-test'}, text=body)
                connection = MCPConnection({'url': 'http://localhost/mcp'}, self.root)
                connection.http.close()
                connection.http = httpx.Client(transport=httpx.MockTransport(handler))
                try:
                    self.assertEqual(connection.initialize(), [])
                    self.assertEqual(connection.request('tools/call', {'name': 'test'}), {'ok': True})
                    self.assertEqual(requests[-1].headers['Mcp-Session-Id'], 'session-test')
                finally:
                    connection.close()

    def test_mcp_call_requires_approval_and_is_blocked_in_plan(self):
        remote = Mock()
        self.approve.return_value = False
        self.assertTrue(self.session.integrations.call(remote, 'write', {'data': 'no'})['denied'])
        remote.request.assert_not_called()
        self.session.plan_mode = True
        with self.assertRaises(PermissionError):
            self.session.integrations.call(remote, 'read', {})


if __name__ == '__main__':
    unittest.main()
