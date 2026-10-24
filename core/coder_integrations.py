"""Explicitly connected MCP tools and approved command hooks."""
from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import re
import subprocess
import tempfile
import threading
import time

import httpx

from core.llm_client import Tool


def expand(value):
    if isinstance(value, str):
        def environment(match):
            if match[1] not in os.environ:
                raise ValueError(f'Не задано змінну середовища {match[1]}')
            return os.environ[match[1]]
        return re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', environment, value)
    if isinstance(value, dict):
        return {k: expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand(v) for v in value]
    return value


class MCPConnection:
    def __init__(self, config: dict, cwd: Path, *, timeout=20):
        self.config = config
        self.timeout = timeout
        self.counter = 0
        self.process = None
        self.http = None
        self.stderr = None
        self.messages = queue.Queue(maxsize=100)
        self.closed = False
        self.session_id = None
        if config.get('command'):
            self.stderr = tempfile.TemporaryFile()
            flags = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {'start_new_session': True}
            self.process = subprocess.Popen([config['command'], *config.get('args', [])], cwd=cwd,
                env={**os.environ, **config.get('env', {})}, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=self.stderr, **flags)
            threading.Thread(target=self._reader, daemon=True).start()
        elif config.get('url', '').startswith(('http://', 'https://')):
            self.http = httpx.Client(timeout=timeout, follow_redirects=False,
                                     headers=config.get('headers', {}))
        else:
            raise ValueError('MCP потребує command/args або HTTP url.')

    def _reader(self):
        try:
            while not self.closed:
                line = self.process.stdout.readline(2 * 1024 * 1024 + 1)
                if not line:
                    break
                if len(line) > 2 * 1024 * 1024:
                    raise ValueError('Завелике MCP-повідомлення.')
                message = json.loads(line.decode('utf-8'))
                if isinstance(message, list):
                    for item in message:
                        self.messages.put_nowait(item)
                else:
                    self.messages.put_nowait(message)
        except (ValueError, OSError, queue.Full) as exc:
            try:
                self.messages.put_nowait({'error': str(exc)})
            except queue.Full:
                pass
        finally:
            try:
                self.messages.put_nowait(None)
            except queue.Full:
                pass

    def _send(self, payload):
        self.process.stdin.write((json.dumps(payload) + '\n').encode('utf-8'))
        self.process.stdin.flush()

    def _match(self, message, identifier):
        if not isinstance(message, dict):
            raise ValueError('Некоректне MCP-повідомлення.')
        if message.get('method') and 'id' in message:
            # Sampling, elicitation and other server-initiated actions are never auto-approved.
            if self.process:
                result = {'result': {}} if message['method'] == 'ping' else {
                    'error': {'code': -32601, 'message': 'Client method not supported'}}
                self._send({'jsonrpc': '2.0', 'id': message['id'], **result})
            return None
        if message.get('id') != identifier:
            return None
        if 'error' in message:
            raise RuntimeError('MCP: ' + str(message['error']))
        return message.get('result', {})

    def request(self, method, params=None, *, notification=False):
        if self.closed:
            raise RuntimeError('MCP-з’єднання закрите.')
        self.counter += 1
        identifier = self.counter
        payload = {'jsonrpc': '2.0', 'method': method, 'params': params or {}}
        if not notification:
            payload['id'] = identifier
        deadline = time.monotonic() + self.timeout
        try:
            if self.process:
                self._send(payload)
                if notification:
                    return {}
                while time.monotonic() < deadline:
                    try:
                        message = self.messages.get(timeout=max(.01, deadline - time.monotonic()))
                    except queue.Empty:
                        break
                    if message is None:
                        raise RuntimeError('MCP-сервер завершив роботу.')
                    result = self._match(message, identifier)
                    if result is not None:
                        return result
            else:
                headers = {'Accept': 'application/json, text/event-stream',
                           'MCP-Protocol-Version': '2025-03-26'}
                if self.session_id:
                    headers['Mcp-Session-Id'] = self.session_id
                with self.http.stream('POST', self.config['url'], json=payload, headers=headers) as response:
                    response.raise_for_status()
                    self.session_id = response.headers.get('mcp-session-id', self.session_id)
                    if notification:
                        return {}
                    if 'text/event-stream' not in response.headers.get('content-type', ''):
                        raw = b''
                        for chunk in response.iter_bytes():
                            raw += chunk
                            if len(raw) > 2 * 1024 * 1024 or time.monotonic() > deadline:
                                raise TimeoutError('Перевищено ліміт MCP-відповіді.')
                        result = self._match(json.loads(raw), identifier)
                        if result is not None:
                            return result
                    else:
                        data = []
                        size = 0
                        for line in response.iter_lines():
                            size += len(line)
                            if size > 2 * 1024 * 1024 or time.monotonic() > deadline:
                                raise TimeoutError('Перевищено ліміт MCP-потоку.')
                            if line.startswith('data:'):
                                data.append(line[5:].lstrip())
                            elif not line and data:
                                result = self._match(json.loads('\n'.join(data)), identifier)
                                data = []
                                if result is not None:
                                    return result
            raise TimeoutError('MCP-сервер не відповів вчасно.')
        except (TimeoutError, OSError, httpx.HTTPError, ValueError):
            self.close()
            raise

    def initialize(self):
        result = self.request('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {},
            'clientInfo': {'name': 'Medfarl', 'version': '0.3.0'}})
        if result.get('protocolVersion') != '2025-03-26':
            raise ValueError('Непідтримувана MCP-версія; потрібна 2025-03-26.')
        self.request('notifications/initialized', notification=True)
        tools = []
        cursor = None
        for _ in range(5):
            page = self.request('tools/list', {'cursor': cursor} if cursor else {})
            tools.extend(page.get('tools', []))
            cursor = page.get('nextCursor')
            if not cursor:
                return tools[:100]
        raise ValueError('Забагато сторінок MCP-інструментів.')

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.process:
            try:
                self.process.stdin.close()
                self.process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                if os.name == 'nt':
                    subprocess.run(['taskkill', '/PID', str(self.process.pid), '/T', '/F'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
                else:
                    import signal
                    try:
                        os.killpg(self.process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                self.process.wait(timeout=3)
            self.process.stdout.close()
            if self.stderr:
                self.stderr.close()
        if self.http:
            self.http.close()


class CoderIntegrations:
    def __init__(self, session):
        self.session = session
        self.connections = {}
        self.tools = {}

    def configuration(self):
        merged = {}
        for relative in ('.mcp.json', '.medfarl/mcp.json'):
            path = self.session._path(relative)
            if path.is_file():
                merged.update(json.loads(self.session._text(path)).get('mcpServers', {}))
        return merged

    def connect(self, name):
        self.session._require_edit()
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}', name):
            raise ValueError('Некоректне ім’я MCP-сервера.')
        raw = self.configuration().get(name)
        if raw is None:
            raise ValueError('Немає такого MCP-сервера в .mcp.json або .medfarl/mcp.json.')
        # Show placeholders, not resolved credentials, in the approval prompt.
        if not self.session.confirm(f'Підключити MCP {name}? Сервер матиме права свого процесу.\n'
                                    f"Команда/URL: {raw.get('command') or raw.get('url')}\n"
                                    f"Аргументи: {json.dumps(raw.get('args', []), ensure_ascii=False)}\n"
                                    'Кожен зовнішній виклик потребуватиме окремого підтвердження.'):
            return {'denied': True}
        config = expand(raw)
        connection = MCPConnection(config, self.session.workspace)
        try:
            definitions = connection.initialize()
            new_tools = []
            for definition in definitions:
                remote = definition['name']
                if not re.fullmatch(r'[A-Za-z0-9_-]{1,60}', remote):
                    raise ValueError('Непідтримуване ім’я MCP-інструмента.')
                schema = definition.get('inputSchema', {'type': 'object', 'properties': {}})
                if schema.get('type') != 'object':
                    raise ValueError('Коренева MCP-схема має бути object.')
                tool_name = f'mcp__{name}__{remote}'
                new_tools.append(Tool(tool_name, str(definition.get('description', remote))[:1000], schema,
                    lambda _remote=remote, _connection=connection, **arguments: self.call(_connection, _remote, arguments)))
        except Exception:
            connection.close()
            raise
        self.disconnect(name)
        self.connections[name] = connection
        self.tools[name] = new_tools
        return {'connected': name, 'tools': [t.name for t in new_tools]}

    def call(self, connection, name, arguments):
        self.session._require_edit()  # External effects cannot be classified as read-only reliably.
        if not self.session.confirm(f'MCP-виклик {name} на підключеному сервері:\n' +
                                    json.dumps(arguments, ensure_ascii=False, indent=2)):
            return {'denied': True}
        return connection.request('tools/call', {'name': name, 'arguments': arguments})

    def disconnect(self, name):
        connection = self.connections.pop(name, None)
        self.tools.pop(name, None)
        if connection:
            connection.close()

    def close(self):
        for name in list(self.connections):
            self.disconnect(name)

    def hooks(self, event, tool_name, arguments, result=None):
        if self.session.plan_mode or self.session.analysis_only:
            return None
        if self.session._turn_allowed is not None and 'run_command' not in self.session._turn_allowed:
            return None
        for relative in ('.claude/settings.json', '.medfarl/settings.json'):
            path = self.session._path(relative)
            if not path.is_file():
                continue
            config = json.loads(self.session._text(path))
            for entry in config.get('hooks', {}).get(event, []):
                if not re.fullmatch(entry.get('matcher', '.*'), tool_name):
                    continue
                for hook in entry.get('hooks', []):
                    if hook.get('type') != 'command':
                        raise ValueError('Підтримуються лише command hooks.')
                    payload = {'hook_event_name': event, 'cwd': str(self.session.workspace),
                               'tool_name': tool_name, 'tool_input': arguments, 'tool_response': result}
                    outcome = self.session.run_command(hook['command'], shell=hook.get('shell', 'powershell'),
                        timeout=min(int(hook.get('timeout', 30)), 60), _input=json.dumps(payload),
                        _approval_context=f'Hook {event} з {relative}, інструмент {tool_name}')
                    if outcome.get('denied') or outcome.get('exit_code') != 0:
                        return {'blocked': True, 'denied': bool(outcome.get('denied')),
                                'error': f'Hook {event} зупинив дію.', 'hook_result': outcome}
        return None
