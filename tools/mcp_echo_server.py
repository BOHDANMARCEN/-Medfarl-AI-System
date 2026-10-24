"""A tiny local MCP demonstration server. Run explicitly through MCP configuration."""
from __future__ import annotations

import json
import sys


def main():
    for line in sys.stdin:
        message = None
        try:
            message = json.loads(line)
            if 'id' not in message:
                continue
            method = message['method']
            if method == 'initialize':
                result = {'protocolVersion': '2025-03-26', 'capabilities': {'tools': {}},
                          'serverInfo': {'name': 'medfarl-demo', 'version': '1.0'}}
            elif method == 'tools/list':
                result = {'tools': [{'name': 'echo', 'description': 'Return the supplied text; no file or network access.',
                    'inputSchema': {'type': 'object', 'properties': {'text': {'type': 'string', 'maxLength': 8000}},
                                    'required': ['text']}}]}
            elif method == 'tools/call' and message.get('params', {}).get('name') == 'echo':
                text = message['params'].get('arguments', {}).get('text', '')
                if not isinstance(text, str) or len(text) > 8000:
                    raise ValueError('text must be a string up to 8000 characters')
                result = {'content': [{'type': 'text', 'text': text}]}
            elif method == 'ping':
                result = {}
            else:
                raise ValueError('Unsupported MCP method')
            reply = {'jsonrpc': '2.0', 'id': message['id'], 'result': result}
        except (ValueError, KeyError, TypeError) as exc:
            reply = {'jsonrpc': '2.0', 'id': message.get('id') if isinstance(message, dict) else None,
                     'error': {'code': -32602, 'message': str(exc)}}
        print(json.dumps(reply, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
