"""Non-interactive shell execution with bounded output and process-tree cleanup."""
from __future__ import annotations

import base64
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import psutil


def run_shell(command: str, shell: str, cwd: str | Path, timeout: int,
              *, input_text: str | None = None, limit: int = 16000) -> dict:
    if shell not in {'powershell', 'pwsh', 'cmd', 'sh'}:
        raise ValueError(f'Unknown shell: {shell}')
    if not isinstance(command, str) or not command.strip():
        raise ValueError('Command must not be empty.')
    executable = shutil.which({'powershell': 'powershell.exe', 'cmd': 'cmd.exe'}.get(shell, shell))
    if not executable:
        raise ValueError(f'Shell is not installed: {shell}')
    directory = Path(os.path.expandvars(str(cwd))).expanduser().resolve()
    if not directory.is_dir():
        raise ValueError(f'Working directory not found: {directory}')
    flags = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {'start_new_session': True}
    with tempfile.TemporaryDirectory(prefix='medfarl-shell-') as temp:
        if shell in {'powershell', 'pwsh'}:
            script = ("[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
                      "$OutputEncoding = [Console]::OutputEncoding;\n" + command)
            encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
            args = [executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded]
        elif shell == 'cmd':
            # A batch file preserves multiline blocks, labels, and percent expansion.
            script_path = Path(temp) / 'command.cmd'
            script_path.write_text('@echo off\nchcp 65001 >nul\n' + command + '\n', encoding='utf-8')
            args = [executable, '/d', '/c', str(script_path)]
        else:
            args = [executable, '-c', command]
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err, tempfile.TemporaryFile() as inp:
            if input_text is not None:
                inp.write(input_text.encode('utf-8'))
                inp.seek(0)
            process = subprocess.Popen(args, cwd=directory, stdin=inp if input_text is not None else subprocess.DEVNULL,
                                       stdout=out, stderr=err, **flags)
            timed_out = False
            try:
                process.wait(timeout=max(1, min(int(timeout), 3600)))
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
                try:
                    children = psutil.Process(process.pid).children(recursive=True)
                except psutil.NoSuchProcess:
                    children = []
                try:
                    if os.name == 'nt':
                        subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       creationflags=subprocess.CREATE_NO_WINDOW, timeout=10)
                    else:
                        os.killpg(process.pid, signal.SIGKILL)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait()
                    # Windows termination is asynchronous; also reap descendants
                    # that outlived their parent before taskkill traversed the tree.
                    for child in children:
                        try:
                            child.kill()
                        except psutil.NoSuchProcess:
                            pass
                    psutil.wait_procs(children, timeout=5)
                if isinstance(exc, KeyboardInterrupt):
                    raise
                timed_out = True
            out.seek(0)
            err.seek(0)
            stdout, stderr = out.read(limit + 1), err.read(limit + 1)
    return {'returncode': process.returncode, 'timed_out': timed_out,
            'stdout': stdout[:limit].decode('utf-8', errors='replace'),
            'stderr': stderr[:limit].decode('utf-8', errors='replace'),
            'truncated': len(stdout) > limit or len(stderr) > limit}
