from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from config import settings
from core.lib_inspector import LibInspector
from core.llm_client import Tool
from core.system_scanner import SystemScanner


SAFE_COMMANDS: dict[str, list[str]] = {
    "uptime": ["uptime"],
}

if platform.system() != "Windows":
    SAFE_COMMANDS.update(
        {
            "df_h": ["df", "-h"],
            "free_h": ["free", "-h"],
            "ip_addr": ["ip", "addr"],
            "ip_route": ["ip", "route"],
            "journal_errors": ["journalctl", "-p", "3", "-xb", "--no-pager"],
            "lsblk": ["lsblk", "-o", "NAME,SIZE,FSTYPE,MOUNTPOINT"],
        }
    )
else:
    SAFE_COMMANDS.update(
        {
            "systeminfo": ["systeminfo"],
            "ipconfig": ["ipconfig", "/all"],
            "route_print": ["route", "print"],
        }
    )


def build_tools(
    scanner: SystemScanner | None = None, inspector: LibInspector | None = None
) -> list[Tool]:
    scanner = scanner or SystemScanner()
    inspector = inspector or LibInspector()

    return [
        Tool(
            name="get_system_snapshot",
            description="Get current hardware state: CPU, RAM, GPU, disk, temperatures, top processes, network. Use this first when diagnosing any issue.",
            parameters={"type": "object", "properties": {}, "required": []},
            fn=lambda: scanner.to_dict(),
        ),
        Tool(
            name="get_installed_pip_packages",
            description="List all Python packages installed via pip. Returns names and versions.",
            parameters={"type": "object", "properties": {}, "required": []},
            fn=lambda: [
                {"name": package.name, "version": package.version}
                for package in inspector.pip_packages()
            ],
        ),
        Tool(
            name="get_pip_outdated",
            description="Check which Python pip packages are outdated. Slow - use on demand.",
            parameters={"type": "object", "properties": {}, "required": []},
            fn=inspector.pip_outdated,
        ),
        Tool(
            name="get_system_packages_summary",
            description="Summary of system-level installed packages and any failed services.",
            parameters={"type": "object", "properties": {}, "required": []},
            fn=inspector.summary_dict,
        ),
        Tool(
            name="get_failed_services",
            description="List system services that are in a failed state.",
            parameters={"type": "object", "properties": {}, "required": []},
            fn=lambda: [service.__dict__ for service in inspector.failed_services()],
        ),
        Tool(
            name="read_file",
            description="Read a text file from an allowed root on disk.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute or allowed relative file path to read",
                    },
                    "max_lines": {
                        "type": "integer",
                        "description": "Max lines to return (default 200)",
                    },
                },
                "required": ["path"],
            },
            fn=_read_file,
        ),
        Tool(
            name="list_directory",
            description="List files and folders in an allowed directory.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path to list"},
                },
                "required": ["path"],
            },
            fn=_list_directory,
        ),
        Tool(
            name="run_safe_command",
            description="Run a shell command from a pre-approved read-only allowlist by key.",
            parameters={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "enum": sorted(SAFE_COMMANDS.keys()),
                        "description": "Safe command key to run",
                    }
                },
                "required": ["command"],
            },
            fn=_run_safe_command,
        ),
        Tool(
            name="ping_host",
            description="Ping a hostname or IP to check connectivity.",
            parameters={
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Hostname or IP"},
                    "count": {
                        "type": "integer",
                        "description": "Ping count (default 4)",
                    },
                },
                "required": ["host"],
            },
            fn=_ping_host,
        ),
    ]


def tool_schemas(tool_registry: list[Tool] | None = None) -> list[dict[str, Any]]:
    tool_registry = tool_registry or build_tools()
    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters,
            },
        }
        for tool in tool_registry
    ]


def execute_tool(
    name: str, arguments: dict[str, Any], tool_registry: list[Tool]
) -> str:
    for tool in tool_registry:
        if tool.name == name:
            try:
                result = tool.fn(**arguments)
            except Exception as exc:
                result = {"error": str(exc)}
            return json.dumps(result, ensure_ascii=False, indent=2)
    return json.dumps({"error": f"Unknown tool: {name}"}, ensure_ascii=False)


def _resolve_allowed_path(path: str) -> Path:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    resolved = candidate.resolve()

    for root in settings.allowed_read_roots:
        root_path = Path(root).expanduser().resolve()
        try:
            resolved.relative_to(root_path)
            return resolved
        except ValueError:
            continue
    raise PermissionError(f"Path outside allowed roots: {resolved}")


def _read_file(path: str, max_lines: int = 200) -> dict[str, Any]:
    try:
        resolved = _resolve_allowed_path(path)
        with resolved.open("r", encoding="utf-8", errors="replace") as file:
            lines = file.readlines()
    except PermissionError as exc:
        return {"error": str(exc)}
    except FileNotFoundError:
        return {"error": f"File not found: {path}"}
    except IsADirectoryError:
        return {"error": f"Expected a file but got directory: {path}"}
    except Exception as exc:
        return {"error": str(exc)}

    return {
        "path": str(resolved),
        "lines": "".join(lines[:max_lines]),
        "truncated": len(lines) > max_lines,
        "total_lines": len(lines),
    }


def _list_directory(path: str) -> dict[str, Any]:
    try:
        resolved = _resolve_allowed_path(path)
        entries = []
        for name in sorted(os.listdir(resolved)):
            full = resolved / name
            entries.append(
                {
                    "name": name,
                    "type": "dir" if full.is_dir() else "file",
                    "size_bytes": full.stat().st_size if full.is_file() else None,
                }
            )
        return {"path": str(resolved), "entries": entries}
    except Exception as exc:
        return {"error": str(exc)}


def _run_safe_command(command: str, timeout: int = 15) -> dict[str, Any]:
    argv = SAFE_COMMANDS.get(command)
    if not argv:
        return {"error": f"Command '{command}' is not in the safe allowlist."}
    if not shutil.which(argv[0]):
        return {"error": f"Command not available on this system: {argv[0]}"}

    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return {"error": "Command timed out"}
    except Exception as exc:
        return {"error": str(exc)}

    return {
        "command": command,
        "stdout": result.stdout[:4000],
        "stderr": result.stderr[:500],
        "returncode": result.returncode,
    }


def _ping_host(host: str, count: int = 4) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", host):
        return {"error": "Host contains invalid characters"}
    if not shutil.which("ping"):
        return {"error": "ping not available"}

    count_flag = "-n" if platform.system() == "Windows" else "-c"
    try:
        result = subprocess.run(
            ["ping", count_flag, str(count), host],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except Exception as exc:
        return {"error": str(exc)}

    output = result.stdout or result.stderr
    return {"host": host, "output": output[-2000:], "returncode": result.returncode}
