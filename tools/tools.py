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
from tools.antivirus_tools import build_antivirus_tools
from tools.maintenance_tools import build_maintenance_tools


SAFE_COMMANDS: dict[str, list[str]] = {
    "uptime": ["uptime"],
}

IDLE_PROCESS_NAMES = {"system idle process", "idle"}


def _is_usable_network_address(address: str) -> bool:
    address = str(address)
    if not address:
        return False
    if address.startswith("127.") or address == "::1" or address.startswith("169.254."):
        return False
    if re.fullmatch(r"[0-9A-Fa-f]{2}([-:][0-9A-Fa-f]{2}){5}", address):
        return False
    return True


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

    base_tools = [
        Tool(
            name="get_system_snapshot",
            description="Get current hardware state: CPU, RAM, GPU, disk, temperatures, top processes, network. Use this first when diagnosing any issue.",
            parameters={"type": "object", "properties": {}, "required": []},
            fn=lambda: scanner.to_dict(),
        ),
        Tool(
            name="get_disk_summary",
            description="Summarize disk usage, free space, and high-usage volumes.",
            parameters={
                "type": "object",
                "properties": {
                    "top_n": {
                        "type": "integer",
                        "description": "How many disks to include (default 10)",
                    }
                },
                "required": [],
            },
            fn=lambda top_n=10: get_disk_summary(scanner, top_n=top_n),
        ),
        Tool(
            name="get_top_processes",
            description="Show the busiest active processes by CPU and memory. Excludes System Idle Process by default.",
            parameters={
                "type": "object",
                "properties": {
                    "count": {
                        "type": "integer",
                        "description": "How many processes to return (default 5)",
                    },
                    "include_idle": {
                        "type": "boolean",
                        "description": "Include System Idle Process in the result",
                    },
                },
                "required": [],
            },
            fn=lambda count=5, include_idle=False: get_top_processes(
                scanner, count=count, include_idle=include_idle
            ),
        ),
        Tool(
            name="get_network_summary",
            description="Summarize active interfaces, IP addresses, and total traffic counters.",
            parameters={"type": "object", "properties": {}, "required": []},
            fn=lambda: get_network_summary(scanner),
        ),
        Tool(
            name="get_recent_errors",
            description="Read recent critical or error-level system events. Uses Windows Event Log on Windows and journalctl on Linux when available.",
            parameters={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Max number of recent error entries to return (default 10)",
                    }
                },
                "required": [],
            },
            fn=lambda limit=10: get_recent_errors(limit=limit),
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

    return [*base_tools, *build_antivirus_tools(), *build_maintenance_tools()]


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


def get_disk_summary(
    scanner: SystemScanner | None = None, top_n: int = 10
) -> dict[str, Any]:
    scanner = scanner or SystemScanner()
    snapshot = scanner.to_dict()
    disks = sorted(
        snapshot.get("disks", []), key=lambda disk: disk.get("percent", 0), reverse=True
    )
    top_n = max(1, min(int(top_n), 20))

    normalized = []
    critical = []
    warning = []

    for disk in disks[:top_n]:
        mount = disk.get("mountpoint") or disk.get("device") or "disk"
        entry = {
            "mountpoint": mount,
            "device": disk.get("device", ""),
            "fstype": disk.get("fstype", ""),
            "total_gb": float(disk.get("total_gb", 0)),
            "used_gb": float(disk.get("used_gb", 0)),
            "free_gb": float(disk.get("free_gb", 0)),
            "percent": float(disk.get("percent", 0)),
        }
        normalized.append(entry)

        if entry["percent"] >= 90:
            critical.append(mount)
        elif entry["percent"] >= 80:
            warning.append(mount)

    return {
        "count": len(normalized),
        "disks": normalized,
        "critical_mounts": critical,
        "warning_mounts": warning,
    }


def get_top_processes(
    scanner: SystemScanner | None = None,
    count: int = 5,
    include_idle: bool = False,
) -> dict[str, Any]:
    scanner = scanner or SystemScanner()
    snapshot = scanner.to_dict()
    processes = snapshot.get("top_processes", [])
    count = max(1, min(int(count), 20))

    if not include_idle:
        processes = [
            process
            for process in processes
            if (process.get("name") or "").casefold() not in IDLE_PROCESS_NAMES
        ]

    normalized = []
    for process in processes[:count]:
        normalized.append(
            {
                "pid": int(process.get("pid", 0)),
                "name": process.get("name", "unknown"),
                "cpu_percent": float(process.get("cpu_percent", 0)),
                "memory_mb": round(float(process.get("memory_mb", 0)), 1),
                "status": process.get("status", "unknown"),
            }
        )

    return {
        "count": len(normalized),
        "processes": normalized,
        "include_idle": include_idle,
    }


def get_network_summary(scanner: SystemScanner | None = None) -> dict[str, Any]:
    scanner = scanner or SystemScanner()
    snapshot = scanner.to_dict()
    network = snapshot.get("network", {})

    interfaces = []
    active_interfaces = []
    total_sent = 0.0
    total_recv = 0.0

    for name, details in network.items():
        addresses = [
            addr
            for addr in details.get("addresses", [])
            if _is_usable_network_address(addr)
        ]
        entry = {
            "name": name,
            "addresses": addresses,
            "bytes_sent_mb": float(details.get("bytes_sent_mb", 0)),
            "bytes_recv_mb": float(details.get("bytes_recv_mb", 0)),
            "packets_sent": int(details.get("packets_sent", 0)),
            "packets_recv": int(details.get("packets_recv", 0)),
        }
        interfaces.append(entry)
        total_sent += entry["bytes_sent_mb"]
        total_recv += entry["bytes_recv_mb"]
        if addresses:
            active_interfaces.append(entry)

    return {
        "interface_count": len(interfaces),
        "active_interface_count": len(active_interfaces),
        "active_interfaces": active_interfaces,
        "interfaces": interfaces,
        "total_sent_mb": round(total_sent, 2),
        "total_recv_mb": round(total_recv, 2),
    }


def get_recent_errors(limit: int = 10) -> dict[str, Any]:
    limit = max(1, min(int(limit), 20))
    current_platform = platform.system()

    if current_platform == "Windows":
        return _get_windows_recent_errors(limit)

    if shutil.which("journalctl"):
        return _get_journal_recent_errors(limit)

    return {
        "source": "none",
        "platform": current_platform,
        "count": 0,
        "entries": [],
        "error": "Recent error reader is not available on this platform.",
    }


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


def _get_windows_recent_errors(limit: int) -> dict[str, Any]:
    powershell = (
        shutil.which("powershell")
        or shutil.which("powershell.exe")
        or shutil.which("pwsh")
    )
    if not powershell:
        return {
            "source": "windows_event_log",
            "platform": "Windows",
            "count": 0,
            "entries": [],
            "error": "PowerShell is not available.",
        }

    script = (
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        "$OutputEncoding=[System.Text.Encoding]::UTF8; "
        "$ErrorActionPreference='Stop'; "
        "$start=(Get-Date).AddDays(-1); "
        f"$events=Get-WinEvent -FilterHashtable @{{LogName='System'; Level=1,2; StartTime=$start}} -MaxEvents {max(limit * 4, 20)} | "
        f"Select-Object -First {limit} TimeCreated, Id, ProviderName, LevelDisplayName, Message; "
        "$events | ConvertTo-Json -Depth 3 -Compress"
    )

    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=25,
            check=False,
        )
    except Exception as exc:
        return {
            "source": "windows_event_log",
            "platform": "Windows",
            "count": 0,
            "entries": [],
            "error": str(exc),
        }

    if result.returncode != 0:
        return {
            "source": "windows_event_log",
            "platform": "Windows",
            "count": 0,
            "entries": [],
            "error": result.stderr.strip() or "Failed to query Windows Event Log.",
        }

    payload = result.stdout.strip()
    if not payload or payload == "null":
        return {
            "source": "windows_event_log",
            "platform": "Windows",
            "count": 0,
            "entries": [],
        }

    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return {
            "source": "windows_event_log",
            "platform": "Windows",
            "count": 0,
            "entries": [],
            "error": "Windows Event Log returned invalid JSON.",
        }

    entries = parsed if isinstance(parsed, list) else [parsed]
    normalized = []
    for entry in entries[:limit]:
        message = " ".join(str(entry.get("Message", "")).split())
        normalized.append(
            {
                "time_created": str(entry.get("TimeCreated", "")),
                "id": entry.get("Id"),
                "provider": entry.get("ProviderName", ""),
                "level": entry.get("LevelDisplayName", ""),
                "message": message[:240],
            }
        )

    return {
        "source": "windows_event_log",
        "platform": "Windows",
        "count": len(normalized),
        "entries": normalized,
    }


def _get_journal_recent_errors(limit: int) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [
                "journalctl",
                "-p",
                "3",
                "-n",
                str(limit),
                "--no-pager",
                "--output",
                "short-iso",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except Exception as exc:
        return {
            "source": "journalctl",
            "platform": platform.system(),
            "count": 0,
            "entries": [],
            "error": str(exc),
        }

    if result.returncode != 0:
        return {
            "source": "journalctl",
            "platform": platform.system(),
            "count": 0,
            "entries": [],
            "error": result.stderr.strip() or "Failed to query journalctl.",
        }

    entries = []
    for line in result.stdout.strip().splitlines()[:limit]:
        entries.append({"message": line[:240]})

    return {
        "source": "journalctl",
        "platform": platform.system(),
        "count": len(entries),
        "entries": entries,
    }
