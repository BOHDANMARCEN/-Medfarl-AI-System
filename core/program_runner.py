from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Any

from config import settings
from core.action_guard import ensure_under_roots


SAFE_EXEC_SUFFIXES = {".exe"}
UNSAFE_EXEC_SUFFIXES = {".exe", ".cmd", ".bat", ".com"}


def _sha256_file(path: Path, block_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while True:
            chunk = file.read(block_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def run_program(
    path: str,
    args: list[str] | None = None,
    cwd: str | None = None,
    timeout: int = 120,
) -> dict[str, Any]:
    args = args or []
    executable = _resolve_executable(path)

    if not executable.is_file():
        return {"error": f"Executable not found: {executable}"}

    allowed_suffixes = (
        UNSAFE_EXEC_SUFFIXES if settings.unsafe_full_access else SAFE_EXEC_SUFFIXES
    )
    suffix = executable.suffix.lower()
    if suffix not in allowed_suffixes:
        return {
            "error": (
                f"Executable type not allowed: {suffix or '<none>'}. "
                f"Allowed: {sorted(allowed_suffixes)}"
            )
        }

    if cwd:
        working_dir = _resolve_working_dir(cwd)
    else:
        working_dir = executable.parent

    if not working_dir.is_dir():
        return {"error": f"Working directory does not exist: {working_dir}"}

    metadata = {
        "path": str(executable),
        "args": args,
        "cwd": str(working_dir),
        "size_bytes": executable.stat().st_size,
        "sha256": _sha256_file(executable),
    }

    try:
        result = subprocess.run(
            [str(executable), *args],
            cwd=str(working_dir),
            capture_output=True,
            text=True,
            timeout=max(1, min(int(timeout), 900)),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {**metadata, "error": "Program execution timed out"}
    except Exception as exc:
        return {**metadata, "error": str(exc)}

    return {
        **metadata,
        "returncode": result.returncode,
        "stdout": result.stdout[-6000:],
        "stderr": result.stderr[-4000:],
    }


def _resolve_executable(path: str) -> Path:
    if settings.unsafe_full_access:
        candidate = Path(path).expanduser()
        if candidate.is_absolute() or any(sep in path for sep in ("\\", "/")):
            resolved = candidate.resolve()
            return resolved

        discovered = shutil.which(path)
        if discovered:
            return Path(discovered).resolve()

        return candidate.resolve()

    return ensure_under_roots(path, settings.allowed_exec_roots, label="Executable")


def _resolve_working_dir(path: str) -> Path:
    if settings.unsafe_full_access:
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        return candidate.resolve()
    return ensure_under_roots(
        path, settings.allowed_exec_roots, label="Working directory"
    )
