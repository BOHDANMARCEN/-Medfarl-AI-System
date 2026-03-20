from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any

from config import settings
from core.action_guard import ensure_under_roots


MAX_TEXT_FILE_BYTES = 2 * 1024 * 1024


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        errors="replace",
        dir=str(path.parent),
        delete=False,
    ) as temp_file:
        temp_file.write(content)
        temp_path = Path(temp_file.name)
    temp_path.replace(path)


def _create_backup(path: Path) -> Path:
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d%H%M%S")
    backup = path.with_suffix(path.suffix + f".bak.{timestamp}")
    shutil.copy2(path, backup)
    return backup


def _read_text_file(path: Path) -> tuple[str | None, str | None]:
    if path.stat().st_size > MAX_TEXT_FILE_BYTES:
        return (
            None,
            f"File is too large for safe edit (> {MAX_TEXT_FILE_BYTES} bytes): {path}",
        )

    raw = path.read_bytes()
    if b"\x00" in raw:
        return None, f"Binary-like file is not supported for text edits: {path}"

    return raw.decode("utf-8", errors="replace"), None


def create_directory(path: str) -> dict[str, Any]:
    target = ensure_under_roots(path, settings.allowed_edit_roots, label="Edit")
    target.mkdir(parents=True, exist_ok=True)
    return {"path": str(target), "created": True}


def create_text_file(path: str, content: str = "") -> dict[str, Any]:
    target = ensure_under_roots(path, settings.allowed_edit_roots, label="Edit")
    if target.exists():
        return {"error": f"File already exists: {target}"}

    _atomic_write(target, content)
    return {
        "path": str(target),
        "created": True,
        "bytes_written": len(content.encode("utf-8")),
    }


def write_text_file(path: str, content: str, overwrite: bool = False) -> dict[str, Any]:
    target = ensure_under_roots(path, settings.allowed_edit_roots, label="Edit")
    backup_path = None

    if target.exists() and not overwrite:
        return {"error": f"File exists and overwrite is disabled: {target}"}

    if target.exists():
        backup_path = _create_backup(target)

    _atomic_write(target, content)
    return {
        "path": str(target),
        "written": True,
        "overwrite": overwrite,
        "backup_path": str(backup_path) if backup_path else None,
        "bytes_written": len(content.encode("utf-8")),
    }


def append_text_file(path: str, content: str) -> dict[str, Any]:
    target = ensure_under_roots(path, settings.allowed_edit_roots, label="Edit")
    backup_path = None

    if target.exists():
        backup_path = _create_backup(target)
        existing, error = _read_text_file(target)
        if error:
            return {"error": error}
        merged = (existing or "") + content
    else:
        merged = content

    _atomic_write(target, merged)
    return {
        "path": str(target),
        "appended": True,
        "backup_path": str(backup_path) if backup_path else None,
        "bytes_appended": len(content.encode("utf-8")),
    }


def edit_text_file(path: str, find_text: str, replace_text: str) -> dict[str, Any]:
    target = ensure_under_roots(path, settings.allowed_edit_roots, label="Edit")
    if not target.is_file():
        return {"error": f"File not found: {target}"}
    if not find_text:
        return {"error": "find_text cannot be empty"}

    original, error = _read_text_file(target)
    if error:
        return {"error": error}
    assert original is not None

    if find_text not in original:
        return {
            "path": str(target),
            "changed": False,
            "reason": "find_text not found",
        }

    updated = original.replace(find_text, replace_text, 1)
    backup = _create_backup(target)
    _atomic_write(target, updated)

    return {
        "path": str(target),
        "changed": True,
        "backup_path": str(backup),
    }


def find_junk_files(
    scope: str = "safe", older_than_days: int = 7, limit: int = 300
) -> dict[str, Any]:
    now = datetime.now(tz=timezone.utc)
    older_than_days = max(0, min(int(older_than_days), 3650))
    limit = max(1, min(int(limit), 2000))

    roots = _junk_roots(scope)
    if not roots:
        return {
            "scope": scope,
            "count": 0,
            "total_size_mb": 0.0,
            "items": [],
            "error": "No searchable roots for this scope.",
        }

    items: list[dict[str, Any]] = []
    total_size = 0
    for root in roots:
        if len(items) >= limit:
            break
        for entry in _iter_junk_candidates(root):
            if len(items) >= limit:
                break
            try:
                stat = entry.stat()
            except OSError:
                continue

            age_days = (
                now - datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            ).days
            if age_days < older_than_days:
                continue

            size = stat.st_size if entry.is_file() else 0
            total_size += size
            items.append(
                {
                    "path": str(entry),
                    "size_bytes": size,
                    "age_days": age_days,
                    "category": _junk_category(entry),
                }
            )

    items.sort(key=lambda item: item["size_bytes"], reverse=True)
    return {
        "scope": scope,
        "count": len(items),
        "total_size_mb": round(total_size / 1024**2, 2),
        "items": items,
        "truncated": len(items) >= limit,
    }


def _junk_roots(scope: str) -> list[Path]:
    if scope not in {"safe", "user"}:
        scope = "safe"

    candidates: list[Path] = [Path(tempfile.gettempdir())]
    home = Path.home()
    local_app_data = os.getenv("LOCALAPPDATA")
    app_data = os.getenv("APPDATA")

    if local_app_data:
        candidates.append(Path(local_app_data) / "Temp")
        candidates.append(Path(local_app_data) / "pip" / "Cache")
        candidates.append(Path(local_app_data) / "CrashDumps")
    if app_data:
        candidates.append(Path(app_data) / "Microsoft" / "Windows" / "Recent")

    if scope == "user":
        candidates.append(home / ".cache")
        candidates.append(home / "AppData" / "Local" / "Temp")

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        key = str(resolved).casefold()
        if key in seen or not resolved.exists():
            continue
        seen.add(key)
        unique.append(resolved)
    return unique


def _iter_junk_candidates(root: Path):
    patterns = ["*.tmp", "*.temp", "*.dmp", "*.old", "*.log"]
    for pattern in patterns:
        try:
            for path in root.rglob(pattern):
                if path.is_file():
                    yield path
        except OSError:
            continue

    for name in ["__pycache__", "Cache", "cache"]:
        try:
            for path in root.rglob(name):
                if path.is_dir():
                    yield path
        except OSError:
            continue


def _junk_category(path: Path) -> str:
    name = path.name.casefold()
    if name in {"__pycache__", "cache"}:
        return "cache"
    suffix = path.suffix.casefold()
    if suffix in {".tmp", ".temp", ".old"}:
        return "temp"
    if suffix == ".dmp":
        return "crash_dump"
    if suffix == ".log":
        return "old_log"
    return "unknown"
