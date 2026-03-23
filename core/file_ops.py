from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import tempfile
import uuid
from typing import Any

from config import settings
from core.action_guard import ensure_under_roots


MAX_TEXT_FILE_BYTES = 2 * 1024 * 1024
MAX_JUNK_PATHS_PER_ACTION = 500
JUNK_CACHE_DIR_NAMES = {"__pycache__", "cache"}
JUNK_FILE_SUFFIXES = {".tmp", ".temp", ".old", ".dmp", ".log"}
QUARANTINE_ID_PREFIX = "qk-"
QUARANTINE_META_SUFFIX = ".meta.json"


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


def copy_path(source: str, destination: str, overwrite: bool = False) -> dict[str, Any]:
    if not settings.unsafe_full_access:
        return {"error": "copy_path is available only in unsafe full access mode."}

    src = _resolve_loose_path(source)
    dst = _resolve_loose_path(destination)
    if not src.exists():
        return {"error": f"Source path does not exist: {src}"}
    if dst.exists():
        if not overwrite:
            return {"error": f"Destination already exists: {dst}"}
        _remove_existing_path(dst)

    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        shutil.copytree(src, dst)
        path_type = "dir"
    else:
        shutil.copy2(src, dst)
        path_type = "file"

    return {
        "source": str(src),
        "destination": str(dst),
        "copied": True,
        "type": path_type,
        "overwrite": overwrite,
    }


def move_path(source: str, destination: str, overwrite: bool = False) -> dict[str, Any]:
    if not settings.unsafe_full_access:
        return {"error": "move_path is available only in unsafe full access mode."}

    src = _resolve_loose_path(source)
    dst = _resolve_loose_path(destination)
    if not src.exists():
        return {"error": f"Source path does not exist: {src}"}
    if dst.exists():
        if not overwrite:
            return {"error": f"Destination already exists: {dst}"}
        _remove_existing_path(dst)

    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return {
        "source": str(src),
        "destination": str(dst),
        "moved": True,
        "overwrite": overwrite,
    }


def remove_path(path: str, recursive: bool = False) -> dict[str, Any]:
    if not settings.unsafe_full_access:
        return {"error": "remove_path is available only in unsafe full access mode."}

    target = _resolve_loose_path(path)
    if not target.exists():
        return {"error": f"Path does not exist: {target}"}

    if target.is_dir() and not recursive:
        return {
            "error": f"Directory removal requires recursive=True: {target}",
            "path": str(target),
        }

    path_type = "dir" if target.is_dir() else "file"
    _remove_existing_path(target)
    return {
        "path": str(target),
        "deleted": True,
        "type": path_type,
        "recursive": recursive,
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


def move_junk_to_quarantine(
    paths: list[str],
    quarantine_dir: str | None = None,
) -> dict[str, Any]:
    if not isinstance(paths, list) or not paths:
        return {"error": "paths must be a non-empty list"}

    if len(paths) > MAX_JUNK_PATHS_PER_ACTION:
        return {
            "error": (
                f"Too many paths in one action ({len(paths)}). "
                f"Limit: {MAX_JUNK_PATHS_PER_ACTION}"
            )
        }

    destination_root = _quarantine_root(quarantine_dir)
    destination_root.mkdir(parents=True, exist_ok=True)

    moved = []
    failed = []
    for raw_path in paths:
        target = _resolve_loose_path(str(raw_path))
        validation_error = _validate_junk_target(target)
        if validation_error:
            failed.append({"path": str(target), "error": validation_error})
            continue

        entry_id = _generate_quarantine_entry_id()
        dest_name = f"{target.name}.{entry_id}"
        destination = destination_root / dest_name
        metadata_path = _quarantine_metadata_path(destination)
        try:
            shutil.move(str(target), str(destination))
        except Exception as exc:
            failed.append({"path": str(target), "error": str(exc)})
            continue

        metadata = {
            "entry_id": entry_id,
            "source": str(target),
            "quarantined_path": str(destination),
            "created_at": datetime.now(tz=timezone.utc).isoformat(),
            "category": _junk_category(target),
            "size_bytes": _path_size_bytes(destination),
            "is_dir": destination.is_dir(),
        }

        try:
            _atomic_write(
                metadata_path, json.dumps(metadata, ensure_ascii=False, indent=2)
            )
        except Exception as exc:
            try:
                shutil.move(str(destination), str(target))
            except Exception:
                failed.append(
                    {
                        "path": str(target),
                        "error": (
                            "Quarantine metadata write failed and rollback also failed: "
                            f"{exc}"
                        ),
                    }
                )
                continue

            failed.append(
                {
                    "path": str(target),
                    "error": f"Could not write quarantine metadata: {exc}",
                }
            )
            continue

        moved.append(
            {
                "entry_id": entry_id,
                "source": str(target),
                "destination": str(destination),
                "metadata_path": str(metadata_path),
            }
        )

    return {
        "quarantine_dir": str(destination_root),
        "moved_count": len(moved),
        "failed_count": len(failed),
        "moved": moved,
        "failed": failed,
    }


def show_quarantine(limit: int = 50) -> dict[str, Any]:
    limit = max(1, min(int(limit), 500))
    quarantine_root = _quarantine_root()
    if not quarantine_root.exists():
        return {
            "quarantine_dir": str(quarantine_root),
            "count": 0,
            "total_size_mb": 0.0,
            "entries": [],
        }

    entries = _load_quarantine_entries(quarantine_root)
    entries.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
    total_size = sum(int(entry.get("size_bytes", 0)) for entry in entries)

    return {
        "quarantine_dir": str(quarantine_root),
        "count": len(entries),
        "total_size_mb": round(total_size / 1024**2, 2),
        "entries": entries[:limit],
        "truncated": len(entries) > limit,
    }


def restore_from_quarantine(
    entry_ids: list[str],
    destination_root: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    if not isinstance(entry_ids, list) or not entry_ids:
        return {"error": "entry_ids must be a non-empty list"}

    if len(entry_ids) > MAX_JUNK_PATHS_PER_ACTION:
        return {
            "error": (
                f"Too many quarantine entries in one action ({len(entry_ids)}). "
                f"Limit: {MAX_JUNK_PATHS_PER_ACTION}"
            )
        }

    quarantine_root = _quarantine_root()
    if not quarantine_root.exists():
        return {
            "error": f"Quarantine directory does not exist: {quarantine_root}",
            "restored_count": 0,
            "failed_count": len(entry_ids),
            "restored": [],
            "failed": [
                {"entry_id": str(entry_id), "error": "Quarantine directory is missing"}
                for entry_id in entry_ids
            ],
        }

    entries = _load_quarantine_entries(quarantine_root)
    by_id = {
        str(entry.get("entry_id")): entry for entry in entries if entry.get("entry_id")
    }

    restored = []
    failed = []
    destination_root_path = None
    if destination_root:
        destination_root_path = ensure_under_roots(
            destination_root,
            settings.allowed_edit_roots,
            label="Restore destination",
        )
        destination_root_path.mkdir(parents=True, exist_ok=True)

    for raw_id in entry_ids:
        entry_id = str(raw_id).strip()
        entry = by_id.get(entry_id)
        if not entry:
            failed.append(
                {"entry_id": entry_id, "error": "Quarantine entry was not found"}
            )
            continue

        if entry.get("status") != "ok":
            failed.append(
                {
                    "entry_id": entry_id,
                    "error": f"Quarantine entry is not restorable (status={entry.get('status')})",
                }
            )
            continue

        source_path = str(entry.get("source") or "")
        if not source_path:
            failed.append(
                {"entry_id": entry_id, "error": "Original source path is missing"}
            )
            continue

        if destination_root_path is not None:
            target = destination_root_path / Path(source_path).name
        else:
            try:
                target = ensure_under_roots(
                    source_path,
                    settings.allowed_edit_roots,
                    label="Restore target",
                )
            except PermissionError as exc:
                failed.append({"entry_id": entry_id, "error": str(exc)})
                continue

        quarantined_path = Path(str(entry.get("quarantined_path") or ""))
        metadata_path = Path(str(entry.get("metadata_path") or ""))
        if not quarantined_path.exists():
            failed.append(
                {"entry_id": entry_id, "error": "Quarantined file no longer exists"}
            )
            continue

        if target.exists() and not overwrite:
            failed.append(
                {
                    "entry_id": entry_id,
                    "error": f"Restore target already exists: {target}",
                }
            )
            continue

        if target.exists() and overwrite:
            try:
                _remove_existing_path(target)
            except Exception as exc:
                failed.append({"entry_id": entry_id, "error": str(exc)})
                continue

        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.move(str(quarantined_path), str(target))
            if metadata_path.is_file():
                metadata_path.unlink()
        except Exception as exc:
            failed.append({"entry_id": entry_id, "error": str(exc)})
            continue

        restored.append(
            {
                "entry_id": entry_id,
                "source": source_path,
                "restored_to": str(target),
                "overwrite": overwrite,
            }
        )

    return {
        "restored_count": len(restored),
        "failed_count": len(failed),
        "restored": restored,
        "failed": failed,
    }


def delete_junk_files(paths: list[str], recursive: bool = False) -> dict[str, Any]:
    if not isinstance(paths, list) or not paths:
        return {"error": "paths must be a non-empty list"}

    if len(paths) > MAX_JUNK_PATHS_PER_ACTION:
        return {
            "error": (
                f"Too many paths in one action ({len(paths)}). "
                f"Limit: {MAX_JUNK_PATHS_PER_ACTION}"
            )
        }

    deleted = []
    failed = []
    for raw_path in paths:
        target = _resolve_loose_path(str(raw_path))
        validation_error = _validate_junk_target(target, allow_quarantine=True)
        if validation_error:
            failed.append({"path": str(target), "error": validation_error})
            continue

        try:
            if target.is_dir():
                if not recursive:
                    failed.append(
                        {
                            "path": str(target),
                            "error": "Directory deletion requires recursive=True",
                        }
                    )
                    continue
                shutil.rmtree(target)
                deleted.append({"path": str(target), "type": "dir"})
            else:
                target.unlink()
                deleted.append({"path": str(target), "type": "file"})
        except Exception as exc:
            failed.append({"path": str(target), "error": str(exc)})

    return {
        "deleted_count": len(deleted),
        "failed_count": len(failed),
        "deleted": deleted,
        "failed": failed,
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


def _quarantine_root(path: str | None = None) -> Path:
    return ensure_under_roots(
        path or settings.junk_quarantine_dir,
        settings.allowed_edit_roots,
        label="Quarantine",
    )


def _generate_quarantine_entry_id() -> str:
    return f"{QUARANTINE_ID_PREFIX}{uuid.uuid4().hex[:8]}"


def _quarantine_metadata_path(quarantined_path: Path) -> Path:
    return quarantined_path.parent / f"{quarantined_path.name}{QUARANTINE_META_SUFFIX}"


def _path_size_bytes(path: Path) -> int:
    try:
        if path.is_file():
            return path.stat().st_size
        total = 0
        for child in path.rglob("*"):
            if child.is_file():
                total += child.stat().st_size
        return total
    except OSError:
        return 0


def _load_quarantine_entries(quarantine_root: Path) -> list[dict[str, Any]]:
    metadata_files = sorted(quarantine_root.glob(f"*{QUARANTINE_META_SUFFIX}"))
    entries: list[dict[str, Any]] = []
    referenced_names: set[str] = set()

    for meta_path in metadata_files:
        entry = _load_quarantine_entry(meta_path)
        entries.append(entry)
        quarantined_path = entry.get("quarantined_path")
        if quarantined_path:
            referenced_names.add(Path(str(quarantined_path)).name)

    for candidate in quarantine_root.iterdir():
        if candidate.name.endswith(QUARANTINE_META_SUFFIX):
            continue
        if candidate.name in referenced_names:
            continue
        entries.append(
            {
                "entry_id": None,
                "source": None,
                "quarantined_path": str(candidate),
                "metadata_path": None,
                "created_at": None,
                "category": "unknown",
                "size_bytes": _path_size_bytes(candidate),
                "status": "missing_metadata",
                "note": "Metadata sidecar is missing; manual recovery required.",
            }
        )

    return entries


def _load_quarantine_entry(meta_path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(meta_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {
            "entry_id": None,
            "source": None,
            "quarantined_path": None,
            "metadata_path": str(meta_path),
            "created_at": None,
            "category": "unknown",
            "size_bytes": 0,
            "status": "invalid_metadata",
            "note": "Metadata could not be parsed.",
        }

    entry_id = str(payload.get("entry_id") or "").strip() or None
    source = payload.get("source")
    quarantined_path = payload.get("quarantined_path")
    created_at = payload.get("created_at")
    category = payload.get("category") or "unknown"
    size_bytes = int(payload.get("size_bytes") or 0)

    status = "ok"
    note = None
    if not entry_id or not quarantined_path:
        status = "invalid_metadata"
        note = "Metadata is incomplete."
    else:
        path = Path(str(quarantined_path))
        if not path.exists():
            status = "missing_file"
            note = "Quarantined file is missing."
        elif size_bytes <= 0:
            size_bytes = _path_size_bytes(path)

    return {
        "entry_id": entry_id,
        "source": source,
        "quarantined_path": quarantined_path,
        "metadata_path": str(meta_path),
        "created_at": created_at,
        "category": category,
        "size_bytes": size_bytes,
        "status": status,
        "note": note,
    }


def _resolve_loose_path(path: str) -> Path:
    candidate = Path(os.path.expandvars(path)).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return candidate.resolve()


def _is_under_any_root(path: Path, roots: list[Path]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _validate_junk_target(path: Path, allow_quarantine: bool = False) -> str | None:
    if not path.exists():
        return f"Path does not exist: {path}"

    if allow_quarantine:
        quarantine_root = _resolve_loose_path(settings.junk_quarantine_dir)
        if _is_under_any_root(path, [quarantine_root]):
            return None

    roots = _junk_roots("safe") + _junk_roots("user")
    if not _is_under_any_root(path, roots):
        return "Path is outside known junk roots"

    if path.is_dir():
        name = path.name.casefold()
        if name not in JUNK_CACHE_DIR_NAMES:
            return "Directory is not a recognized junk cache folder"
        return None

    suffix = path.suffix.casefold()
    if suffix not in JUNK_FILE_SUFFIXES:
        return "File extension is not in allowed junk categories"
    return None


def _remove_existing_path(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


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
