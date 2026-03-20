from __future__ import annotations

import os
from pathlib import Path


def resolve_path(path: str) -> Path:
    candidate = Path(os.path.expandvars(path)).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return candidate.resolve()


def is_under_roots(path: str, roots: list[str]) -> bool:
    resolved = resolve_path(path)
    for root in roots:
        root_path = resolve_path(root)
        try:
            resolved.relative_to(root_path)
            return True
        except ValueError:
            continue
    return False


def ensure_under_roots(path: str, roots: list[str], *, label: str) -> Path:
    resolved = resolve_path(path)
    if not is_under_roots(str(resolved), roots):
        raise PermissionError(f"{label} path outside allowed roots: {resolved}")
    return resolved
