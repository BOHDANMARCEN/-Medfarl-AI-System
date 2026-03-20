from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from config import settings
from core.approval import PendingAction


MAX_RESULT_CHARS = 6000


def log_action_event(
    event: str,
    *,
    action: PendingAction | None = None,
    result: Any = None,
    note: str | None = None,
) -> None:
    if not settings.enable_action_audit_log:
        return

    payload: dict[str, Any] = {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "event": event,
    }

    if action is not None:
        payload.update(
            {
                "action_id": action.id,
                "action_type": action.action_type,
                "tool_name": action.tool_name,
                "arguments": action.arguments,
                "summary": action.summary,
                "risk": action.risk,
                "created_at": action.created_at,
            }
        )

    if result is not None:
        payload["result"] = _sanitize_result(result)

    if note:
        payload["note"] = note

    path = Path(settings.action_audit_log_path).expanduser()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", errors="replace") as file:
            file.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        return


def read_action_history(limit: int = 10) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 200))
    path = Path(settings.action_audit_log_path).expanduser()
    if not path.is_file():
        return []

    records: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception:
        return []

    return records[-limit:]


def read_last_action() -> dict[str, Any] | None:
    history = read_action_history(limit=1)
    if not history:
        return None
    return history[-1]


def _sanitize_result(result: Any) -> Any:
    try:
        serialized = json.dumps(result, ensure_ascii=False)
    except TypeError:
        serialized = str(result)

    if len(serialized) <= MAX_RESULT_CHARS:
        try:
            return json.loads(serialized)
        except Exception:
            return serialized

    truncated = serialized[:MAX_RESULT_CHARS]
    return {"truncated": True, "preview": truncated}
