from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid


@dataclass
class PendingAction:
    id: str
    action_type: str
    tool_name: str
    arguments: dict[str, Any]
    summary: str
    risk: str = "medium"
    plan: list[str] = field(default_factory=list)
    created_at: str = ""


class PendingActionExistsError(RuntimeError):
    def __init__(self, pending: PendingAction) -> None:
        super().__init__(f"Pending action already exists: {pending.id}")
        self.pending = pending


@dataclass
class ApprovalState:
    pending: PendingAction | None = None

    def create(
        self,
        *,
        action_type: str,
        tool_name: str,
        arguments: dict[str, Any],
        summary: str,
        risk: str = "medium",
        plan: list[str] | None = None,
    ) -> PendingAction:
        if self.pending is not None:
            raise PendingActionExistsError(self.pending)

        action = PendingAction(
            id=str(uuid.uuid4())[:8],
            action_type=action_type,
            tool_name=tool_name,
            arguments=arguments,
            summary=summary,
            risk=risk,
            plan=plan or [],
            created_at=datetime.now(tz=timezone.utc).isoformat(),
        )
        self.pending = action
        return action

    def clear(self) -> None:
        self.pending = None

    def has_pending(self) -> bool:
        return self.pending is not None
