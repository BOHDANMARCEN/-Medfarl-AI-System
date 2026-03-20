from __future__ import annotations

from dataclasses import dataclass
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
    ) -> PendingAction:
        action = PendingAction(
            id=str(uuid.uuid4())[:8],
            action_type=action_type,
            tool_name=tool_name,
            arguments=arguments,
            summary=summary,
            risk=risk,
        )
        self.pending = action
        return action

    def clear(self) -> None:
        self.pending = None

    def has_pending(self) -> bool:
        return self.pending is not None
