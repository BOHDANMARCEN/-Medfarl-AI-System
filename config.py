from __future__ import annotations

import os
from dataclasses import dataclass, field


def _split_paths(raw: str) -> list[str]:
    return [path.strip() for path in raw.split(os.pathsep) if path.strip()]


@dataclass
class Settings:
    llm_url: str = os.getenv("MEDFARL_LLM_URL", "http://localhost:11434")
    model: str = os.getenv("MEDFARL_MODEL", "llama3.2:3b")
    timeout: int = int(os.getenv("MEDFARL_TIMEOUT", "120"))
    max_tool_steps: int = int(os.getenv("MEDFARL_MAX_TOOL_STEPS", "8"))
    allowed_read_roots: list[str] = field(
        default_factory=lambda: _split_paths(
            os.getenv("MEDFARL_ALLOWED_READ_ROOTS", os.pathsep.join([os.getcwd()]))
        )
    )

    @property
    def llm_base_url(self) -> str:
        return self.llm_url

    @property
    def llm_model(self) -> str:
        return self.model

    @property
    def llm_timeout(self) -> int:
        return self.timeout

    @property
    def max_tool_calls_per_turn(self) -> int:
        return self.max_tool_steps

    @property
    def allowed_paths(self) -> list[str]:
        return self.allowed_read_roots


settings = Settings()
