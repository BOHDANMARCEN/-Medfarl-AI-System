from __future__ import annotations

import os
import string
from dataclasses import dataclass, field


def _split_paths(raw: str) -> list[str]:
    return [path.strip() for path in raw.split(os.pathsep) if path.strip()]


def _env_flag(name: str, default: bool = True) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _all_filesystem_roots() -> list[str]:
    if os.name == "nt":
        roots = [
            f"{letter}:\\"
            for letter in string.ascii_uppercase
            if os.path.exists(f"{letter}:\\")
        ]
        if roots:
            return roots
    return [os.path.abspath(os.sep)]


@dataclass
class Settings:
    llm_url: str = os.getenv("MEDFARL_LLM_URL", "http://localhost:11434")
    model: str = os.getenv("MEDFARL_MODEL", "qwen3.5:9b")
    timeout: int = int(os.getenv("MEDFARL_TIMEOUT", "120"))
    max_tool_steps: int = int(os.getenv("MEDFARL_MAX_TOOL_STEPS", "8"))
    allowed_read_roots: list[str] = field(
        default_factory=lambda: _split_paths(
            os.getenv("MEDFARL_ALLOWED_READ_ROOTS", os.pathsep.join([os.getcwd()]))
        )
    )
    allowed_edit_roots: list[str] = field(
        default_factory=lambda: _split_paths(
            os.getenv("MEDFARL_ALLOWED_EDIT_ROOTS", os.pathsep.join([os.getcwd()]))
        )
    )
    allowed_exec_roots: list[str] = field(
        default_factory=lambda: _split_paths(
            os.getenv("MEDFARL_ALLOWED_EXEC_ROOTS", os.pathsep.join([os.getcwd()]))
        )
    )
    require_confirmation_for_exec: bool = _env_flag("MEDFARL_CONFIRM_EXEC", True)
    require_confirmation_for_delete: bool = _env_flag("MEDFARL_CONFIRM_DELETE", True)
    require_confirmation_for_package_changes: bool = _env_flag(
        "MEDFARL_CONFIRM_PACKAGE_CHANGES", True
    )
    require_confirmation_for_file_edits: bool = _env_flag(
        "MEDFARL_CONFIRM_FILE_EDITS", True
    )
    enable_action_audit_log: bool = _env_flag("MEDFARL_ENABLE_ACTION_LOG", True)
    action_audit_log_path: str = os.getenv(
        "MEDFARL_ACTION_LOG_PATH", os.path.join(os.getcwd(), "medfarl_actions.log")
    )
    junk_quarantine_dir: str = os.getenv(
        "MEDFARL_JUNK_QUARANTINE_DIR", os.path.join(os.getcwd(), "junk_quarantine")
    )
    unsafe_full_access: bool = _env_flag("MEDFARL_UNSAFE_FULL_ACCESS", False)

    def __post_init__(self) -> None:
        if self.unsafe_full_access:
            self.enable_unsafe_full_access()

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

    def enable_unsafe_full_access(self) -> None:
        self.unsafe_full_access = True
        roots = _all_filesystem_roots()
        self.allowed_read_roots = list(roots)
        self.allowed_edit_roots = list(roots)
        self.allowed_exec_roots = list(roots)
        self.require_confirmation_for_exec = False
        self.require_confirmation_for_delete = False
        self.require_confirmation_for_package_changes = False
        self.require_confirmation_for_file_edits = False


settings = Settings()
