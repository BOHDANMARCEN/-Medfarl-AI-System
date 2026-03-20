from __future__ import annotations

from core.antivirus import (
    detect_antivirus,
    list_antivirus_threats,
    run_antivirus_custom_scan,
    run_antivirus_quick_scan,
    update_antivirus_definitions,
)
from core.llm_client import Tool


def build_antivirus_tools() -> list[Tool]:
    provider_schema = {
        "type": "string",
        "enum": ["windows_defender", "clamav"],
        "description": "Optional antivirus provider override",
    }

    return [
        Tool(
            name="detect_antivirus",
            description="Detect available antivirus providers (Windows Defender or ClamAV) and their status.",
            parameters={"type": "object", "properties": {}, "required": []},
            fn=detect_antivirus,
        ),
        Tool(
            name="update_antivirus_definitions",
            description="Update antivirus signatures for the selected provider or default detected provider.",
            parameters={
                "type": "object",
                "properties": {
                    "provider": provider_schema,
                },
                "required": [],
            },
            fn=update_antivirus_definitions,
        ),
        Tool(
            name="run_antivirus_quick_scan",
            description="Run a quick antivirus scan using the selected provider or default detected provider.",
            parameters={
                "type": "object",
                "properties": {
                    "provider": provider_schema,
                },
                "required": [],
            },
            fn=run_antivirus_quick_scan,
        ),
        Tool(
            name="run_antivirus_custom_scan",
            description="Run a custom antivirus scan on a specific file or directory path.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute or relative path to scan",
                    },
                    "provider": provider_schema,
                },
                "required": ["path"],
            },
            fn=run_antivirus_custom_scan,
        ),
        Tool(
            name="list_antivirus_threats",
            description="List recent detected antivirus threats from the selected provider.",
            parameters={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of threat entries to return",
                    },
                    "provider": provider_schema,
                },
                "required": [],
            },
            fn=list_antivirus_threats,
        ),
    ]
