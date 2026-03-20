from __future__ import annotations

from core.file_ops import (
    append_text_file,
    create_directory,
    create_text_file,
    delete_junk_files,
    edit_text_file,
    find_junk_files,
    move_junk_to_quarantine,
    restore_from_quarantine,
    show_quarantine,
    write_text_file,
)
from core.llm_client import Tool
from core.package_manager import (
    pip_check,
    pip_freeze,
    pip_install_package,
    pip_uninstall_package,
)
from core.program_runner import run_program


def build_maintenance_tools() -> list[Tool]:
    return [
        Tool(
            name="run_program",
            description="Run an approved executable from allowed execution roots.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "args": {"type": "array", "items": {"type": "string"}},
                    "cwd": {"type": "string"},
                    "timeout": {"type": "integer"},
                },
                "required": ["path"],
            },
            fn=run_program,
        ),
        Tool(
            name="pip_install_package",
            description="Install a Python package into the current interpreter environment.",
            parameters={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "version": {"type": "string"},
                    "upgrade": {"type": "boolean"},
                },
                "required": ["name"],
            },
            fn=pip_install_package,
        ),
        Tool(
            name="pip_uninstall_package",
            description="Uninstall a Python package from the current interpreter environment.",
            parameters={
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                },
                "required": ["name"],
            },
            fn=pip_uninstall_package,
        ),
        Tool(
            name="pip_check",
            description="Check Python environment for dependency conflicts.",
            parameters={"type": "object", "properties": {}, "required": []},
            fn=pip_check,
        ),
        Tool(
            name="pip_freeze",
            description="List installed Python packages as pip freeze output.",
            parameters={"type": "object", "properties": {}, "required": []},
            fn=pip_freeze,
        ),
        Tool(
            name="find_junk_files",
            description="Preview temporary and cache-like files/directories that may be safe to clean later.",
            parameters={
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "string",
                        "enum": ["safe", "user"],
                        "description": "Search scope for junk candidates",
                    },
                    "older_than_days": {
                        "type": "integer",
                        "description": "Only include entries older than this",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Max number of entries to return",
                    },
                },
                "required": [],
            },
            fn=find_junk_files,
        ),
        Tool(
            name="show_quarantine",
            description="List quarantined junk entries with original path, size, and status.",
            parameters={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of quarantine entries to return",
                    }
                },
                "required": [],
            },
            fn=show_quarantine,
        ),
        Tool(
            name="move_junk_to_quarantine",
            description="Move selected junk files/directories into quarantine storage.",
            parameters={
                "type": "object",
                "properties": {
                    "paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Junk file/directory paths to move",
                    },
                    "quarantine_dir": {
                        "type": "string",
                        "description": "Optional quarantine root directory",
                    },
                },
                "required": ["paths"],
            },
            fn=move_junk_to_quarantine,
        ),
        Tool(
            name="restore_from_quarantine",
            description="Restore quarantined junk entries back to their original path or a safe destination.",
            parameters={
                "type": "object",
                "properties": {
                    "entry_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Quarantine entry IDs to restore",
                    },
                    "destination_root": {
                        "type": "string",
                        "description": "Optional restore destination inside allowed edit roots",
                    },
                    "overwrite": {
                        "type": "boolean",
                        "description": "Allow overwriting an existing restore target",
                    },
                },
                "required": ["entry_ids"],
            },
            fn=restore_from_quarantine,
        ),
        Tool(
            name="delete_junk_files",
            description="Delete selected junk files/directories from disk.",
            parameters={
                "type": "object",
                "properties": {
                    "paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Junk file/directory paths to delete",
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Allow recursive deletion for junk directories",
                    },
                },
                "required": ["paths"],
            },
            fn=delete_junk_files,
        ),
        Tool(
            name="create_directory",
            description="Create a directory in allowed edit roots.",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            fn=create_directory,
        ),
        Tool(
            name="create_text_file",
            description="Create a new text file in allowed edit roots.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path"],
            },
            fn=create_text_file,
        ),
        Tool(
            name="write_text_file",
            description="Write full text content to a file in allowed edit roots.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                    "overwrite": {"type": "boolean"},
                },
                "required": ["path", "content"],
            },
            fn=write_text_file,
        ),
        Tool(
            name="append_text_file",
            description="Append text to a file in allowed edit roots.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
            fn=append_text_file,
        ),
        Tool(
            name="edit_text_file",
            description="Replace first matching text fragment in a file and keep a backup.",
            parameters={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "find_text": {"type": "string"},
                    "replace_text": {"type": "string"},
                },
                "required": ["path", "find_text", "replace_text"],
            },
            fn=edit_text_file,
        ),
    ]
