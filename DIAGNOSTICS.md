# Diagnostic agent reference

Snapshot: 2026-10-24. This guide covers `--agent` and legacy diagnostic unsafe mode.
Coding tools and their independent permissions are documented in [TECHNICAL.md](TECHNICAL.md).

## Start and inspect

```powershell
.\run.bat --agent
python main.py --agent --no-warmup --healthcheck
```

The agent combines intent classification, deterministic observations, LLM planning
and guided responses. A system snapshot is the initial diagnostic context.
Tool calling is needed for model-driven diagnostic work; hardware/provider
availability and OS permissions determine which observations can be collected.
Within the agent, `/tools` lists the actual registry for the active mode.

## Approval and audit

Guarded mutations create one pending action with an ID, arguments and summary.
Use `pending`, `approve <id>`, `cancel <id>`, `history actions` and `last action`.
Read-only flows can continue while an action is pending. A mismatched or stale ID
does not approve an action. Applicable confirmation flags are listed in
[TECHNICAL.md](TECHNICAL.md#configuration-reference).

When enabled, diagnostic lifecycle events are JSONL records in
`MEDFARL_ACTION_LOG_PATH`; package changes use the running Python interpreter.
Quarantine records preserve metadata for inspection/restoration and do not imply
that an arbitrary path is safe to remove. Antivirus operations require a detected
supported Windows Defender or ClamAV adapter.

`run-unsafe.bat`, `--unsafe-full-access` outside coder mode, or
`MEDFARL_UNSAFE_FULL_ACCESS=1` expands diagnostic roots and disables its confirmation
flags. Raw shell and copy/move/remove tools are registered only in this legacy
unsafe path. This differs from coder full file access, which retains approvals.
No mode automatically elevates Windows administrator privileges.

## Observation and diagnostic tools

Source: `tools/tools.py`. Parameters marked required come from the tool schema.

| Tool | Inputs | Availability |
| --- | --- | --- |
| `get_system_snapshot` | None | Registered in guarded mode |
| `get_disk_summary` | `top_n` | Registered in guarded mode |
| `get_top_processes` | `count`, `include_idle` | Registered in guarded mode |
| `get_network_summary` | None | Registered in guarded mode |
| `get_recent_errors` | `limit` | Registered in guarded mode |
| `get_installed_pip_packages` | None | Registered in guarded mode |
| `get_pip_outdated` | None | Registered in guarded mode |
| `get_system_packages_summary` | None | Registered in guarded mode |
| `get_failed_services` | None | Registered in guarded mode |
| `read_file` | `path` (required), `max_lines` | Registered in guarded mode |
| `list_directory` | `path` (required) | Registered in guarded mode |
| `run_safe_command` | `command` (required) | Registered in guarded mode |
| `ping_host` | `host` (required), `count` | Registered in guarded mode |
| `run_shell_command` | `command` (required), `shell`, `cwd`, `timeout` | Diagnostic unsafe only |

## Maintenance tools

Source: `tools/maintenance_tools.py`. Parameters marked required come from the tool schema.

| Tool | Inputs | Availability |
| --- | --- | --- |
| `run_program` | `path` (required), `args`, `cwd`, `timeout` | Registered in guarded mode |
| `pip_install_package` | `name` (required), `version`, `upgrade` | Registered in guarded mode |
| `pip_uninstall_package` | `name` (required) | Registered in guarded mode |
| `pip_check` | None | Registered in guarded mode |
| `pip_freeze` | None | Registered in guarded mode |
| `find_junk_files` | `scope`, `older_than_days`, `limit` | Registered in guarded mode |
| `show_quarantine` | `limit` | Registered in guarded mode |
| `move_junk_to_quarantine` | `paths` (required), `quarantine_dir` | Registered in guarded mode |
| `restore_from_quarantine` | `entry_ids` (required), `destination_root`, `overwrite` | Registered in guarded mode |
| `delete_junk_files` | `paths` (required), `recursive` | Registered in guarded mode |
| `create_directory` | `path` (required) | Registered in guarded mode |
| `create_text_file` | `path` (required), `content` | Registered in guarded mode |
| `write_text_file` | `path` (required), `content` (required), `overwrite` | Registered in guarded mode |
| `append_text_file` | `path` (required), `content` (required) | Registered in guarded mode |
| `edit_text_file` | `path` (required), `find_text` (required), `replace_text` (required) | Registered in guarded mode |
| `copy_path` | `source` (required), `destination` (required), `overwrite` | Diagnostic unsafe only |
| `move_path` | `source` (required), `destination` (required), `overwrite` | Diagnostic unsafe only |
| `remove_path` | `path` (required), `recursive` | Diagnostic unsafe only |

## Antivirus tools

Source: `tools/antivirus_tools.py`. Parameters marked required come from the tool schema.

| Tool | Inputs | Availability |
| --- | --- | --- |
| `detect_antivirus` | None | Registered in guarded mode |
| `update_antivirus_definitions` | `provider` | Registered in guarded mode |
| `run_antivirus_quick_scan` | `provider` | Registered in guarded mode |
| `run_antivirus_custom_scan` | `path` (required), `provider` | Registered in guarded mode |
| `list_antivirus_threats` | `limit`, `provider` | Registered in guarded mode |

## Safe-command keys and platform dependencies

`run_safe_command` accepts a fixed key, not an arbitrary command string.
The common key is `uptime`. Windows additionally registers `systeminfo`,
`ipconfig` and `route_print`. Other hosts register `df_h`, `free_h`, `ip_addr`,
`ip_route`, `journal_errors` and `lsblk`. Registration does not install an executable;
a missing command returns an availability error. These tools are separate from
the coder's approved general shell runner.

`ping_host` sends network traffic to the supplied host. Error-log sources, failed
services, GPU sensors and antivirus providers vary across Windows, Linux and macOS.
Unavailable observations should be reported as unavailable, not invented.

The parameter tables describe registrations, not blanket authorization. Runtime
path roots, guards, provider checks and applicable pending-action approvals still
apply. See source schemas for defaults and value bounds; the coder may have a
same-named tool with a different schema and approval workflow.
