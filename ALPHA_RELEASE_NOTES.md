# Medfarl v0.2.0-alpha Release Notes

Release date: 2026-03-23

`v0.2.0-alpha` is the first public chat-first alpha of the new Medfarl architecture.
It keeps the guarded PC Doctor flows, adds stronger interactive CLI behavior, and
introduces an opt-in unsafe local-agent mode for trusted sessions.

## What works now

- Local tool-calling through Ollama with `qwen3.5:9b` as the default model.
- Chat-first routing with explicit assistant behaviors for:
  - direct response
  - clarification
  - tool use
  - guided/manual mode
- Deterministic fast paths for:
  - overall PC diagnostics
  - processes
  - disks
  - network
  - logs
- Guided maintenance flows in guarded mode with explicit approval:
  - run approved programs
  - install/uninstall Python packages
  - create/write/append/edit text files
  - junk preview, quarantine, restore, and delete
- Interactive help menu with 3 quick choices (`1/2/3`) and deterministic fallback when help LLM calls fail.
- Antivirus adapters for Windows Defender and ClamAV.
- Generic antivirus quick scan now goes through explicit approval when a provider is available.
- Better Windows CLI reliability:
  - UTF-8/Cyrillic input handling fixed
  - clearer Ollama-offline recovery messaging
- Single pending-action policy with:
  - `pending`
  - `approve <action_id>`
  - `cancel <action_id>`
  - `history actions`
  - `last action`
- Read-only inspection stays available while a mutating action is pending.
- JSONL audit log for pending, approved, cancelled, and executed actions.
- Opt-in `--unsafe-full-access` mode now enables:
  - unrestricted filesystem roots across local drives
  - direct local program execution without approval gates
  - raw `cmd` / `PowerShell` execution through registered tools
  - CLI-style file operations such as `copy`, `move`, `rm`, and `mkdir`
  - multi-line shell mode via `/shell powershell` or `/shell cmd`

## Smoke checks

Run these before calling the build stable:

```bash
python main.py --healthcheck
python scripts/smoke_intents.py
python scripts/smoke_maintenance.py
python -m unittest tests.test_chat_routing tests.test_unsafe_mode
```

## Known alpha limitations

- Only one pending mutating action is supported at a time.
- Antivirus provider availability depends on the host machine.
- Quarantine restore is safest when restoring into allowed edit roots.
- The model can still vary in tone; deterministic flows reduce, but do not fully remove, LLM variability.
- Unsafe mode is intentionally powerful and should be treated as a trusted local operator mode.
- Multi-line shell mode currently executes the full buffered block as one command when you call `/end`.

## Recommended release positioning

- `chat-first local PC Doctor`: ready for alpha users.
- `guarded maintenance mode`: usable and auditable for alpha testing.
- `unsafe full access mode`: experimental but available for trusted local power-user workflows.
