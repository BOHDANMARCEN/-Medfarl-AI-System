# Medfarl Alpha Notes

Current alpha focuses on safe local diagnostics plus guarded maintenance.

## What works now

- Local tool-calling through Ollama with `qwen3.5:9b` as the default model.
- Deterministic diagnostic flows for:
  - overall PC diagnostics
  - processes
  - disks
  - network
  - logs
- Guided maintenance flows with explicit approval:
  - run approved programs
  - install/uninstall Python packages
  - create/write/append/edit text files
  - junk preview, quarantine, restore, and delete
- Interactive help menu with 3 quick choices (`1/2/3`) and deterministic fallback when help LLM calls fail.
- Antivirus adapters for Windows Defender and ClamAV.
- Generic antivirus quick scan now goes through explicit approval when a provider is available.
- Single pending-action policy with:
  - `pending`
  - `approve <action_id>`
  - `cancel <action_id>`
  - `history actions`
  - `last action`
- Read-only inspection stays available while a mutating action is pending.
- JSONL audit log for pending, approved, cancelled, and executed actions.

## Smoke checks

Run these before calling the build stable:

```bash
python main.py --healthcheck
python scripts/smoke_intents.py
python scripts/smoke_maintenance.py
```

## Known alpha limitations

- Only one pending mutating action is supported at a time.
- Antivirus provider availability depends on the host machine.
- Quarantine restore is safest when restoring into allowed edit roots.
- The model can still vary in tone; deterministic flows reduce, but do not fully remove, LLM variability.

## Recommended release positioning

- `diagnose mode`: stable enough for alpha use.
- `repair mode`: guarded and usable for alpha testing.
- `dangerous actions`: available, approval-gated, and should still be treated cautiously.
