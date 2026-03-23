# Changelog

All notable product-facing changes are documented here.

## v0.2.0-alpha - 2026-03-23

First public chat-first alpha release of the new Medfarl architecture.

### Highlights

- Medfarl was refactored from a mostly deterministic router into a chat-first local assistant with planner-driven routing.
- An opt-in unsafe mode now enables Gemini-CLI-like local agent behavior with full filesystem access, raw Windows shell execution, and direct program launch.
- Windows CLI stability and offline UX were improved, including UTF-8 input fixes and friendlier Ollama-unavailable messages.

### Added

- Chat-first routing with explicit assistant behaviors for direct response, clarification, tool use, and guided/manual mode.
- Interactive help menu with short category choices (`1`, `2`, `3`) and deterministic fallback behavior.
- Expanded smoke and unit coverage for routing, maintenance flows, quarantine, pending-action behavior, and unsafe mode.
- Opt-in `--unsafe-full-access` session mode.
- Unsafe-mode shell access via `cmd` and `PowerShell`.
- Unsafe-mode filesystem actions for any local path:
  - `copy`
  - `move`
  - `rm` / `delete` / `rmdir`
  - `mkdir`
- Multi-line shell mode in the CLI:
  - `/shell powershell`
  - `/shell cmd`
  - `/end`
  - `/cancel`
  - `/show`
- New CLI slash commands:
  - `/help`
  - `/reset`
  - `/status`
  - `/tools`
  - `/quit`

### Changed

- Default UX is now more conversational and closer to a terminal AI assistant than a strict command parser.
- Planner prompts, direct-response prompts, and guided/manual prompts were separated and cleaned up.
- Unsafe mode now disables approval gates and expands read/edit/exec roots across local drives.
- `run_program` in unsafe mode can resolve local executables more flexibly, including common Windows command entry points.
- README and release docs now document guarded mode vs unsafe mode more clearly.

### Fixed

- Fixed Windows CLI input handling for Cyrillic/UTF-8 text by reconfiguring `stdin` as well as output streams.
- Improved runtime behavior when Ollama is unavailable with a clearer error message and actionable recovery steps.
- Reduced false dead-ends in interactive help and pending-action flows.

### Hardening

- Read-only flows remain available while a mutating action is pending.
- Approval, quarantine, antivirus, and recovery scenarios received stronger regression coverage.
- Safer fallback behavior was added for unavailable LLM/tool situations.

### Docs

- Updated README examples for unsafe mode, slash commands, shell mode, and local file operations.
- Refreshed author credits and core development team section.
