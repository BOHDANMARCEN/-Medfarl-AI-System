# Changelog

All notable product-facing changes are documented here.

## Unreleased — development snapshot 2026-10-24

### Added

- Separate project coder (`--coder`, `run-coder.bat`, menu option 19) and `/coder` entry from chat.
- Project templates, custom multi-file manifests, approved batch edits, SHA-256 rewrite checks and `/diff`.
- Portable `SKILL.md` loading, seven original bundled workflows, per-turn tool restrictions and supporting-file reads.
- Runtime-enforced plan mode and in-memory task checklists.
- CLAUDE project instructions/rules, approved memory notes, explicit session save/resume and compaction.
- File checkpoints and conflict-aware rewind, preserving external edits.
- Isolated, sequential, read-only analysis agents.
- Explicit MCP stdio/HTTP JSON/SSE tool connections and approved command hooks.
- Single-task `--prompt`, coder `--plan`/`--resume`, model selection and runtime inspection commands.
- `PyYAML` dependency and a local MCP echo demonstration server.
- Technical architecture and a detailed Claude Code compatibility matrix.

### Changed

- Default model: `tripolskypetr/qwen3.5-uncensored-aggressive:9b`.
- Default startup opens direct streaming chat; diagnostics use `--agent`.
- Ollama may start automatically and preload the selected model; model downloads remain explicit.
- Launchers check imports of all required base packages.
- Session/checkpoint directories are Git-ignored in this repository and generated templates.
- README, Ukrainian launch guide and streaming documentation now describe the current mode boundaries.

### Fixed

- Streaming function-call fragments are assembled by index, with all calls preserved for the coder.
- Completed tool activity receives a factual fallback summary if the model returns an empty final reply.
- Coder action confirmations remain enabled when file access is expanded.
- Fixed read-only Git inspection avoids configured external filters and other executable read helpers.

### Verification and scope

- Windows snapshot: 80 tests; 79 passed and one symbolic-link test skipped.
- Manual checks covered the configured Qwen 9B, generated Python tests, plan-mode reads,
  session restoration, terminal commands and the local MCP demonstration server.
- HTTP transport tests use mocked JSON/SSE responses; authenticated remote MCP services were not verified.
- Claude compatibility is a documented subset; this entry does not announce a new release tag.

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
