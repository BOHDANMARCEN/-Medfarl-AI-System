# Coding workflows and Claude Code compatibility

See [README](readme.md) for installation and [TECHNICAL.md](TECHNICAL.md) for
module ownership, tool contracts, state formats and configuration. Snapshot: 2026-10-24.

Medfarl implements the local workflows below using the configured Ollama model.
The default remains `tripolskypetr/qwen3.5-uncensored-aggressive:4b`.
This is a documented compatibility subset, not a complete Claude Code replacement.

| Area | Implemented in Medfarl | Boundaries |
| --- | --- | --- |
| Files and projects | Read/search/list, create directories/projects, exact edits, full rewrites with hashes, multi-file approvals | UTF-8 text; 32 files per batch; no native image/PDF/notebook editor |
| Skills | `SKILL.md`, YAML name/description, `$ARGUMENTS`, `${SKILL_DIR}`, supporting files, tool restrictions, explicit-only skills, legacy project commands | No shell expansion, automatic scripts, fork/model/hooks frontmatter or marketplace synchronization |
| Plans and tasks | `/plan`, `/mode edit`, task checklist and deterministic tool restrictions | Read-only Git inspection is allowed; general shell, writes, hooks and MCP are blocked in plan mode |
| Memory and rules | Root/nested `CLAUDE.md`, `.claude/CLAUDE.md`, `.claude/rules/*.md` with path patterns, project notes | No `@file` imports or proprietary automatic memory engine; notes are saved with approval |
| Sessions | Explicit save/list/resume, transcript compaction, tracked file history | JSON files are Medfarl's own format; no Claude transcript migration or automatic background saving |
| Checkpoints | Named file snapshots and approved rewind; external edits are preserved | Tracks file-tool changes only; shell changes, external files, directories and Git state are not rewound |
| Analysis agents | Built-in explorer/reviewer and `.claude/agents/*.md` bodies, isolated context | Sequential and read-only; same selected model; no team scheduler, nested agents or worktree isolation |
| Hooks | Approved `PreToolUse` and `PostToolUse` command hooks with event JSON on stdin | Native Medfarl tool names/arguments; no other lifecycle events, prompt/agent/HTTP hooks or automatic approval |
| MCP | Explicit connection, initialization, tool discovery/calls, local stdio and Streamable HTTP JSON/SSE | Protocol 2025-03-26; no OAuth flow, legacy SSE endpoint, resources, prompts, sampling, elicitation or reconnect daemon |
| Git | Read-only status/diff/log tools; normal Git commands with approval | No dedicated worktree/PR manager or automatic publishing |
| Batch use | `-p` / `--prompt`, `--plan`, `--resume` | Text output, no JSON event stream; EOF denies actions, never auto-approves them |
| Local model control | `/model`, `/doctor`, current permissions display | No Claude subscription, Anthropic cloud, IDE/LSP integration, browser automation or remote-control service |

## Start

```powershell
.\run-coder.bat
.\run-coder.bat --plan
.\run-coder.bat --workspace "E:\My App" -p "Explain the project" --plan
.\run-coder.bat --resume work
```

Entering `/coder` in normal chat opens the same coding workflow.
`/help` lists commands. No runtime extension disables write or command confirmations.

## Skills

Bundled original workflows: `/review`, `/debug`, `/test`, `/refactor`, `/docs`,
`/commit`, `/implementation-plan`. `/commit` can only be invoked by the user.
Skills are loaded from these locations, in increasing precedence:

1. This application's `skills/` directory.
2. `~/.claude/skills/` and `~/.medfarl/skills/`.
3. Project `.claude/commands/*.md`, `.claude/skills/*/SKILL.md`, `.medfarl/skills/*/SKILL.md`.

`/skills` lists them and parse errors. `/<name> arguments` or `/skill name arguments`
runs one. The model can use `load_skill` for skills without
`disable-model-invocation: true`; names/descriptions appear in context, bodies load
on invocation. `user-invocable: false` hides manual invocation.
`allowed-tools` restricts tools for that turn and never grants permissions.
Supported aliases: Read, Glob, Grep, Write, Edit, Bash. Argument-specific permission
patterns are rejected. Unknown tool names grant no tools.
Supporting files are read with `read_skill_file`, confined to that active skill's directory.
Shell substitutions such as `!command` are never executed by the skill loader.

```markdown
---
name: inspect-api
description: Inspect an API module without making changes.
allowed-tools: [Read, Glob, Grep]
---
Read the API implementation for $ARGUMENTS, trace callers, and report concrete bugs.
```

## Plans, memory and sessions

```text
/plan Investigate how to add authentication
/tasks
/mode edit
/init
/remember Tests for this project use unittest.
/memory
/save work
/sessions
/resume work
/compact
```

`/init` offers to create `CLAUDE.md`; it preserves any existing file.
`/remember` appends to `.medfarl/memory.md` after showing the change.
The root instructions load on each model request. Nested `CLAUDE.md` and path-scoped
rules load after a file under their scope is read. Rule patterns use Python-style
glob matching, with a zero-directory fallback for `**/`.

`/save` stores history, tasks, mode and tracked file baselines under
`.medfarl/sessions/`. It may include file contents and sensitive conversation data;
these directories are ignored by this repository's Git rules. Saving is explicit.
Starter project templates include the same ignore entries. For existing projects,
add `.medfarl/sessions/` and `.medfarl/checkpoints/` to their `.gitignore` before staging files.
Resume replaces the current history after confirmation, preserves the currently
selected model and revokes full filesystem access. No saved tool call is executed.
Plan mode blocks saves as well as other writes; switch to edit mode to save.
`/compact` uses the local model to summarize history, while keeping memory and tasks.

## Checkpoints and analysis agents

```text
/checkpoint before-change
/rewind before-change
/agents
/agent explorer Find the code handling startup
/agent reviewer Inspect the current diff
```

Create a checkpoint before the next edits. Rewind shows the exact changes,
including removal of newly created files, and asks for approval. It refuses to
overwrite files whose current contents differ from the last file-tool write.
It leaves directories in place. A partial I/O failure reports completed paths.
Checkpoints and saved sessions can be used together across restarts.

Analysis agents use a fresh conversation and return a result to the caller. They
cannot write files, run shell, invoke hooks/MCP or create more agents. Custom agent
files use `name` plus their Markdown body; other Claude agent settings are not applied.

## MCP configuration

Nothing connects on startup. Store servers in `.mcp.json` or `.medfarl/mcp.json`:

```json
{
  "mcpServers": {
    "demo": {
      "command": "python",
      "args": ["-u", "-m", "tools.mcp_echo_server"]
    },
    "remote": {
      "type": "http",
      "url": "https://your-server.example/mcp",
      "headers": {"Authorization": "Bearer ${MY_MCP_TOKEN}"}
    }
  }
}
```

The bundled demo is available when the working directory is this repository;
for other projects use the absolute path to `tools/mcp_echo_server.py`.
The remote entry is an example requiring a real endpoint and token.
`${ENV_NAME}` is resolved only when connecting; missing values cause an error.

```text
/mcp
/mcp connect demo
/tools
Call mcp__demo__echo with text "hello"
/mcp disconnect demo
```

Connection and each tool call require separate approval. Connected servers expose
`mcp__<server>__<tool>` functions. Servers run with OS permissions, so an approved
server process is not a filesystem sandbox. Connections close on exit/project switch.
HTTP JSON and response SSE are supported. Use another client for an OAuth-only server.

## Hooks

Only the `hooks` block of `.claude/settings.json` and `.medfarl/settings.json`
is interpreted. Claude permission settings are not imported or trusted.
This example blocks shell tools after approval of the hook command:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "run_command",
      "hooks": [{"type": "command", "shell": "powershell", "command": "exit 2"}]
    }]
  }
}
```

Matchers are regular expressions against native Medfarl tool names. Command hooks
receive JSON with `hook_event_name`, `cwd`, `tool_name`, `tool_input`, and
`tool_response` on stdin. Every command requires approval. A denied/nonzero pre-hook
prevents the tool. A failing post-hook reports that the tool action already completed.
Hooks cannot approve another action. They do not run during plan/read-only analysis
or when the active skill does not permit shell execution. `/hooks` shows configuration.

## Reference and scope

The compatibility surface follows public documentation, with independently written
workflows and runtime code:
[skills](https://code.claude.com/docs/en/skills),
[memory](https://code.claude.com/docs/en/memory),
[hooks](https://code.claude.com/docs/en/hooks),
[MCP](https://code.claude.com/docs/en/mcp),
[MCP transports](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports).
Claude's service, model behavior, IDE integrations and proprietary/cloud features
are outside this implementation. Local model quality still affects planning and tool choice;
permissions and plan-mode restrictions are enforced by the runtime.
