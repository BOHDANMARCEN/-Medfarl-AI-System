# Medfarl AI System

[Українська](readme.md) · **English**

**A local AI assistant for conversation, coding, and PC diagnostics.**

Medfarl is a Python terminal application that runs models through Ollama. It combines direct chat, an agent for creating and editing projects, and PC maintenance tools. The model receives actual tool results: file contents, system metrics, command output, and action status.

**Windows** is the primary development and verification environment. The application includes `.bat` launchers and supports Windows PowerShell, PowerShell 7, and CMD. Some functionality is available through Python on other operating systems; system adapters and shells depend on the platform.

[Quick start](#quick-start) · [Operating modes](#operating-modes) · [Coding](#working-with-code) · [Terminal and access](#terminal-and-access-permissions) · [Configuration](#configuration) · [Testing](#testing)

## Features

| Area | Implemented functionality |
| --- | --- |
| Chat | Conversation history, streaming output, custom system instructions, and model selection |
| Coding | File search and reading, directory creation, targeted replacements, batch edits, change previews, tests, and commands |
| Project creation | `python`, `web`, and `empty` templates, plus custom file sets through `create_project` |
| Workflows | Skills, planning mode, task lists, project instructions, and project memory |
| Saved work | Local sessions, history compaction, file checkpoints, and restoration with conflict checks |
| Analysis | Separate, sequential, read-only `explorer` and `reviewer` agents |
| Integrations | MCP tools over stdio or HTTP; command hooks before and after tool execution |
| PC diagnostics | CPU, RAM, disks, processes, networking, available temperature sensors, and NVIDIA GPU metrics |
| Maintenance | Python package inspection, file operations, program execution, temporary file discovery, and quarantine |
| Antivirus | Windows Defender and ClamAV adapters: detection, scanning, definition updates, and available scan results |

Diagnostic data depends on the operating system, hardware, and installed services. Medfarl uses an existing antivirus engine rather than replacing it.

## Quick start

### Requirements

- **Python 3.10+**.
- **Ollama** and a downloaded model.
- **Git** for cloning the repository and using the coder's Git tools.
- A model with **tool calling** support for coding and diagnostic agent modes.

RAM, VRAM, and disk requirements depend on the selected model. An NVIDIA GPU is not required to start the application.

### Windows installation

After installing Python, Git, and Ollama, run the following in PowerShell:

```powershell
git clone https://github.com/BOHDANMARCEN/-Medfarl-AI-System.git
cd .\-Medfarl-AI-System

python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

ollama pull tripolskypetr/qwen3.5-uncensored-aggressive:4b
.\run.bat
```

The model in this example is the current default in `config.py`. Override it with `--model` or environment variables.

`run.bat` uses `.venv\Scripts\python.exe` when present, otherwise `python` from `PATH`. It checks imports for `httpx`, `psutil`, and `yaml`, and installs dependencies from `requirements.txt` if needed.

By default, the application attempts to start Ollama and preload the model into memory. **Model weights are not downloaded automatically**: run `ollama pull` first.

### Connection checks

```powershell
.\run.bat --list-models
.\run.bat --no-warmup --healthcheck
.\run.bat --coder --no-warmup --healthcheck
```

The standard check verifies Ollama and model availability. With `--coder` or `--agent`, it also checks whether requests containing tool definitions are accepted; this does not guarantee that the model will use tools effectively.

## Operating modes

| Mode | Launch | Behavior |
| --- | --- | --- |
| Chat | `.\run.bat` | Conversation without file or diagnostic tools |
| Coder | `.\run-coder.bat` | Project work; edits and commands require approval by default |
| Planning | `.\run-coder.bat --plan` | Research and planning without file writes, arbitrary shell commands, hooks, or MCP calls |
| Diagnostics | `.\run.bat --agent` | System tools and controlled maintenance actions |
| Agent with full access | `.\run-unsafe.bat` | Diagnostic agent, arbitrary shell commands, and file actions without additional approvals |
| Coder with full access | `.\run-coder-full-access.bat` | Access beyond the project directory and actions without additional approvals |

`--agent` and `--coder` are mutually exclusive. `--prompt`, `--plan`, and `--resume` automatically select coder mode and cannot be combined with `--agent`.

Enter coder mode from chat or diagnostics with:

```text
/coder "E:\Projects\my-app"
```

`/quit` returns to the previous chat. When the coder is launched directly, it exits the application.

Additional launchers:

- `Medfarl_Menu.bat` provides a model and mode menu; option **18** opens diagnostics and **19** opens the coder.
- `run-quick.bat` skips the startup health check but retains model preloading.
- `run-streaming.bat` explicitly enables streaming, which is also the default.

## Working with code

### Opening and creating projects

```powershell
.\run-coder.bat --workspace "E:\Projects\my-app"
```

If the workspace does not exist, the coder offers to create it. Inside a session:

```text
/new python "calculator"
/new web "landing-page"
/new empty "new-app"
/open "E:\Projects\existing-app"
/project
/diff
```

`/new` creates and opens a project. The `python` template includes a CLI and a unittest test; `web` includes HTML, CSS, and JavaScript; `empty` includes a README and `.gitignore`. Creating a template does not install packages or run the generated application.

Describe tasks in natural language:

```text
Create a Python calculator project with tests and verify that it works.
Read parser.py, identify the cause of the error, and fix it.
Handle empty input and run the relevant tests.
```

The coder supports reading, searching, creating files, targeted replacements, and batch edits. Overwriting through `write_file` requires the current SHA-256 from `read_file`. External changes are checked before writing.

File tool limits:

- Up to **512 KiB** per text file.
- **1–32 files** and up to **2 MiB** per batch edit.
- Atomic writes for individual files.
- A batch is not a single transaction: files already written may remain changed if a later operation fails.
- Direct file tool access to `.git` internals is blocked even with expanded access.

### Coder commands

| Commands | Purpose |
| --- | --- |
| `/help`, `/status`, `/tools`, `/project` | Help, session status, available tools, and workspace |
| `/new python\|web\|empty "path"`, `/open "path"` | Create or open a project |
| `/diff` | Changes tracked by the current session's file tools |
| `/plan [task]`, `/mode edit`, `/tasks` | Planning, return to execution, and task list |
| `/skills`, `/skill name [arguments]` | List and run skills |
| `/review`, `/debug`, `/test`, `/refactor`, `/docs` | Bundled workflows |
| `/commit`, `/implementation-plan` | Commit and implementation planning workflows |
| `/init`, `/remember text`, `/memory` | Create `CLAUDE.md`, add notes, and read notes |
| `/save name`, `/sessions`, `/resume name`, `/compact` | Save, restore, and compact conversation history |
| `/checkpoint name`, `/rewind name` | File checkpoints and restoration |
| `/agents`, `/agent reviewer task` | Separate analysis without changes |
| `/mcp`, `/mcp connect name`, `/mcp disconnect name` | Manage MCP connections |
| `/hooks`, `/permissions`, `/model [name]`, `/doctor` | Integrations, permissions, model, and environment information |
| `/access full`, `/access project` | Expand or narrow the file tools' scope |
| `/reset`, `/quit` | Clear history or exit |

Skill commands pass instructions to the model; their outcome depends on the model and available tools. `/commit` is not an unconditional invocation of `git commit`.

### Skills, instructions, and memory

Skills load from the bundled `skills/` directory, personal `~/.claude/skills` and `~/.medfarl/skills` directories, and project directories `.claude/commands`, `.claude/skills`, and `.medfarl/skills`. Project definitions take precedence over personal and bundled definitions. `allowed-tools` restricts the tools available for a task but does not grant additional permissions.

The coder reads root-level `AGENTS.md`, `QWEN.md`, `GEMINI.md`, `CLAUDE.md`, `.claude/CLAUDE.md`, and `.medfarl/memory.md`. Nested `CLAUDE.md` files and matching `.claude/rules/` rules are included based on the files that have been read.

| Data | Location |
| --- | --- |
| Project memory | `.medfarl/memory.md` |
| Saved sessions | `.medfarl/sessions/` |
| Checkpoints | `.medfarl/checkpoints/` |
| Custom analysis agents | `.claude/agents/*.md` |

Sessions are stored locally without encryption. Session and checkpoint directories are excluded by this repository's and the templates' `.gitignore` files; check the ignore rules when working in another project.

`/rewind` covers tracked file changes, not the entire disk, Git state, or arbitrary effects of shell commands. External changes block restoration of conflicting files. `/reset` clears the conversation while preserving files and access mode. `/resume` retains the current model and narrows file tool access to the project; it does not revoke automatic approval in a session launched with `--unsafe-full-access`.

### Coder persona

The coder uses **Kohana 3.1** from `persona/persona_kohana_v3_1.xml`. The XML is validated and added to system instructions when a `CoderSession` is created. Open a new session after changing the persona. A missing or malformed file produces an explicit error.

The persona applies only to `--coder` and `/coder`. References to external tools in its text do not install or connect those tools. The full persona is included in model requests and consumes part of the context window.

## Terminal and access permissions

### Standard mode

The coder's file tools are confined to the workspace. Edits display a preview; command approvals show the shell, directory, and timeout. `y`, `yes`, or `так` approves an action; Enter or end-of-input denies it.

`/access full` expands file tool scope but **does not disable approvals** in a standard session. `/access project` restricts file tools specifically: it does not sandbox shell commands or external servers.

### Full access

```powershell
.\run-unsafe.bat
.\run-coder-full-access.bat --workspace "E:\Projects\my-app"
```

The equivalent Python CLI flag is `--unsafe-full-access`. The environment variable `MEDFARL_UNSAFE_FULL_ACCESS=1` is also supported.

In this mode, agent and coder actions run without additional approval prompts. For the coder, this also applies to MCP connections, external calls, hooks, and local state saves. Planning mode continues to block writes and command execution.

**Commands run with the current OS user's permissions.** The application does not automatically grant administrator privileges or isolate shell commands from the rest of the filesystem or network.

### Shells

| `shell` value | Execution |
| --- | --- |
| `powershell` | Windows PowerShell through `powershell.exe` |
| `pwsh` | PowerShell 7, when `pwsh` is on `PATH` |
| `cmd` | Windows Command Prompt through `cmd.exe` |
| `sh` | A compatible shell, if installed; available through the coder's command tool |

The shared runner supports multiline scripts, UTF-8, exit codes, bounded output, and process-tree termination after a timeout. Each call starts a new process: variables and directory changes do not persist between commands. Set the working directory through `cwd`. Interactive applications that expect ordinary terminal input are not the runner's primary use case.

The diagnostic agent provides direct multiline input in full-access mode:

```text
/shell powershell
Get-Location
Get-ChildItem -File | Select-Object -First 5
/end
```

`/shell cmd` selects CMD, `/show` displays the buffer, and `/cancel` discards it. Invoke PowerShell 7 with a separate request such as `pwsh Get-Date`. In coder mode, the `run_command` tool executes shell commands as part of a task.

## PC diagnostics and maintenance

```powershell
.\run.bat --agent
```

Example requests:

```text
Run a general PC diagnostic check.
Show the heaviest processes.
Check disks and free space.
Check network status.
Show errors in system logs.
```

The agent uses a system snapshot, specialized tools, and request routing. Some standard requests are handled without model-generated responses; general requests require an available LLM for full functionality.

Maintenance tools cover:

- Dependency checks, `pip freeze`, and Python package installation and removal in the current interpreter's environment.
- Text file creation and editing, and execution of permitted programs.
- Temporary file discovery, quarantine, inspection, and restoration.
- Windows Event Log or `journalctl`, when available.
- Scanning and updates through an available Windows Defender or ClamAV provider.

In standard mode, read, write, and execution roots are configured separately and default to the process's current directory. These settings are separate from the coder's `--workspace`.

Approval commands are `pending`, `approve <id>`, and `cancel <id>`. Only one action can be pending at a time. Use `history actions` and `last action` to inspect activity. The diagnostic audit log defaults to `medfarl_actions.log`; it is not a complete log of all coder actions.

## MCP and hooks

The coder reads MCP configuration from `.mcp.json` and `.medfarl/mcp.json` in the workspace. It supports local servers through `command`/`args`, and HTTP servers through `url` with optional `headers`. `${VARIABLE}` values are expanded from environment variables.

Discovering a configuration does not automatically connect its servers:

```text
/mcp
/mcp connect my-server
/mcp disconnect my-server
```

Hooks load from `.claude/settings.json` and `.medfarl/settings.json`. Command hooks are implemented for `PreToolUse` and `PostToolUse`; they receive JSON context through stdin. Planning mode disables hooks and MCP calls.

Compatibility with `.claude` formats is partial: this is not a complete implementation of the external platform, OAuth, IDE/LSP integration, cloud agent teams, or every plugin mechanism. Built-in analysis agents run **sequentially**, with separate context and no permission to edit files or run shell commands.

## Configuration

Configuration is read from environment variables at startup. `.env` files are not loaded automatically.

Model selection priority:

- Chat and diagnostics: `--model` → `MEDFARL_MODEL` → the default in `config.py`.
- Coder: `--model` → `MEDFARL_CODER_MODEL` → the configured main model.

```powershell
$env:MEDFARL_CODER_MODEL = "your-installed-model-name"
.\run-coder.bat --timeout 240
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `MEDFARL_LLM_URL` | `http://localhost:11434` | Backend root URL, without a trailing `/v1` |
| `MEDFARL_MODEL` | `tripolskypetr/qwen3.5-uncensored-aggressive:4b` | Main model |
| `MEDFARL_CODER_MODEL` | Main model | Separate coder model |
| `MEDFARL_TIMEOUT` | `120` | HTTP request timeout, in seconds |
| `MEDFARL_KEEP_ALIVE` | `30m` | Model retention time for preload requests |
| `MEDFARL_AUTOSTART_OLLAMA` | `1` | Allow automatic Ollama startup |
| `MEDFARL_WARMUP` | `1` | Preload the model |
| `MEDFARL_MAX_TOOL_STEPS` | `8` | Diagnostic agent loop limit; the coder has a separate limit |
| `MEDFARL_CHAT_SYSTEM_PROMPT` | Built-in instructions | Direct chat system prompt |
| `MEDFARL_CHAT_REASONING_EFFORT` | `none` | Direct chat reasoning parameter |
| `MEDFARL_UNSAFE_FULL_ACCESS` | `0` | Full access without additional approvals |

Diagnostic agent settings:

| Variable | Default |
| --- | --- |
| `MEDFARL_ALLOWED_READ_ROOTS`, `MEDFARL_ALLOWED_EDIT_ROOTS`, `MEDFARL_ALLOWED_EXEC_ROOTS` | Current process directory |
| `MEDFARL_CONFIRM_EXEC`, `MEDFARL_CONFIRM_DELETE`, `MEDFARL_CONFIRM_PACKAGE_CHANGES`, `MEDFARL_CONFIRM_FILE_EDITS` | `1` |
| `MEDFARL_ENABLE_ACTION_LOG` | `1` |
| `MEDFARL_ACTION_LOG_PATH` | `medfarl_actions.log` in the current directory |
| `MEDFARL_JUNK_QUARANTINE_DIR` | `junk_quarantine` in the current directory |

Directory lists use `;` on Windows and `:` on POSIX systems. Diagnostic confirmation settings do not control standard coder approvals.

### Useful CLI options

```powershell
.\run.bat --help
.\run.bat --no-stream
.\run-coder.bat --plan -p "Study the project architecture and prepare a change plan"
.\run-coder.bat --resume work
.\run-coder-full-access.bat -p "Read the README and inspect the project structure"
```

`-p` runs one task and exits. In standard mode, approvals remain active; end-of-input on stdin denies an action. Running without approval prompts requires explicitly selecting full access.

`--skip-healthcheck` skips the preflight check; `--no-warmup` disables automatic Ollama startup and model preloading. These options are independent. `--benchmark-models` runs a short comparison of installed models using diagnostic requests.

Generation uses `/v1/chat/completions`, while model listing, checks, and warmup use Ollama APIs. An arbitrary OpenAI-compatible server is not guaranteed to be a complete replacement for Ollama.

## Repository structure

```text
main.py                       CLI, startup, and mode switching
config.py                     Configuration and access policy
core/
  chat.py                     Direct chat
  agent.py                    Diagnostic request routing and agent loop
  coder.py                    Coder, file tools, and coder CLI
  coder_extensions.py         Skills, memory, sessions, checkpoints, analysis
  coder_integrations.py       MCP and hooks
  coder_persona.py            Persona loading
  llm_client.py               Ollama, generation, and streaming responses
  shell_runner.py             Shared shell execution
  system_scanner.py           System metrics
  file_ops.py                 File operations and quarantine
  program_runner.py           Program execution
  package_manager.py          pip operations
  antivirus.py                Antivirus adapters
  approval.py, audit.py        Diagnostic approvals and audit logging
  project_templates.py        Project templates
  action_guard.py             Allowed-path checks
  lib_inspector.py            Packages and services
persona/                      Coder XML persona
skills/                       Bundled workflows
tools/                        Tool registries and a test MCP server
ui/                           Terminal interface
tests/                        Automated tests
scripts/                      Supporting checks
```

Dependencies are defined in `requirements.txt`: `httpx`, `psutil`, `PyYAML`, and `pynvml`. The last package provides optional NVIDIA telemetry but is included in the general installation requirements.

## Testing

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Latest Windows verification, **October 31, 2026**: **99 tests — 98 passed, 1 skipped**. This is a recorded local test run, not a live CI status.

Tests cover chat and routing, coder file operations, templates, skills, planning, sessions, checkpoints, hooks, MCP, full access, and shell execution. Regression tests cover Unicode, multiline CMD, exit codes, timeouts and child processes, backup preservation, and source protection during copy or move operations.

Passing tests does not establish response quality for every model or compatibility with every external MCP server. See the [October 31, 2026 audit](AUDIT_2026-10-31.md) for recent fixes and verification limits.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Ollama is unavailable | Confirm that Ollama is installed, the server is running, and `MEDFARL_LLM_URL` is correct; run `ollama serve` if needed |
| Model not found | Use `ollama list` or `--list-models`; download it with `ollama pull` and verify its exact name |
| Chat works but tools do not | Check the model with `--coder --no-warmup --healthcheck`, or the equivalent for `--agent` |
| Model request times out | Increase `--timeout`; consider available hardware, model size, and context length |
| Shell is not installed | Check `PATH`; `pwsh` requires a separate PowerShell 7 installation |
| Path is outside the allowed scope | For the coder, check `--workspace` and `/permissions`; for diagnostics, check `MEDFARL_ALLOWED_*_ROOTS` |
| A command cannot run in planning mode | Switch to `/mode edit` when research is complete |
| GPU, service, or antivirus information is missing | Check the hardware, drivers, provider, and adapter availability on the current OS |

Direct chat has no file tools. Open `/coder` to create or edit files rather than receive code as text only.

## Data and implementation boundaries

With the default `localhost` URL, model requests go to the local Ollama service. Selecting a remote backend, running network commands, querying package repositories, or connecting external MCP servers may transmit data beyond the computer.

The current interface is a CLI. The codebase does not include a graphical editor, embedded browser, full IDE, or persistent interactive terminal session. Support for other operating systems does not imply complete diagnostic feature parity with Windows.

## Documentation

- [Ukrainian README](readme.md)
- [Launch guide](ІНСТРУКЦІЯ_ЗАПУСКУ.md)
- [Technical overview](TECHNICAL.md)
- [Diagnostic tools](DIAGNOSTICS.md)
- [Format and extension compatibility](CLAUDE_COMPATIBILITY.md)
- [Streaming responses](STREAMING_README.md)
- [Changelog](CHANGELOG.md)
- [Verification report: October 31, 2026](AUDIT_2026-10-31.md)

Some topic-specific documents describe earlier revisions, and some are in Ukrainian. For full-access behavior, use this README and the current code; older statements that coder approvals are always required do not apply to `--unsafe-full-access`.

## License

The code is distributed under the [Apache License 2.0](LICENSE). Models and third-party components have their own licenses and terms of use.
