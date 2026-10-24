# Medfarl AI System

Local AI chat, a project coding agent, and PC diagnostics in one terminal application.

Default model: **`tripolskypetr/qwen3.5-uncensored-aggressive:4b`**, served by Ollama
at `http://localhost:11434`. Chat streams by default. The coder creates and edits
files, runs approved commands, and supports skills, plans, project memory, saved
sessions, checkpoints, analysis agents, hooks and MCP tools.

Development additions since the documented `v0.2.0-alpha` are listed in
[CHANGELOG.md](CHANGELOG.md). They have not been assigned a new release tag.

## Documentation

- [Українська інструкція запуску](ІНСТРУКЦІЯ_ЗАПУСКУ.md)
- [Technical architecture, contracts and configuration](TECHNICAL.md)
- [Diagnostic tools and maintenance approvals](DIAGNOSTICS.md)
- [Coding commands and Claude Code compatibility](CLAUDE_COMPATIBILITY.md)
- [Streaming behavior](STREAMING_README.md)
- [Implementation and verification summary](ЩО_ЗРОБЛЕНО.md)
- [Historical alpha release notes](ALPHA_RELEASE_NOTES.md)

## Choose a mode

| Mode | Start | Behavior |
| --- | --- | --- |
| Direct chat | `python main.py` or `run.bat` | Conversation; no file or diagnostic tools |
| Coder | `python main.py --coder` or `run-coder.bat` | Project files, edits, tests and coding workflows; action approvals stay enabled |
| Plan | `python main.py --coder --plan` | Read-only research and planning; writes, general shell, hooks and MCP calls blocked |
| Diagnostics | `python main.py --agent` or `run.bat --agent` | System inspection and guarded maintenance |
| Diagnostic unsafe | `run-unsafe.bat` | Legacy diagnostic operator mode; expands roots and disables its action gates |

Enter `/coder` or `/coder "E:\My Project"` inside direct chat to open the coder;
`/quit` returns to that chat. A directly launched coder exits on `/quit`.
The Windows menu offers diagnostics at **18** and coder mode at **19**.

## Kohana 3.1 — built-in coder personality

The coding agent loads `persona/persona_kohana_v3_1.xml` when a new
`CoderSession` starts. This is Kohana's **system-level identity** in
`--coder` and `/coder` mode, not a skill, user message or optional chat command.
The bundled persona includes the `world_class_programmer` standards and
guidance for working with Codex and Claude Code **when those tools are actually
available**. It does not install or connect either external tool automatically.

`core/coder_persona.py` verifies and combines the XML with the existing
Medfarl coder operating rules. Tool restrictions, per-action approvals,
workspace confinement and read-only plan mode remain enforced in code.
The persona is loaded per coder session; restart coder mode after editing XML.
Missing or malformed XML raises an explicit error instead of silently
reverting to a different personality.

Normal chat (`python main.py`) and PC diagnostics (`--agent`) retain their
existing system instructions. Since the full XML is included in every coder
request, choose a model/context window large enough for the persona, tool
schemas, project context and conversation history.

## Install and run

Requirements: Python 3.10+, Git for Git tools, Ollama, and an installed Ollama
model. Coder/diagnostic modes require tool calling; direct chat does not.
Hardware requirements depend on the model and context size.

```powershell
git clone https://github.com/BOHDANMARCEN/-Medfarl-AI-System.git
cd .\-Medfarl-AI-System
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
ollama pull tripolskypetr/qwen3.5-uncensored-aggressive:4b
.\run.bat
```

Launchers use `.venv\Scripts\python.exe` when present, otherwise `python`. They
check `httpx`, `psutil` and `yaml` and install requirements if those imports fail.
Startup can launch `ollama serve` and preload the model. **Models are not pulled
automatically.**

For Linux/macOS, use the Python entry point:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python main.py --coder --workspace /path/to/project
```

Windows is the primary verification environment. Shells, sensors, antivirus adapters
and process behavior depend on the OS; Windows launchers are not cross-platform scripts.

| Dependency | Purpose |
| --- | --- |
| `httpx>=0.27.0` | Ollama requests, completion streams and MCP HTTP |
| `psutil>=5.9.0` | Telemetry and process inspection |
| `PyYAML>=6.0` | Skill and rule frontmatter |
| `pynvml>=11.5.0` | Optional NVIDIA telemetry; included in requirements |

GPU telemetry needs a compatible NVIDIA GPU/driver. Chat and coding do not depend
on GPU telemetry. Antivirus operations need an available supported provider.

## Create and edit projects

```powershell
.\run-coder.bat --workspace "E:\My Project"
```

A missing workspace can be created after confirmation. Inside the coder:

```text
/new python "my calculator"
/new web "my website"
/new empty "my app"
/open "E:\Existing Project"
/project
/diff
```

`/new` previews every file, asks once, creates the project and selects it as the
workspace. Templates contain a Python CLI with unittest tests, a static HTML/CSS/JS
site, or a README and `.gitignore`. Creation does not install packages or run code.
Natural-language tasks can create arbitrary structures:

```text
Create a calculator in calc with source files, a README and tests, then verify it.
Read parser.py, fix the parsing bug and run the relevant tests.
```

The coder lists/searches/reads files, creates directories, makes exact replacements,
and applies batches of **1–32 files**, **512 KiB per file**, **2 MiB per batch**.
Full rewrites require the current SHA-256 from `read_file`; approval-time conflicts
are checked before writing. Each file write is atomic. A multi-file batch can
retain earlier writes on an I/O error and reports completed paths.

## Coding workflows

| Commands | Purpose |
| --- | --- |
| `/help`, `/status`, `/tools`, `/project` | Commands, model/mode, permitted tools and workspace |
| `/skills`, `/skill name arguments` | Discover and run a reusable workflow |
| `/review`, `/debug`, `/test`, `/refactor`, `/docs` | Bundled coding workflows |
| `/commit`, `/implementation-plan` | Explicit commit preparation or read-only planning |
| `/plan [task]`, `/mode edit`, `/tasks` | Research without writes, approved execution, checklist |
| `/init`, `/remember text`, `/memory` | Project instructions and approved notes |
| `/save work`, `/sessions`, `/resume work`, `/compact` | Save, list, restore and summarize conversations |
| `/checkpoint before`, `/rewind before` | Track and restore file-tool changes with conflict checks |
| `/agents`, `/agent reviewer task` | Isolated, sequential, read-only analysis |
| `/mcp`, `/mcp connect name`, `/mcp disconnect name` | Explicit external tool connections |
| `/hooks`, `/permissions`, `/model [name]`, `/doctor` | Configuration and runtime inspection |
| `/access full`, `/access project` | Expand file access after confirmation, or restrict it |
| `/reset`, `/quit` | Clear conversation history, or leave the coder |

Skills load from bundled `skills/`, personal `.claude/skills`/`.medfarl/skills`,
and project `.claude/commands`, `.claude/skills` and `.medfarl/skills`.
`allowed-tools` can only restrict a turn; skills never grant extra rights.

Root `AGENTS.md`, `QWEN.md`, `GEMINI.md`, `CLAUDE.md`, `.claude/CLAUDE.md` and
project memory provide guidance. Nested CLAUDE files and matching rules load after
relevant files are read. Notes live in `.medfarl/memory.md`; sessions/checkpoints
live under `.medfarl/sessions/` and `.medfarl/checkpoints/`. Those state directories
are Git-ignored in this repository and starter templates; add them to existing projects.

Resume restores history, tasks and tracked file baselines, retains the currently
selected model and revokes full access. Rewind covers file-tool edits, not a whole
disk, shell changes or Git state; external changes block it. `/reset` preserves
files, the change list and access mode. `/open` selects another project and clears
its conversation.

[CLAUDE_COMPATIBILITY.md](CLAUDE_COMPATIBILITY.md) documents formats, examples and
boundaries. Compatibility is partial: OAuth, IDE/LSP, cloud services, agent teams
and full Claude plugin semantics are outside the current implementation.

## Approvals and data access

Coder writes show a diff; commands show the shell, cwd and timeout. `y`, `yes` or
`так` approves; Enter/EOF denies. Denial stops the task and preserves completed
actions. MCP connections/calls, hook commands, session saves/restores and checkpoint
restores have explicit approvals. Plan mode blocks state saves as well as code writes.

File tools are workspace-confined by default. **Approved shell commands and MCP
server processes are not sandboxed**: they use the OS user's file/network rights.
The application does not automatically grant administrator privileges.

Coder `--unsafe-full-access` still asks to expand file access and retains approvals.
In **legacy diagnostic unsafe mode**, the flag or `MEDFARL_UNSAFE_FULL_ACCESS=1`
expands roots and disables diagnostic action gates. Diagnostic confirmation settings
do not disable coder approvals.

Default localhost Ollama requests stay local. A remote backend, approved network
command or remote MCP server can transmit data. Saved sessions may contain
conversation/file content and are not encrypted. The diagnostic JSONL audit covers
its own action workflow, not every coder operation.

## Configuration and CLI

Chat/diagnostic model priority: `--model` > `MEDFARL_MODEL` > built-in default.
Coder priority: `--model` > `MEDFARL_CODER_MODEL` > configured chat model.

```powershell
$env:MEDFARL_CODER_MODEL = "your-installed-tool-model"
.\run-coder.bat --timeout 240
python main.py --list-models
python main.py --no-warmup --healthcheck
python main.py --coder --no-warmup --healthcheck
python main.py --coder --plan -p "Explain the project"
python main.py --coder --resume work
python main.py --no-stream
```

`--prompt`/`-p`, `--plan` and `--resume` imply coder mode and reject `--agent`.
One-shot execution prints text and retains approvals; noninteractive EOF denies
actions. It does not enable unattended execution.

| Setting | Default | Scope |
| --- | --- | --- |
| `MEDFARL_LLM_URL` | `http://localhost:11434` | Backend root, without a trailing `/v1` |
| `MEDFARL_MODEL` | `tripolskypetr/qwen3.5-uncensored-aggressive:4b` | Chat/diagnostics; coder fallback |
| `MEDFARL_CODER_MODEL` | Configured chat model | Coder override |
| `MEDFARL_TIMEOUT` | `120` seconds | Model request timeout |
| `MEDFARL_KEEP_ALIVE` | `30m` | Ollama preload request |
| `MEDFARL_AUTOSTART_OLLAMA` | `1` | Allow startup to launch Ollama |
| `MEDFARL_WARMUP` | `1` | Preload unless `--no-warmup` |
| `MEDFARL_CHAT_SYSTEM_PROMPT` | Built-in prompt | Direct chat only |
| `MEDFARL_CHAT_REASONING_EFFORT` | `none` | Direct chat only |

`--skip-healthcheck` skips preflight, not preload; `--no-warmup` controls preload.
Non-Ollama backends need compatible endpoints and may require both flags. `/model`,
listing and preflight use Ollama APIs. See [TECHNICAL.md](TECHNICAL.md) for all
diagnostic root/confirmation/audit settings and `python main.py --help` for flags.

| Windows launcher | Behavior |
| --- | --- |
| `run.bat` | Dependency check and streaming chat |
| `run-coder.bat` | Coder, forwarding additional flags |
| `run-streaming.bat` | Explicit streaming; respects model overrides |
| `run-quick.bat` | Skips preflight; retains preload |
| `run-unsafe.bat` | Legacy diagnostic unsafe mode |
| `Medfarl_Menu.bat` | Model/mode menu |

## Diagnostics and maintenance

Start `run.bat --agent` for snapshots, CPU/RAM/disks/processes/network, package
inspection, supported logs and available NVIDIA sensors. Guarded maintenance
includes approved file/program/package actions, junk quarantine and supported
antivirus adapters. Availability depends on OS, hardware and installed tools.

Diagnostic approval commands: `pending`, `approve <id>`, `cancel <id>`,
`history actions`, `last action`. One mutation may be pending at a time.
Diagnostic roots default to the process cwd and are separate from the coder
workspace. Multi-line `/shell powershell` and `/shell cmd` belong to diagnostic unsafe mode.

## Verification and development

```powershell
python -m unittest discover -s tests -v
```

Verification snapshot: **80 tests, 79 passed, 1 skipped**, Windows, 2026-10-24.
The symlink test was skipped because the account could not create symbolic links.
Coverage includes chat/routing, coder files/projects, skills, plans, sessions/rewind,
hooks, local MCP stdio and HTTP JSON/SSE behavior.

Manual checks covered Qwen 9B tool use, generated Python tests, session restoration,
terminal commands and the bundled MCP echo server. HTTP tests use a mocked transport;
external authenticated MCP providers were not verified. Architecture and contribution
guidance are in [TECHNICAL.md](TECHNICAL.md).

## Project and license

Repository: [BOHDANMARCEN/-Medfarl-AI-System](https://github.com/BOHDANMARCEN/-Medfarl-AI-System).
See [LICENSE](LICENSE) for the Apache License 2.0 terms.
