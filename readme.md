# Medfarl AI System

**PC Doctor powered by a local LLM**

> Deep local diagnostics. Zero cloud. All analysis stays on your machine.

Medfarl is a terminal-based diagnostic assistant that runs a local LLM as an agent with
controlled tool access to your system. It inspects hardware, processes, packages,
logs, and services — then explains what it finds in plain language. It can also run
maintenance actions through guarded tools with explicit approval.

---

## Table of contents

- [Why Medfarl](#why-medfarl)
- [What Works Now](#what-works-now)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [First user flow](#first-user-flow)
- [Maintenance mode](#maintenance-mode)
- [Demo](#demo)
- [Stability checks](#stability-checks)
- [Configuration](#configuration)
- [Project structure](#project-structure)
- [Architecture deep dive](#architecture-deep-dive)
- [Tool reference](#tool-reference)
- [Safety model](#safety-model)
- [Supported platforms](#supported-platforms)
- [Extending Medfarl](#extending-medfarl)
- [Known limitations](#known-limitations)
- [Roadmap](#roadmap)

---

## Why Medfarl

Most "AI system assistants" either phone home, hallucinate tool results, or give the LLM
unrestricted shell access. Medfarl is built around three different priorities:

**Local-first.** Everything runs on your machine. The LLM runs via Ollama (or any
OpenAI-compatible local backend). No data leaves the host.

**Controlled tool access.** The agent can only call explicitly registered tools. Shell
execution is limited to a hardcoded allowlist of safe diagnostic commands. No arbitrary
`subprocess.run(user_input)`. Mutating actions are available only through dedicated
maintenance tools with approval prompts.

**Real data before conclusions.** The system prompt instructs the model to always call
`get_system_snapshot` before diagnosing any unknown issue. It is not allowed to invent
tool results or guess before reading actual system state.

---

## What Works Now

Current alpha is strongest in three areas:

- `diagnose mode` - deterministic local summaries for overall system state, processes, disks, network, and logs.
- `repair mode` - approval-gated maintenance plans for packages, file edits, program launch, antivirus tasks, and junk handling.
- `auditability` - action ids, JSONL audit trail, single pending-action policy, and smoke scripts for regression checks.

This makes the current build useful as a local PC Doctor alpha rather than just a chat wrapper around tools.

---

## How it works

At startup Medfarl collects a system snapshot (CPU, RAM, disks, temperatures, running
processes, GPU if available, package manager state) and injects it into the conversation
as a synthetic bootstrap tool result. The LLM receives this context before the first user
message — so it can answer basic questions immediately without making extra tool calls.

When you ask a question, the agent enters a tool-calling loop:

```
user message
    → LLM decides: answer directly OR call a tool
        → tool executes locally, result appended to context
            → LLM continues reasoning
                → repeat until final text answer
```

The loop runs for at most `max_tool_steps` iterations (default 8) as a safety cap.
Conversation history is preserved across turns within a session.

For mutating tools (run program, install/uninstall pip packages, edit files), Medfarl
creates a pending action plan and waits for `approve` or `cancel` instead of executing
immediately.

Every pending action gets an `Action ID`. You can confirm or cancel a specific action
using that ID, and inspect current pending state with `pending`.

---

## Quick start

### 1. Install Ollama and pull a model

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2
```

Any model with tool-calling support works. Tested models: `llama3.2`, `qwen2.5`,
`mistral-nemo`. Larger models give better diagnostic reasoning.

### 2. Clone and set up

```bash
git clone <your-repo-url>
cd medfarl-ai-system

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Run

```bash
python main.py --healthcheck
python main.py --list-models
python main.py --model qwen3.5:9b
python main.py --timeout 240 --model qwen3.5:9b
python main.py --skip-healthcheck
python main.py --benchmark-models llama3.2:3b qwen3.5:4b qwen3.5:9b
python scripts/smoke_intents.py
python scripts/smoke_maintenance.py
python main.py
```

Windows quick launchers:

```bat
run-llama.bat
run-qwen4b.bat --timeout 240
```

`--healthcheck` verifies that Ollama is reachable and that `MEDFARL_MODEL` is installed
and supports tool calling before you start the interactive session. `--list-models`
shows local Ollama models, `--model` overrides the default model for a single run, and
`--benchmark-models` runs a short side-by-side comparison on fixed prompts. `--timeout`
overrides the HTTP timeout for slower models, and `--skip-healthcheck` bypasses the
startup preflight when you explicitly want to try a model anyway. The normal startup
path runs the same preflight automatically and exits early with a helpful error if
Ollama is not ready.

You will see the banner and a `medfarl>` prompt. Type any diagnostic question or
`exit` / `quit` / `q` to quit.

When Medfarl plans a mutating action, it pauses and asks for explicit confirmation.
Use:

```text
approve <action_id>
cancel <action_id>
pending
```

---

## First user flow

The default UX is optimized for a short, guided first interaction.

- `привіт` returns a clear next-step menu (overall health, processes, disks, network, logs).
- `help`, `допомога`, or `що ти ще можеш` now returns a short interactive help menu first (`1. діагностика ПК`, `2. обслуговування / дії`, `3. інше запитання`), with the older deterministic capability summary kept as timeout/error fallback.
- After that interactive help menu, replying with `1`, `2`, or `3` routes into the matching next step.
- Very short intents are normalized into deterministic actions before LLM reasoning:
  - `діагностикою ПК` → `Зроби загальну діагностику ПК`
  - `процеси` → `Покажи найважчі процеси`
  - `мережа` → `Перевір стан мережі`
  - `диск` / `диски` → `Перевір диски і вільне місце`
  - `логи` → `Покажи помилки в системних логах`
- Ambiguous short inputs trigger a clarification prompt instead of a low-quality guess.

For `діагностика ПК`, `процеси`, `диски`, `мережа`, and `логи`, the agent runs
deterministic local flows and returns short PC Doctor-style reports without chatty detours.

---

## Maintenance mode

Maintenance mode keeps system-changing actions explicit and reviewable.

- Agent builds a short execution plan first.
- Action is queued with an `Action ID`.
- Nothing mutating runs until you confirm.
- Only one pending action is supported at a time. New mutating requests are rejected until you `approve` or `cancel` the current one.
- Read-only flows like diagnostics, help, history, and quarantine inspection remain available while a mutating action is pending.

Use control commands:

```text
pending
approve <action_id>
cancel <action_id>
history actions
last action
```

### Modes

- **diagnose mode**: read-only diagnostics and summaries (`діагностика`, `процеси`, `мережа`, `логи`).
- **repair mode**: guarded mutating plans that require confirmation.
- **dangerous actions**: high-risk operations (for example uninstall package or deleting junk) remain approval-gated and are visible in audit log.

Deterministic maintenance intents currently supported:

- package install requests (`pip_install_package` plan + confirmation)
- file creation requests (`create_text_file` plan + confirmation)
- program launch requests (`run_program` plan + confirmation)
- junk preview requests (`find_junk_files` direct preview)
- antivirus requests:
  - `перевір антивірусом`
  - `онови бази антивіруса`
  - `проскануй папку ...`
  - `покажи загрози`

When an antivirus provider is available, generic quick-scan requests like `перевір антивірусом`
now queue an `Action ID` and require explicit confirmation before the scan starts.

Junk cleanup stage 2 tools are available and still confirmation-gated:

- `move_junk_to_quarantine(paths)`
- `show_quarantine(limit)`
- `restore_from_quarantine(entry_ids, destination_root=None, overwrite=False)`
- `delete_junk_files(paths, recursive)`

Common Ukrainian aliases now work too:

- `покажи що в карантині`
- `віднови з карантину qk-1234abcd`

If a maintenance request is incomplete (for example `файл створи` or `встанови пакет`),
Medfarl now responds with a guided next-step example instead of falling back to a generic ambiguous-input message.

Quarantine lifecycle:

```text
preview -> move to quarantine -> show quarantine -> restore or delete
```

### Live example

```text
medfarl> встанови пакет rich
... Action ID: a1b2c3d4 ...

medfarl> approve a1b2c3d4
... success ...

medfarl> створи файл notes.txt
... Action ID: e5f6g7h8 ...

medfarl> cancel e5f6g7h8
... cancelled ...

medfarl> знайди сміття
... preview list ...

medfarl> move junk to quarantine C:\Users\User\AppData\Local\Temp\old.tmp
... Action ID: ...

medfarl> approve <action_id>
... moved to quarantine ...

medfarl> show quarantine
... qk-1a2b3c4d ...

medfarl> restore from quarantine qk-1a2b3c4d
... Action ID: ...
```

---

## Demo

```text
medfarl> привіт
Привіт! Що саме перевірити: загальний стан системи, процеси, диски, мережу чи логи?

medfarl> діагностикою ПК
Добре, запускаю базову діагностику системи.
- CPU: ...
- RAM: ...
- Disk: ...
- Processes: ...
- Services & packages: ...
- Network: ...

medfarl> процеси
Добре, показую найважчі процеси зараз:
- ...
```

Typical internal flow for that second command:

```text
normalize intent -> deterministic diagnostics -> concise report
```

This keeps the first experience practical: less small talk, more actual diagnostics.

---

## Stability checks

Recommended alpha regression commands:

```bash
python main.py --healthcheck
python scripts/smoke_intents.py
python scripts/smoke_maintenance.py
```

- `scripts/smoke_intents.py` checks guided diagnose and repair intents.
- `scripts/smoke_maintenance.py` checks pending approvals, wrong-id refusals, junk lifecycle, audit/history, and antivirus routing.

---

## Configuration

All settings live in `config.py` as a `Settings` dataclass. Every field can be
overridden with an environment variable.

| Variable | Default | Description |
|---|---|---|
| `MEDFARL_LLM_URL` | `http://localhost:11434` | Ollama or any OpenAI-compatible endpoint |
| `MEDFARL_MODEL` | `qwen3.5:9b` | Model name as Ollama knows it |
| `MEDFARL_TIMEOUT` | `120` | HTTP timeout in seconds for LLM calls |
| `MEDFARL_MAX_TOOL_STEPS` | `8` | Maximum tool call iterations per user turn |
| `MEDFARL_ALLOWED_READ_ROOTS` | current workspace | `os.pathsep`-separated roots for file read access |
| `MEDFARL_ALLOWED_EDIT_ROOTS` | current workspace | Roots where text files/directories can be created or edited |
| `MEDFARL_ALLOWED_EXEC_ROOTS` | current workspace | Roots where `run_program` is allowed to execute files |
| `MEDFARL_CONFIRM_EXEC` | `1` | Require approval before `run_program` |
| `MEDFARL_CONFIRM_PACKAGE_CHANGES` | `1` | Require approval before pip install/uninstall |
| `MEDFARL_CONFIRM_FILE_EDITS` | `1` | Require approval before create/write/edit file actions |
| `MEDFARL_CONFIRM_DELETE` | `1` | Reserved for delete actions (future cleanup stage) |
| `MEDFARL_ENABLE_ACTION_LOG` | `1` | Enable JSONL audit log for pending/approved/cancelled/executed actions |
| `MEDFARL_ACTION_LOG_PATH` | `./medfarl_actions.log` | Path to the action audit log file |
| `MEDFARL_JUNK_QUARANTINE_DIR` | `./junk_quarantine` | Default destination for moved junk files |

### Using a different backend

Point `MEDFARL_LLM_URL` at any OpenAI-compatible `/v1/chat/completions` endpoint:

```bash
# LM Studio (default port)
MEDFARL_LLM_URL=http://localhost:1234 python main.py

# vLLM
MEDFARL_LLM_URL=http://localhost:8000 MEDFARL_MODEL=mistral python main.py

# Jan
MEDFARL_LLM_URL=http://localhost:1337 python main.py
```

---

## Project structure

```
medfarl-ai-system/
├── main.py                   entry point and REPL loop
├── config.py                 Settings dataclass + env var overrides
├── requirements.txt
├── core/
│   ├── agent.py              MedfarlAgent — orchestrator, history, bootstrap
│   ├── approval.py           pending action memory and approval state
│   ├── action_guard.py       allowed-root and path guardrails for mutating actions
│   ├── program_runner.py     guarded executable launcher
│   ├── package_manager.py    controlled pip operations via current interpreter
│   ├── file_ops.py           guarded file create/write/edit helpers + junk preview
│   ├── antivirus.py          provider adapters for Defender/ClamAV operations
│   ├── audit.py              JSONL audit logger for mutating action lifecycle
│   ├── llm_client.py         LLMClient + Tool dataclass
│   ├── system_scanner.py     SystemScanner — hardware sensors via psutil + pynvml
│   └── lib_inspector.py      LibInspector — pip, packages, services
├── tools/
│   ├── tools.py              Base diagnostics tools and helper functions
│   ├── antivirus_tools.py    Antivirus tool registry and schemas
│   └── maintenance_tools.py  Mutating maintenance tools (approval-gated)
└── ui/
    └── cli.py                Terminal banner and prompt helpers
```

---

## Architecture deep dive

### Agent (`core/agent.py`)

`MedfarlAgent` owns the conversation history and the tool-calling loop.

**Bootstrap.** On `__init__`, the agent calls `_bootstrap()` which collects a real
system snapshot and inserts it into `_history` as a synthetic
`assistant → tool_calls → tool_result` exchange. This follows the exact message format
the OpenAI spec requires for tool results — not a user message, not a raw JSON dump in
the system prompt. Models like llama3 and qwen2 are sensitive to this: putting raw JSON
in a user turn causes confused or ignored context.

```
_history after bootstrap:
  [0]  role: assistant  (synthetic — called get_system_snapshot)
  [1]  role: tool       (real snapshot data)
```

**Agent loop.** `_run_agent_loop()` builds the full message list
(`system_prompt + _history`), sends it to the LLM, and handles tool calls one at a time.
Each tool call appends two messages to the local loop buffer: the assistant turn with
`tool_calls` and the tool result. At the end of the loop, the final assistant text reply
is appended to `_history` and returned to the caller.

**Reset.** `agent.reset()` trims `_history` back to the bootstrap entries `[:1]`,
clearing the conversation while keeping the initial system context.

### LLM client (`core/llm_client.py`)

A thin synchronous HTTP client (via `httpx`) that wraps `/v1/chat/completions`.

It handles one tool call per response round-trip and returns a structured dict:

```python
{
    "assistant_message": {"role": "assistant", "content": "..."},
    "tool_call": {"name": "get_system_snapshot", "arguments": {}},
    "tool_call_id": "call_abc123",   # passed through from the API response
}
```

The `tool_call_id` is critical: it must be echoed back in the tool result message or
most models raise a validation error on the next turn.

### System scanner (`core/system_scanner.py`)

Uses `psutil` for CPU, memory, disks, network, processes and temperatures.
Uses `pynvml` for NVIDIA GPU metrics (optional — gracefully absent if not installed).

Reads `/proc/cpuinfo` on Linux and the Windows registry on Windows to get the CPU model
string, since `platform.processor()` is often empty or wrong.

`SystemScanner.to_dict()` returns a plain nested dict suitable for JSON serialisation
into the LLM context.

### Library inspector (`core/lib_inspector.py`)

`LibInspector.pip_packages()` uses `importlib.metadata` directly — no subprocess, no
pip invocation. Fast and works without pip in PATH.

`pip_outdated()` calls `pip list --outdated --format=json` via subprocess. This is slow
(15–30 seconds on large environments) so it is a separate tool the agent calls only when
explicitly needed.

System packages are detected by probing `dpkg-query`, `rpm -qa`, or `pacman -Q`
depending on what is in PATH.

Services come from `systemctl list-units --type=service --all`.

### Tools (`tools/tools.py`)

Each tool is a `Tool` dataclass with a name, description (the LLM reads this when
deciding what to call), a JSON Schema for parameters, and a Python callable.

The tool layer now includes narrower summaries for disks, processes, network state, and
recent system errors so the agent does not have to infer everything from one large
bootstrap snapshot.

Maintenance tools are split into a dedicated module and merged into the registry. The
agent marks mutating calls as pending plans and asks for explicit confirmation before
execution.

Antivirus tools are implemented through provider adapters (Windows Defender and ClamAV)
instead of free-form shell calls. This keeps scan/update operations structured and
platform-aware.

**Safe command allowlist.** `SAFE_COMMANDS` maps string keys to hardcoded `argv` lists.
The model passes a key (e.g. `df_h`), not a raw command string. This prevents prompt
injection via command arguments entirely.

**Path allowlist.** `read_file` and `list_directory` resolve the requested path and
check it against `settings.allowed_read_roots` before opening anything. Paths outside
the allowed roots raise `PermissionError` which becomes a JSON error returned to the LLM.

**Host validation.** `ping_host` rejects any host string containing shell metacharacters
before passing it to `subprocess.run`.

---

## Tool reference

| Tool | Arguments | What it does |
|---|---|---|
| `get_system_snapshot` | — | CPU, RAM, disk, GPU, temps, network, top 5 processes |
| `get_disk_summary` | `top_n` | Disk usage summary with high-usage volumes |
| `get_top_processes` | `count`, `include_idle` | Busiest active processes by CPU and memory |
| `get_network_summary` | — | Active interfaces, IP addresses, and traffic totals |
| `get_recent_errors` | `limit` | Recent critical/error events from Windows Event Log or journalctl |
| `detect_antivirus` | — | Detect available antivirus providers and status |
| `update_antivirus_definitions` | `provider` | Update antivirus signatures for Defender/ClamAV |
| `run_antivirus_quick_scan` | `provider` | Start provider quick scan using adapter defaults |
| `run_antivirus_custom_scan` | `path`, `provider` | Scan a specific file/folder path via antivirus adapter |
| `list_antivirus_threats` | `limit`, `provider` | List recent detected threats from provider records/logs |
| `get_installed_pip_packages` | — | All pip packages in active environment |
| `get_pip_outdated` | — | Outdated pip packages (slow, ~15s) |
| `get_system_packages_summary` | — | Package manager name + failed systemd services |
| `get_failed_services` | — | List of failed systemd service names |
| `run_program` | `path`, `args`, `cwd`, `timeout` | Run approved `.exe` from allowed execution roots (approval-gated) |
| `pip_install_package` | `name`, `version`, `upgrade` | Install package via `sys.executable -m pip` (approval-gated) |
| `pip_uninstall_package` | `name` | Uninstall package via `sys.executable -m pip` (approval-gated) |
| `pip_check` | — | Report package dependency conflicts |
| `pip_freeze` | — | Output installed package versions |
| `find_junk_files` | `scope`, `older_than_days`, `limit` | Preview temp/cache-like files and estimate cleanup impact |
| `move_junk_to_quarantine` | `paths`, `quarantine_dir` | Move selected junk paths into quarantine (approval-gated) |
| `show_quarantine` | `limit` | List quarantine entries with ids, source path, size, and status |
| `restore_from_quarantine` | `entry_ids`, `destination_root`, `overwrite` | Restore quarantined entries by id (approval-gated) |
| `delete_junk_files` | `paths`, `recursive` | Delete selected junk paths from disk (approval-gated, high risk) |
| `create_directory` | `path` | Create directory in allowed edit roots (approval-gated) |
| `create_text_file` | `path`, `content` | Create text file in allowed edit roots (approval-gated) |
| `write_text_file` | `path`, `content`, `overwrite` | Write file with backup-aware behavior (approval-gated) |
| `append_text_file` | `path`, `content` | Append text with backup-aware behavior (approval-gated) |
| `edit_text_file` | `path`, `find_text`, `replace_text` | Single replace with backup creation (approval-gated) |
| `read_file` | `path` | Read a text file within allowed roots |
| `list_directory` | `path` | List contents of a directory within allowed roots |
| `run_safe_command` | `command` (key) | Run a pre-approved command by its allowlist key |
| `ping_host` | `host` | Ping a hostname or IP address |

### Safe command keys

| Key | Actual command |
|---|---|
| `df_h` | `df -h` |
| `free_h` | `free -h` |
| `uptime` | `uptime` |
| `ip_addr` | `ip addr` |
| `ip_route` | `ip route` |
| `journal_errors` | `journalctl -p 3 -xb --no-pager` |
| `lsblk` | `lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT` |

---

## Safety model

Medfarl is intentionally a controlled diagnostics + maintenance assistant, not an
unrestricted automation platform.

- No arbitrary shell execution. The `run_safe_command` tool only accepts keys from a
  hardcoded dictionary of safe read-only commands, not raw strings.
- Mutating actions are approval-gated. Tools such as `run_program`, `pip_install_package`,
  `pip_uninstall_package`, and file edit tools are never executed immediately when the
  model requests them; the agent creates a pending action with a human-readable execution
  plan and asks for `approve <action_id>`.
- Path access is bounded. `read_file` and `list_directory` are limited to roots defined
  in `MEDFARL_ALLOWED_READ_ROOTS`. By default this is the current workspace so the app
  works out of the box on Windows, macOS, and Linux.
- Execution and edit paths are also bounded via `MEDFARL_ALLOWED_EXEC_ROOTS` and
  `MEDFARL_ALLOWED_EDIT_ROOTS`.
- Tool calls are explicit. Only registered tools can be called. The LLM cannot invent
  new capabilities.
- Tool results are capped. `read_file` truncates at 12,000 characters. Shell output is
  truncated at 4,000 characters. This prevents a large log file from silently blowing
  out the context window.
- Mutating lifecycle events (`pending_created`, `approved`, `cancelled`, `executed`) are
  written to `medfarl_actions.log` as JSONL by default.

Future repair capabilities (restarting services, modifying configs, installing packages)
are planned but will require an explicit confirmation step before execution.

---

## Supported platforms

**Primary target: Linux**

Full functionality including temperatures, systemd services, and package managers.
ClamAV adapter works when `clamscan` (and optionally `freshclam`) is installed.

**Partial: macOS**

CPU, RAM, disk, network, and pip tools work. Temperature sensors and systemd are
unavailable. System package detection requires Homebrew and is not yet implemented.

**Partial: Windows**

Basic CPU, RAM, disk, network, pip tools, `ping_host`, and `get_recent_errors` work.
Recent error reads use Windows Event Log through PowerShell. Linux-only safe commands and
systemd tools return errors or empty results gracefully. Antivirus adapter supports
Windows Defender out of the box and ClamAV when binaries are installed.

NVIDIA GPU support requires `pynvml` and a working NVIDIA driver on any platform.
If `pynvml` is not installed or no NVIDIA GPU is present, the GPU section of the
snapshot will be an empty list — no error.

---

## Extending Medfarl

### Adding a new tool

Add an entry to the list in `tools/tools.py`:

```python
Tool(
    name="check_open_ports",
    description="List open TCP ports on the local machine.",
    parameters={
        "type": "object",
        "properties": {},
        "required": [],
    },
    fn=lambda: _check_open_ports(),
)
```

Then implement the function in the same file:

```python
def _check_open_ports() -> dict:
    connections = psutil.net_connections(kind="tcp")
    listening = [
        {"port": c.laddr.port, "pid": c.pid}
        for c in connections
        if c.status == "LISTEN"
    ]
    return {"listening_ports": sorted(listening, key=lambda x: x["port"])}
```

The tool is registered automatically — no other changes needed.

### Adding a new safe command

Add a key and argv to `SAFE_COMMANDS` in `tools/tools.py`:

```python
SAFE_COMMANDS: Dict[str, List[str]] = {
    ...
    "dmesg_errors": ["dmesg", "--level=err,crit", "--notime"],
}
```

### Changing the system prompt

Edit `SYSTEM_PROMPT` in `core/agent.py`. The prompt instructs the model on its role,
what tools to prefer, and what rules to follow. Keep it concise — overly long system
prompts reduce instruction-following quality on smaller models.

---

## Known limitations

- **Single tool call per LLM response.** The client currently processes only the first
  tool call in a response. Some models (GPT-4, Claude) batch multiple tool calls in one
  turn. This is a planned fix.

- **No streaming.** The LLM response is collected in full before displaying. Long
  reasoning steps can feel slow with no output.

- **No session persistence.** Conversation history lives in memory and is lost when the
  process exits. No session log is written to disk.

- **pip_outdated is slow.** On environments with many packages this can take 20–30
  seconds. The agent should warn the user before calling it. Currently it does not.

- **Temperatures on some Linux kernels.** `psutil.sensors_temperatures()` requires
  kernel modules to expose sensors. On some minimal installs or VMs this returns nothing.

---

## Roadmap

- [ ] Streaming output — print the response token by token
- [ ] Session log — save conversations to `~/.medfarl/sessions/`
- [ ] Web UI — FastAPI backend, React frontend, real-time sensor charts
- [ ] Repair mode — tools that modify the system, with explicit confirmation prompts
- [ ] Scheduled health checks — run a snapshot on a cron, alert on anomalies
- [ ] Windows WMI adapter — temperatures, services, and packages on Windows
- [ ] Multi-tool-call support — handle batched tool calls in one LLM response
- [ ] Plugin system — drop a Python file into `plugins/` to register new tools
- [ ] Export — PDF or JSON diagnostics report from a session
