# Medfarl AI System

**PC Doctor powered by a local LLM**

> Deep local diagnostics. Zero cloud. All analysis stays on your machine.

Current prerelease: `v0.2.0-alpha` — see [CHANGELOG.md](CHANGELOG.md) for release notes.

Medfarl is a chat-first terminal diagnostic assistant that runs a local LLM as an
agent with controlled tool access to your system. Speak naturally — it decides whether
to answer directly, ask one clarifying question, use tools, or switch into guided/manual
assistance when an action is blocked. Inspects hardware, processes, packages, logs, and
services — then explains findings in plain language. Can also run maintenance actions
through guarded tools with explicit approval.

**Default mode:** Interactive streaming output is now enabled by default,
with `qwen3.5:9b` as the default model.

---

## Table of contents

- [Why Medfarl](#why-medfarl)
- [What Works Now](#what-works-now)
- [System Requirements](#system-requirements)
- [Dependencies](#dependencies)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Streaming Mode](#streaming-mode)
- [Chat-first Behavior](#chat-first-behavior)
- [How it Works](#how-it-works)
- [Configuration](#configuration)
- [Available Models](#available-models)
- [Launch Scripts](#launch-scripts)
- [CLI Arguments](#cli-arguments)
- [Slash Commands](#slash-commands)
- [Maintenance Mode](#maintenance-mode)
- [Tool Reference](#tool-reference)
- [Project Structure](#project-structure)
- [Architecture](#architecture)
- [Safety Model](#safety-model)
- [Stability Checks](#stability-checks)
- [Supported Platforms](#supported-platforms)
- [Known Limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Extending Medfarl](#extending-medfarl)

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

Current alpha is strongest in four areas:

- **chat-first routing** — every turn is handled as a conversational request first, not as a strict command.
- **tool-aware diagnostics** — the agent decides when to answer directly and when to use the existing tool loop.
- **guided/manual mode** — blocked actions become practical manual guidance instead of cold refusal.
- **interactive streaming** — responses appear token-by-token in real-time (like Gemini CLI).
- **auditability** — action IDs, JSONL audit trail, single pending-action policy, smoke scripts, and targeted unit tests.

This keeps Medfarl useful as a local PC Doctor alpha while making the UX feel like a
normal assistant instead of a command parser.

---

## System Requirements

### Hardware

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 8 GB | 16 GB |
| Disk | 10 GB free | 20 GB free (for models) |
| GPU | None (CPU-only) | NVIDIA GPU (for hardware acceleration via Ollama) |

### Software

| Component | Version | Notes |
|-----------|---------|-------|
| Python | 3.10+ | Required |
| Ollama | Latest | https://ollama.ai |
| Windows | 10/11 | Primary platform |
| Linux | Ubuntu 20.04+ | Supported |
| macOS | 12+ | Supported |

### Model Requirements

You need at least **one Ollama model with tool-calling support**:

| Model | Size | RAM needed | Speed | Quality |
|-------|------|------------|-------|---------|
| `qwen3.5:4b` | 3.4 GB | 6 GB | ⚡⚡⚡ Fast | ⭐⭐⭐ Good |
| `qwen3.5:9b` | 6.6 GB | 10 GB | ⚡⚡ Medium | ⭐⭐⭐⭐ Better |
| `llama3.2:3b` | 2.0 GB | 4 GB | ⚡⚡⚡⚡ Very Fast | ⭐⭐ Basic |
| `gemma-abliterated` | 7.3 GB | 10 GB | ⚡⚡ Medium | ⭐⭐⭐⭐ Good |
| `gpt-oss-20b` | 11 GB | 16 GB | ⚡ Slow | ⭐⭐⭐⭐⭐ Best |
| `huihui_ai/qwen2.5-1m-abliterated:14b` | 9.0 GB | 14 GB | ⚡⚡ Medium | ⭐⭐⭐⭐ Great |
| `huihui_ai/qwen3-abliterated:14b` | 9.0 GB | 14 GB | ⚡⚡ Medium | ⭐⭐⭐⭐ Great |

**Default model:** `qwen3.5:9b` (higher-quality default for chat-first interactive use)

---

## Dependencies

### Python Packages

All dependencies are listed in `requirements.txt`:

```
psutil>=5.9.0       # System monitoring (CPU, RAM, disk, network, processes)
httpx>=0.27.0       # HTTP client for Ollama API calls
pynvml>=11.5.0      # Optional — NVIDIA GPU telemetry support
```

### What Each Dependency Does

| Package | Required | Purpose |
|---------|----------|---------|
| `psutil` | ✅ Yes | Cross-platform system monitoring: CPU usage, memory, disk I/O, network, temperatures |
| `httpx` | ✅ Yes | Synchronous HTTP client for Ollama `/v1/chat/completions` and `/api/tags` endpoints |
| `pynvml` | ⚠️ Optional | NVIDIA Management Library — GPU utilization, memory, temperature via `nvidia-ml-py` |

### Install Dependencies

```bash
# Automatic (recommended)
pip install -r requirements.txt

# Without optional GPU support
pip install psutil>=5.9.0 httpx>=0.27.0
```

### External Dependencies

| Component | Required | Purpose |
|-----------|----------|---------|
| **Ollama** | ✅ Yes | Local LLM runtime server |
| **Model** | ✅ Yes | At least one tool-calling capable model |
| **Windows Defender** | ⚠️ Optional | Antivirus scanning (auto-detected) |
| **ClamAV** | ⚠️ Optional | Third-party antivirus scanning |
| **pip** | ⚠️ Optional | Package management via maintenance tools |

---

## Installation

### Step 1: Install Ollama

**Windows:**
```bash
# Download and install from https://ollama.ai
# Or use winget:
winget install Ollama.Ollama
```

**Linux:**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

**macOS:**
```bash
brew install ollama
```

### Step 2: Pull a Model

```bash
# Fast fallback model
ollama pull qwen3.5:4b

# Default recommended model
ollama pull qwen3.5:9b

# Lightweight model for low-RAM systems
ollama pull llama3.2:3b
```

### Step 3: Set Up Medfarl

```bash
# Clone or copy the project
cd medfarl-ai-system

# Create virtual environment (recommended)
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 4: Verify Installation

```bash
# Check Ollama connectivity and model availability
python main.py --healthcheck

# List installed models
python main.py --list-models
```

Expected output:
```
[ok] Ollama reachable at http://localhost:11434
[ok] Model available: qwen3.5:9b
[ok] Tool calling supported: qwen3.5:9b
```

---

## Quick Start

### Using Batch Scripts (Windows)

**Easiest — Interactive Menu:**
```bat
Medfarl_Menu.bat
```

**Normal Launch:**
```bat
run.bat
```

This now starts the default interactive Gemini-CLI-like mode:
- streaming enabled
- model `qwen3.5:9b`

**Fast Launch (skip Ollama check):**
```bat
run-quick.bat
```

**Streaming Mode (like Gemini CLI):**
```bat
run-streaming.bat
```

**Full Access Mode:**
```bat
run-unsafe.bat
```

### Using Command Line

```bash
# Interactive streaming session (default model: qwen3.5:9b)
python main.py

# Streaming is already enabled by default
python main.py --stream

# Disable streaming and print full replies only at the end
python main.py --no-stream

# Specific model
python main.py --model qwen3.5:9b

# Streaming with specific model
python main.py --stream --model qwen3.5:9b

# Increase timeout for slower/larger models
python main.py --timeout 240 --model gpt-oss-20b

# Skip healthcheck (when Ollama is not yet running)
python main.py --skip-healthcheck

# Full access mode (unrestricted filesystem + shell)
python main.py --unsafe-full-access --skip-healthcheck

# Check system health
python main.py --healthcheck

# List available models
python main.py --list-models

# Run benchmark across multiple models
python main.py --benchmark-models qwen3.5:4b qwen3.5:9b llama3.2:3b
```

---

## Streaming Mode

Streaming is now the default interactive behavior. Responses appear token-by-token in
real time, just like Gemini CLI or ChatGPT.

### Before (Normal Mode):
```
medfarl> що жере RAM
[waiting 10-30 seconds...]
[entire response appears at once]
```

### After (Streaming Mode):
```
medfarl> що жере RAM
Зараз найбільше RAM споживають: ← appears immediately!
- browser.exe: 2048 MB ← streams in real-time
- editor.exe: 512 MB
...
```

### Features

✅ **Instant feedback** — see text as it's generated  
✅ **Better UX** — feels like talking to a person  
✅ **No waiting** — especially useful for long responses  
✅ **Tool indicators** — see `🔧 Using tool: ...` during execution  
✅ **Multi-language** — works with Ukrainian, Russian, English  

### Enable Streaming

```bash
# Command line (already default)
python main.py --stream
python main.py --stream --model qwen3.5:9b

# Explicitly disable it if needed
python main.py --no-stream

# Batch file
run-streaming.bat

# Menu (option 16)
Medfarl_Menu.bat
```

### How It Works

1. **HTTP Streaming** → Uses `httpx.stream()` instead of `httpx.post()`
2. **Server-Sent Events** → Reads `data:` lines from Ollama response stream
3. **Incremental Print** → Each token printed immediately with `flush=True`
4. **Tool Call Detection** → Parses JSON chunks for tool calls, shows indicators

---

## Chat-first Behavior

Each user turn passes through an explicit conversational router inside the agent:

```
DIRECT_RESPONSE
CLARIFICATION
TOOL_USE
GUIDED_MANUAL_MODE
```

What that means in practice:

- **Natural language is the default UX.** Inputs like `привіт`, `подивись, чому комп гальмує`, `що жере RAM`, or `ось папка з ClamAV, як це запустити` are valid first-class prompts.
- **Fast-path intent normalization** still exists for short, common diagnostics such as `діагностика ПК`, `процеси`, `мережа`, `диск`, and `логи`, but it is only an optimization.
- **Ambiguous fragments** like `воно не працює` or a bare path no longer dead-end the session; Medfarl either asks one short follow-up question or switches into guided/manual help.
- **Language is preserved** turn by turn for Ukrainian, Russian, and English replies.

### Realistic Examples

```text
medfarl> привіт
Привіт! Що саме перевірити: загальний стан системи, процеси, диски, мережу чи логи?

medfarl> подивись, чому комп гальмує
Добре, перевірю CPU, RAM, диски та найважчі процеси.
... tool-aware diagnostic reply ...

medfarl> C:\clamav-1.5.1.win.x64
I can see a Windows path ... The safest next step is to open that folder manually
and check for clamscan.exe or freshclam.exe.

medfarl> там антивірус його треба запустити
Бачу, ти хочеш запустити програму з цього шляху. Я не можу напряму запускати .exe
поза дозволеними шляхами, але можу підказати, який файл шукати вручну:
clamscan.exe або freshclam.exe.
```

---

## How it Works

At startup Medfarl collects a system snapshot (CPU, RAM, disks, temperatures, running
processes, GPU if available, package manager state) and injects it into the conversation
as a synthetic bootstrap tool result. The LLM receives this context before the first user
message — so it can answer basic questions immediately without making extra tool calls.

### Two-Stage Processing

```
user message
    → conversational planner
        → direct response
        → clarification
        → guided/manual mode
        → tool use
```

If the planner selects `TOOL_USE`, Medfarl enters the tool-calling loop:

```
user message
    → LLM decides which tool to call
        → tool executes locally, result appended to context
            → LLM continues reasoning
                → repeat until final text answer
```

The loop runs for at most `max_tool_steps` iterations (default 8) as a safety cap.
Conversation history is preserved across turns within a session.

For mutating tools (run program, install/uninstall pip packages, edit files), Medfarl
creates a pending action plan and waits for `approve` or `cancel` instead of executing
immediately.

Every pending action gets an **Action ID**. You can confirm or cancel a specific action
using that ID, and inspect current pending state with `pending`.

---

## Configuration

All settings live in `config.py` as a `Settings` dataclass. Every field can be
overridden with an environment variable.

### Environment Variables

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
| `MEDFARL_ENABLE_ACTION_LOG` | `1` | Enable JSONL audit log for mutating action lifecycle |
| `MEDFARL_ACTION_LOG_PATH` | `./medfarl_actions.log` | Path to the action audit log file |
| `MEDFARL_JUNK_QUARANTINE_DIR` | `./junk_quarantine` | Default destination for moved junk files |

### Using a Different Backend

Point `MEDFARL_LLM_URL` at any OpenAI-compatible `/v1/chat/completions` endpoint:

```bash
# LM Studio (default port)
MEDFARL_LLM_URL=http://localhost:1234 python main.py

# vLLM
MEDFARL_LLM_URL=http://localhost:8000 MEDFARL_MODEL=mistral python main.py

# Jan
MEDFARL_LLM_URL=http://localhost:1337 python main.py
```

### Config Properties

```python
# Read-only properties
settings.llm_url         # → http://localhost:11434
settings.llm_base_url    # → same as llm_url
settings.model           # → qwen3.5:9b
settings.llm_model       # → same as model
settings.timeout         # → 120
settings.llm_timeout     # → same as timeout
settings.max_tool_steps  # → 8
settings.max_tool_calls_per_turn  # → same as max_tool_steps

# Lists
settings.allowed_read_roots    # Paths for file reading
settings.allowed_edit_roots    # Paths for file creation/editing
settings.allowed_exec_roots    # Paths for program execution

# Enable unsafe mode programmatically
settings.enable_unsafe_full_access()
```

---

## Available Models

### Installed Models (Current System)

Run `ollama list` to see what's available:

```
NAME                                    ID              SIZE      MODIFIED
qwen3.5:9b                              6488c96fa5fa    6.6 GB    3 weeks ago
qwen3.5:4b                              2a654d98e6fb    3.4 GB    3 weeks ago
gemini-3-flash-preview:cloud            436200142af2    -         3 months ago
kimi-k2-thinking:cloud                  9752ffb77f53    -         3 months ago
gpt-oss:120b-cloud                      569662207105    -         4 months ago
huihui_ai/qwen3-abliterated:14b         fa0eaa5098bc    9.0 GB    4 months ago
deepseek-v3.1:671b-cloud                d3749919e45f    -         4 months ago
qwen3-coder:480b-cloud                  e30e45586389    -         4 months ago
huihui_ai/qwen2.5-1m-abliterated:14b    3bf3d8d5e063    9.0 GB    6 months ago
llama3.2:3b                             a80c4f17acd5    2.0 GB    6 months ago
gpt-oss-20b-quality:latest              f04274984f87    11 GB     6 months ago
gemma-abliterated:latest                71e17c56807f    7.3 GB    7 months ago
```

### Local Models (Recommended)

| Model | Size | RAM | Speed | Quality | Use Case |
|-------|------|-----|-------|---------|----------|
| `qwen3.5:4b` | 3.4 GB | 6 GB | ⚡⚡⚡ | ⭐⭐⭐ | Faster fallback |
| `qwen3.5:9b` | 6.6 GB | 10 GB | ⚡⚡ | ⭐⭐⭐⭐ | **Default** — better reasoning |
| `llama3.2:3b` | 2.0 GB | 4 GB | ⚡⚡⚡⚡ | ⭐⭐ | Low-RAM systems |
| `gemma-abliterated` | 7.3 GB | 10 GB | ⚡⚡ | ⭐⭐⭐⭐ | Uncensored |
| `gpt-oss-20b` | 11 GB | 16 GB | ⚡ | ⭐⭐⭐⭐⭐ | Maximum quality |
| `huihui_ai/qwen2.5-1m-abliterated:14b` | 9.0 GB | 14 GB | ⚡⚡ | ⭐⭐⭐⭐ | 1M context window |
| `huihui_ai/qwen3-abliterated:14b` | 9.0 GB | 14 GB | ⚡⚡ | ⭐⭐⭐⭐ | Uncensored |

### Cloud Models

Cloud models require special setup and are not supported out of the box:

- `gemini-3-flash-preview:cloud`
- `kimi-k2-thinking:cloud`
- `gpt-oss:120b-cloud`
- `deepseek-v3.1:671b-cloud`
- `qwen3-coder:480b-cloud`

---

## Launch Scripts

Windows batch files for quick launching:

| Script | Description |
|--------|-------------|
| `Medfarl_Menu.bat` | **Interactive menu** with all models and modes |
| `run.bat` | Default interactive streaming launch with `qwen3.5:9b` |
| `run-quick.bat` | Fast default launch without Ollama healthcheck |
| `run-unsafe.bat` | Full filesystem + shell access mode |
| `run-streaming.bat` | Explicit streaming launcher pinned to `qwen3.5:9b` |

### Menu Options

```
========================================
    Medfarl AI System - Меню запуску
========================================

ДОСТУПНІ МОДЕЛІ:
1. qwen3.5:4b         (3.4 GB - швидка)
2. qwen3.5:9b         (6.6 GB - якісна)
3. llama3.2:3b        (2.0 GB - легка)
4. gemma-abliterated  (7.3 GB)
5. gpt-oss-20b        (11 GB - потужна)
6. qwen2.5-1m:14b     (9.0 GB - великий контекст)
7. qwen3:14b          (9.0 GB - без цензури)
8. Cloud моделі       (gemini, kimi, deepseek, qwen-coder)

ЗАПУСК:
10. Запуск за замовчуванням (Streaming, qwen3.5:9b)
11. Швидкий запуск (Streaming, без перевірки)
12. Режим повного доступу (Unsafe)
13. Перевірка здоров'я
14. Список моделей
15. Бенчмарк (порівняння моделей)
16. ІНТЕРАКТИВНИЙ РЕЖИМ (Streaming як Gemini CLI, qwen3.5:9b)
17. Вихід
```

---

## CLI Arguments

```
usage: main.py [-h] [--model MODEL] [--list-models] [--healthcheck]
               [--benchmark-models MODEL [MODEL ...]] [--skip-healthcheck]
               [--timeout TIMEOUT] [--unsafe-full-access] [--stream] [--no-stream]

Medfarl AI System

options:
  --model MODEL               Override default Ollama model for this run
  --list-models               List installed Ollama models and exit
  --healthcheck               Check Ollama connectivity, model availability,
                              and tool support, then exit
  --benchmark-models MODEL    Run short benchmark across specified models
  --skip-healthcheck          Skip startup healthcheck before interactive session
  --timeout TIMEOUT           Override HTTP timeout in seconds for LLM calls
  --unsafe-full-access        Enable unrestricted filesystem, shell, and
                              program access for this session
  --stream                    Enable streaming output explicitly (already default)
  --no-stream                 Disable streaming output and print full replies only
                              after completion
```

### Argument Examples

```bash
# Use different model
python main.py --model llama3.2:3b

# Default-style launch with high-quality model and longer timeout
python main.py --stream --model qwen3.5:9b --timeout 240

# Benchmark three models
python main.py --benchmark-models qwen3.5:4b qwen3.5:9b llama3.2:3b

# Unsafe mode with default streaming
python main.py --stream --unsafe-full-access
```

---

## Slash Commands

Available during interactive session:

| Command | Description |
|---------|-------------|
| `/help` | Show interactive help menu |
| `/reset` | Clear session history and bootstrap context |
| `/status` | Show current model, mode, and settings |
| `/tools` | List registered tools for this session |
| `/shell powershell` | Enter multi-line PowerShell mode (unsafe mode only) |
| `/shell cmd` | Enter multi-line CMD mode (unsafe mode only) |
| `/end` | Run buffered shell block |
| `/cancel` | Discard buffered shell block |
| `/show` | Preview buffered shell script |
| `/quit`, `/q`, `exit` | Exit the session |

### Approval Commands

| Command | Description |
|---------|-------------|
| `pending` | Show current pending action |
| `approve <action_id>` | Confirm and execute pending action |
| `cancel <action_id>` | Cancel pending action |
| `history actions` | Show action audit log |
| `last action` | Show most recent action |

---

## Maintenance Mode

Maintenance mode keeps system-changing actions explicit and reviewable.

- Agent builds a short execution plan first.
- Action is queued with an **Action ID**.
- Nothing mutating runs until you confirm.
- Only one pending action is supported at a time.
- Read-only flows (diagnostics, help, history, quarantine) remain available while action is pending.

### Modes

| Mode | Description |
|------|-------------|
| **diagnose mode** | Read-only diagnostics and summaries |
| **repair mode** | Guarded mutating plans requiring confirmation |
| **unsafe full access mode** | Opt-in via `--unsafe-full-access`; no approval gates |
| **dangerous actions** | In guarded mode, high-risk operations remain approval-gated and auditable |

### Supported Maintenance Intents

- **Package install** → `pip_install_package` plan + confirmation
- **File creation** → `create_text_file` plan + confirmation
- **Program launch** → `run_program` plan + confirmation
- **Junk preview** → `find_junk_files` direct preview
- **Antivirus requests:**
  - `перевір антивірусом`
  - `онови бази антивіруса`
  - `проскануй папку ...`
  - `покажи загрози`
- **Junk cleanup:**
  - `move_junk_to_quarantine(paths)`
  - `show_quarantine(limit)`
  - `restore_from_quarantine(entry_ids, destination_root=None, overwrite=False)`
  - `delete_junk_files(paths, recursive)`

### Quarantine Lifecycle

```
preview → move to quarantine → show quarantine → restore or delete
```

### Live Example

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

medfarl> show quarantine
... qk-1a2b3c4d ...

medfarl> restore from quarantine qk-1a2b3c4d
... Action ID: ...
```

---

## Tool Reference

### Diagnostics Tools

| Tool | Arguments | What it does |
|---|---|---|
| `get_system_snapshot` | — | CPU, RAM, disk, GPU, temps, network, top 5 processes |
| `get_disk_summary` | `top_n` | Disk usage summary with high-usage volumes |
| `get_top_processes` | `count`, `include_idle` | Busiest active processes by CPU and memory |
| `get_network_summary` | — | Active interfaces, IP addresses, and traffic totals |
| `get_recent_errors` | `limit` | Recent critical/error events from Windows Event Log or journalctl |
| `ping_host` | `host` | Ping a hostname or IP address |
| `run_safe_command` | `command` (key) | Run a pre-approved command by its allowlist key |

### Antivirus Tools

| Tool | Arguments | What it does |
|---|---|---|
| `detect_antivirus` | — | Detect available antivirus providers and status |
| `update_antivirus_definitions` | `provider` | Update antivirus signatures for Defender/ClamAV |
| `run_antivirus_quick_scan` | `provider` | Start provider quick scan using adapter defaults |
| `run_antivirus_custom_scan` | `path`, `provider` | Scan a specific file/folder path via antivirus adapter |
| `list_antivirus_threats` | `limit`, `provider` | List recent detected threats from provider records/logs |

### Package Management

| Tool | Arguments | What it does |
|---|---|---|
| `get_installed_pip_packages` | — | All pip packages in active environment |
| `get_pip_outdated` | — | Outdated pip packages (slow, ~15s) |
| `get_system_packages_summary` | — | Package manager name + failed systemd services |
| `get_failed_services` | — | List of failed systemd service names |
| `pip_install_package` | `name`, `version`, `upgrade` | Install package via `sys.executable -m pip` (approval-gated) |
| `pip_uninstall_package` | `name` | Uninstall package via `sys.executable -m pip` (approval-gated) |
| `pip_check` | — | Report package dependency conflicts |
| `pip_freeze` | — | Output installed package versions |

### File Operations

| Tool | Arguments | What it does |
|---|---|---|
| `read_file` | `path` | Read a text file within allowed roots |
| `list_directory` | `path` | List contents of a directory within allowed roots |
| `create_directory` | `path` | Create directory in allowed edit roots (approval-gated) |
| `create_text_file` | `path`, `content` | Create text file in allowed edit roots (approval-gated) |
| `write_text_file` | `path`, `content`, `overwrite` | Write file with backup-aware behavior (approval-gated) |
| `append_text_file` | `path`, `content` | Append text with backup-aware behavior (approval-gated) |
| `edit_text_file` | `path`, `find_text`, `replace_text` | Single replace with backup creation (approval-gated) |

### Junk Cleanup

| Tool | Arguments | What it does |
|---|---|---|
| `find_junk_files` | `scope`, `older_than_days`, `limit` | Preview temp/cache-like files and estimate cleanup impact |
| `move_junk_to_quarantine` | `paths`, `quarantine_dir` | Move selected junk paths into quarantine (approval-gated) |
| `show_quarantine` | `limit` | List quarantine entries with ids, source path, size, and status |
| `restore_from_quarantine` | `entry_ids`, `destination_root`, `overwrite` | Restore quarantined entries by id (approval-gated) |
| `delete_junk_files` | `paths`, `recursive` | Delete selected junk paths from disk (approval-gated, high risk) |

### Program Execution

| Tool | Arguments | What it does |
|---|---|---|
| `run_program` | `path`, `args`, `cwd`, `timeout` | Run approved `.exe` from allowed execution roots (approval-gated) |

### Safe Command Keys

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

## Project Structure

```
medfarl-ai-system/
├── main.py                   Entry point, argument parsing, REPL loop
├── config.py                 Settings dataclass + environment variable overrides
├── requirements.txt          Python dependencies (psutil, httpx, pynvml)
├── readme.md                 This file — comprehensive documentation
├── CHANGELOG.md              Release notes and version history
├── LICENSE                   Project license
│
├── core/                     Core logic modules
│   ├── __init__.py
│   ├── agent.py              MedfarlAgent — orchestrator, history, bootstrap,
│   │                         chat-first routing, approval workflow, streaming
│   ├── approval.py           Pending action memory and approval state
│   ├── action_guard.py       Allowed-root and path guardrails for mutating actions
│   ├── program_runner.py     Guarded executable launcher
│   ├── package_manager.py    Controlled pip operations via current interpreter
│   ├── file_ops.py           Guarded file create/write/edit helpers + junk preview
│   ├── antivirus.py          Provider adapters for Defender/ClamAV operations
│   ├── audit.py              JSONL audit logger for mutating action lifecycle
│   ├── llm_client.py         LLMClient + Tool dataclass, streaming support
│   ├── system_scanner.py     SystemScanner — hardware sensors via psutil + pynvml
│   └── lib_inspector.py      LibInspector — pip, packages, services
│
├── tools/                    Tool definitions
│   ├── tools.py              Base diagnostics tools and helper functions
│   ├── antivirus_tools.py    Antivirus tool registry and schemas
│   └── maintenance_tools.py  Mutating maintenance tools (approval-gated)
│
├── ui/                       User interface
│   └── cli.py                Terminal banner, prompt helpers, color output
│
├── tests/                    Unit tests
│   ├── test_chat_routing.py  Chat-first routing and language preservation
│   └── test_unsafe_mode.py   Unsafe mode tool routing and permissions
│
├── scripts/                  Utility scripts
│   ├── smoke_intents.py      Intent normalization and routing smoke tests
│   └── smoke_maintenance.py  Maintenance workflow smoke tests
│
├── junk_quarantine/          Default quarantine directory for moved junk
│
├── Medfarl_Menu.bat          Interactive launch menu (Windows)
├── run.bat                   Normal launch with checks (Windows)
├── run-quick.bat             Fast launch without Ollama check (Windows)
├── run-unsafe.bat            Full access mode (Windows)
├── run-streaming.bat         Interactive streaming mode (Windows)
├── STREAMING_README.md       Streaming mode documentation
├── ІНСТРУКЦІЯ_ЗАПУСКУ.md     Ukrainian launch instructions
└── ЩО_ЗРОБЛЕНО.md            Changelog and changes summary
```

---

## Architecture

### Agent (`core/agent.py`)

`MedfarlAgent` owns the conversation history and the tool-calling loop.

**Bootstrap.** On `__init__`, the agent calls `_bootstrap()` which collects a real
system snapshot and inserts it into `_history` as a synthetic
`assistant → tool_calls → tool_result` exchange. This follows the exact message format
the OpenAI spec requires for tool results.

```
_history after bootstrap:
  [0]  role: assistant  (synthetic — called get_system_snapshot)
  [1]  role: tool       (real snapshot data)
```

**Agent loop.** `_run_agent_loop()` builds the full message list
(`system_prompt + _history`), sends it to the LLM, and handles tool calls one at a time.
Supports both normal and streaming modes.

**Chat-first routing.** `handle_user_message()` classifies each request into:
- `DIRECT_RESPONSE` — answer naturally
- `CLARIFICATION` — ask one clarifying question
- `TOOL_USE` — use diagnostic/maintenance tools
- `GUIDED_MANUAL_MODE` — provide manual guidance for blocked actions

**Reset.** `agent.reset()` trims `_history` back to bootstrap entries, clearing
conversation while keeping system context.

### LLM Client (`core/llm_client.py`)

A thin synchronous HTTP client (via `httpx`) that wraps `/v1/chat/completions`.

**Normal mode:** Sends complete request, waits for full response.

**Streaming mode:** Uses `httpx.stream()` with Server-Sent Events protocol. Each token
is printed immediately as it arrives (`print(token, end="", flush=True)`).

Returns structured dict:
```python
{
    "assistant_message": {"role": "assistant", "content": "..."},
    "tool_call": {"name": "get_system_snapshot", "arguments": {}},
    "tool_call_id": "call_abc123",   # passed through from API response
}
```

### System Scanner (`core/system_scanner.py`)

Uses `psutil` for CPU, memory, disks, network, processes and temperatures.
Uses `pynvml` for NVIDIA GPU metrics (optional — gracefully absent if not installed).

Reads `/proc/cpuinfo` on Linux and Windows registry on Windows for CPU model string.

`SystemScanner.to_dict()` returns plain nested dict suitable for JSON serialisation.

### Library Inspector (`core/lib_inspector.py`)

`LibInspector.pip_packages()` uses `importlib.metadata` directly — no subprocess, no
pip invocation. Fast and works without pip in PATH.

`pip_outdated()` calls `pip list --outdated --format=json` via subprocess (15–30s).

System packages detected by probing `dpkg-query`, `rpm -qa`, or `pacman -Q`.

Services come from `systemctl list-units --type=service --all`.

### Tools (`tools/tools.py`)

Each tool is a `Tool` dataclass with name, description (LLM reads this), JSON Schema
for parameters, and Python callable.

**Safe command allowlist.** `SAFE_COMMANDS` maps string keys to hardcoded `argv` lists.
Prevents prompt injection via command arguments.

**Path allowlist.** `read_file` and `list_directory` check against `settings.allowed_read_roots`.

**Host validation.** `ping_host` rejects shell metacharacters before subprocess execution.

---

## Safety Model

By default, Medfarl is intentionally a controlled diagnostics + maintenance assistant,
not an unrestricted automation platform.

### Guardrails

- **No arbitrary shell execution** — only allowlisted safe commands
- **No unrestricted filesystem access** — read/edit/exec roots are explicitly configured
- **No program execution without approval** — mutating tools require confirmation
- **No hallucinated tool results** — real data only
- **Single pending action policy** — one mutating action at a time

### Approval Workflow

1. User requests mutating action (install package, run program, edit file)
2. Agent creates pending action with unique `Action ID`
3. Nothing executes until user confirms with `approve <action_id>`
4. User can inspect pending state with `pending` or cancel with `cancel <action_id>`
5. All actions logged to JSONL audit trail

### Audit Logging

When `MEDFARL_ENABLE_ACTION_LOG=1` (default), all mutating actions are logged to
`medfarl_actions.log` in JSONL format:

```json
{"action_id": "a1b2c3d4", "status": "pending", "tool": "pip_install_package", ...}
{"action_id": "a1b2c3d4", "status": "approved", "timestamp": "..."}
{"action_id": "a1b2c3d4", "status": "executed", "result": "..."}
```

### Unsafe Full Access Mode

Enabled via `--unsafe-full-access`:

- All filesystem roots allowed for read/edit/exec
- No approval gates for mutating actions
- Direct CMD/PowerShell shell access
- CLI-style filesystem commands (`copy`, `move`, `rm`, `mkdir`)

⚠️ **Use with caution** — no safety rails in this mode.

---

## Stability Checks

Recommended regression commands:

```bash
# Healthcheck
python main.py --healthcheck

# Unit tests
python -m unittest discover tests -v

# Smoke tests
python scripts/smoke_intents.py
python scripts/smoke_maintenance.py
```

### Test Coverage

| Test File | Coverage |
|-----------|----------|
| `tests/test_chat_routing.py` | Language preservation, clarification, path handling, guided/manual mode, fast-path intent normalization, fake-client tool loop |
| `tests/test_unsafe_mode.py` | Unsafe mode tool routing, shell tool inclusion, filesystem expansion, multiline shell buffer |

### Current Status

```
Ran 15 tests in 3.889s
OK
```

---

## Supported Platforms

| Platform | Version | Status |
|----------|---------|--------|
| Windows | 10/11 (x64) | ✅ Primary |
| Linux | Ubuntu 20.04+, Debian, Arch | ✅ Supported |
| macOS | 12+ (Monterey) | ✅ Supported |

### Platform-Specific Features

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| CPU model detection | Registry | `/proc/cpuinfo` | `sysctl` |
| GPU telemetry | pynvml (NVIDIA) | pynvml (NVIDIA) | pynvml (NVIDIA) |
| System services | Windows Services | systemd | launchctl |
| Package management | pip only | apt/rpm/pacman + pip | brew + pip |
| Antivirus | Defender + ClamAV | ClamAV | ClamAV |
| Event logs | Windows Event Log | journalctl | log show |

---

## Known Limitations

### Alpha Stage

- **No GUI** — terminal-only interface
- **No voice input** — text input only
- **Limited antivirus** — Defender and ClamAV adapters only
- **No remote execution** — local machine only
- **No multi-agent** — single agent per session
- **Streaming compatibility** — requires Ollama with SSE support

### Model Constraints

- **Tool calling** — requires models with tool-calling capability
- **Context window** — large system snapshots + long conversations may exceed limits
- **Quality variance** — smaller models (3-4B) may give less accurate diagnostics
- **Speed** — larger models (20B+) need 16+ GB RAM and may be slow

### Platform Constraints

- **No arbitrary shell** — only allowlisted commands in guarded mode
- **Windows-focused** — some diagnostics tools are Windows-specific
- **No cloud fallback** — if Ollama is down, no automatic fallback to cloud models

---

## Roadmap

### Near Term

- [ ] GUI interface (TBD: customtkinter)
- [ ] Conversation export (JSON, Markdown)
- [ ] System snapshot export/import
- [ ] Model switching without restart
- [ ] Response time statistics in REPL

### Medium Term

- [ ] Voice input support
- [ ] Multi-language UI
- [ ] Scheduled diagnostics
- [ ] Report generation (PDF)
- [ ] System monitoring dashboard

### Long Term

- [ ] Multi-agent collaboration
- [ ] Remote machine management
- [ ] Plugin system for custom tools
- [ ] Cloud model fallback
- [ ] Mobile companion app

---

## Extending Medfarl

### Adding a New Tool

1. Create tool in `tools/tools.py` or new file in `tools/`:

```python
from core.llm_client import Tool

def my_custom_tool(arg1: str) -> str:
    """Do something useful."""
    return f"Result: {arg1}"

my_tool = Tool(
    name="my_custom_tool",
    description="Describe what this tool does for the LLM.",
    parameters={
        "type": "object",
        "properties": {
            "arg1": {
                "type": "string",
                "description": "Description of arg1",
            }
        },
        "required": ["arg1"],
    },
    fn=my_custom_tool,
)
```

2. Register in `build_tools()` function
3. Add to tool schemas if needed

### Adding Intent Normalization

Add to `INTENT_NORMALIZATION` dict in `core/agent.py`:

```python
INTENT_NORMALIZATION = {
    "my phrase": "Normalized intent",
    ...
}
```

### Custom System Scanner

Extend `SystemScanner` in `core/system_scanner.py`:

```python
class MyCustomScanner(SystemScanner):
    def to_dict(self):
        snapshot = super().to_dict()
        snapshot["my_metric"] = self._read_my_metric()
        return snapshot
```

---

## Authors and Core Development Team

Medfarl AI System — local-first PC diagnostics assistant.

---

## License

See [LICENSE](LICENSE) file for details.

---

**Enjoy local-first AI diagnostics!** 🚀
