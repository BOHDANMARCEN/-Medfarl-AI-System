from __future__ import annotations

import argparse
import os
import time
import sys

from config import settings
from core.agent import MedfarlAgent
from core.chat import ChatSession
from core.coder import CoderSession, run_coder_cli
from core.llm_client import LLMClient
from ui.cli import configure_console, print_banner, prompt_user


def build_client(model: str | None = None) -> LLMClient:
    return LLMClient(
        base_url=settings.llm_url,
        model=model or settings.model,
        timeout=settings.timeout,
    )


def build_client_with_timeout(
    model: str | None = None, timeout: int | None = None
) -> LLMClient:
    return LLMClient(
        base_url=settings.llm_url,
        model=model or settings.model,
        timeout=timeout or settings.timeout,
    )


def run_healthcheck(
    model: str | None = None, timeout: int | None = None, *, require_tools: bool = True
) -> int:
    client = build_client_with_timeout(model, timeout)
    result = client.healthcheck(require_tools=require_tools)

    if result["ok"]:
        print(f"[ok] Ollama reachable at {result['base_url']}")
        print(f"[ok] Model available: {result['model']}")
        if require_tools:
            print(f"[ok] Tool calling supported: {result['model']}")
        return 0

    print(f"[error] {result['error']}")
    if result.get("server_reachable"):
        print(f"[ok] Ollama reachable at {result['base_url']}")
    if result.get("model_available"):
        print(f"[ok] Model available: {result['model']}")
    if result.get("server_reachable"):
        available = result.get("available_models", [])
        if available:
            print("[info] Installed models:")
            for available_model in available:
                print(f"  - {available_model}")
    return 1


def list_models(model: str | None = None, timeout: int | None = None) -> int:
    client = build_client_with_timeout(model, timeout)
    try:
        available_models = client.list_models()
    except Exception as exc:
        print(f"[error] Cannot list models: {exc}")
        return 1

    if not available_models:
        print("[info] No models found in Ollama.")
        return 0

    print("[info] Installed models:")
    for available_model in available_models:
        marker = " (default)" if available_model == (model or settings.model) else ""
        print(f"  - {available_model}{marker}")
    return 0


def run_benchmark(models: list[str], timeout: int | None = None) -> int:
    prompts = [
        "привіт",
        "Коротко опиши цей ПК на основі наявного bootstrap context.",
        "Що можна сказати про диски на цій машині? Не вигадуй неіснуючі tools.",
    ]

    exit_code = 0
    for model in models:
        print(f"\n=== Benchmark: {model} ===")
        if run_healthcheck(model, timeout) != 0:
            exit_code = 1
            continue

        agent = MedfarlAgent(model=model, timeout=timeout)
        for prompt in prompts:
            started_at = time.perf_counter()
            try:
                reply = agent.handle_user_message(prompt)
            except Exception as exc:
                print(f"[error] Prompt failed for {model}: {exc}")
                exit_code = 1
                break
            duration = time.perf_counter() - started_at
            print(f"\n--- Prompt: {prompt}")
            print(f"[time] {duration:.2f}s")
            print(reply)
        print()
    return exit_code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Medfarl AI System")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--agent", action="store_true",
        help="enable PC diagnostics and tools instead of direct model chat",
    )
    modes.add_argument("--coder", action="store_true", help="interactive project coding agent with approval prompts")
    parser.add_argument("--workspace", default=os.getcwd(), help="project directory for --coder")
    parser.add_argument(
        "--model", help="override the default Ollama model for this run"
    )
    parser.add_argument(
        "--list-models",
        action="store_true",
        help="list installed Ollama models and exit",
    )
    parser.add_argument(
        "--healthcheck",
        action="store_true",
        help="check Ollama and model availability (also tool support with --agent or --coder)",
    )
    parser.add_argument(
        "--benchmark-models",
        nargs="+",
        metavar="MODEL",
        help="run a short benchmark across one or more installed models",
    )
    parser.add_argument(
        "--skip-healthcheck",
        action="store_true",
        help="skip startup healthcheck before opening the interactive session",
    )
    parser.add_argument(
        "--no-warmup",
        action="store_true",
        help="do not start Ollama or preload the selected model",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="override the HTTP timeout in seconds for this run",
    )
    parser.add_argument(
        "--unsafe-full-access",
        action="store_true",
        help="full access for diagnostics; in coder mode ask to expand file access, retaining action approvals",
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        help="enable streaming output explicitly (streaming is already the default)",
    )
    parser.add_argument(
        "--no-stream",
        action="store_true",
        help="disable streaming output and print full replies only after completion",
    )
    return parser.parse_args()


def _cli_help_text(unsafe_mode: bool, agent_mode: bool = True) -> str:
    lines = [
        "CLI commands:",
        "- /help   show interactive help",
        "- /reset  clear session history",
        "- /status show current model and mode",
        "- /quit   exit the session",
        "- /q      short exit alias",
        "- exit    exit the session",
    ]
    if not agent_mode:
        lines.append("- Direct model chat. Launch with --agent for PC diagnostics and tools.")
        return "\n".join(lines)
    lines.append("- /tools  list registered tools for this session")
    if unsafe_mode:
        lines.append(
            "- unsafe mode is ON: full filesystem, CMD, PowerShell, and program execution are available"
        )
        lines.extend(
            [
                "- /shell [powershell|cmd]  enter multi-line shell mode",
                "- /end                    run the buffered shell block",
                "- /cancel                 discard the buffered shell block",
                "- /show                   preview the buffered shell block",
            ]
        )
    else:
        lines.append(
            "- unsafe mode is OFF: guarded tool access and approval gates remain enabled"
        )
    return "\n".join(lines)


def _cli_status_text(
    selected_model: str, selected_timeout: int, agent_mode: bool = True
) -> str:
    if not agent_mode:
        return "\n".join([
            "Session status:", f"- model: {selected_model}",
            f"- timeout: {selected_timeout}", "- mode: direct chat",
        ])
    mode = "unsafe-full-access" if settings.unsafe_full_access else "guarded"
    return "\n".join(
        [
            "Session status:",
            f"- model: {selected_model}",
            f"- timeout: {selected_timeout}",
            f"- mode: {mode}",
            f"- read roots: {', '.join(settings.allowed_read_roots[:5])}",
            f"- exec roots: {', '.join(settings.allowed_exec_roots[:5])}",
        ]
    )


def _shell_prompt_label(shell_name: str) -> str:
    return f"\n  {shell_name}*> "


def main() -> None:
    configure_console()
    args = parse_args()

    if args.unsafe_full_access and not args.coder:
        settings.enable_unsafe_full_access()

    selected_model = args.model or (os.getenv("MEDFARL_CODER_MODEL", settings.model) if args.coder else settings.model)
    selected_timeout = args.timeout or settings.timeout
    enable_streaming = not args.no_stream
    agent_mode = args.agent or args.coder or settings.unsafe_full_access

    coder = None
    if args.coder:
        try:
            coder = CoderSession(build_client_with_timeout(selected_model, selected_timeout), args.workspace)
        except (OSError, ValueError) as exc:
            print(f"[error] {exc}")
            raise SystemExit(2)

    if args.list_models:
        raise SystemExit(list_models(selected_model, selected_timeout))

    if (
        not args.no_warmup
        and settings.warmup_on_start
        and not args.benchmark_models
    ):
        warmup_client = build_client_with_timeout(selected_model, selected_timeout)
        print(f"[..] Loading model into Ollama: {selected_model}")
        warmup_result = warmup_client.warmup(
            keep_alive=settings.keep_alive,
            autostart=settings.autostart_ollama,
        )
        if warmup_result["ok"]:
            print(f"[ok] Model ready: {warmup_result['model']}")
        else:
            print(f"[warn] {warmup_result['error']}")

    if args.healthcheck:
        raise SystemExit(run_healthcheck(
            selected_model, selected_timeout, require_tools=agent_mode
        ))

    if args.benchmark_models:
        raise SystemExit(run_benchmark(args.benchmark_models, selected_timeout))

    if not args.skip_healthcheck:
        preflight_code = run_healthcheck(
            selected_model, selected_timeout, require_tools=agent_mode
        )
        if preflight_code != 0:
            print(
                "[hint] Run `python main.py --healthcheck` for details after fixing Ollama."
            )
            raise SystemExit(preflight_code)

    if coder is not None:
        if args.unsafe_full_access:
            coder.set_full_access(True)
        run_coder_cli(coder, stream=enable_streaming)
        return

    if agent_mode:
        print_banner(unsafe_mode=settings.unsafe_full_access)
        agent = MedfarlAgent(model=selected_model, timeout=selected_timeout)
    else:
        print(f"\nMedfarl — інтерактивний чат\nМодель: {selected_model}")
        print(
            "Пишіть повідомлення й натискайте Enter. /reset — нова розмова, "
            "/quit — вихід.\n"
        )
        agent = ChatSession(
            build_client_with_timeout(selected_model, selected_timeout),
            system_prompt=settings.chat_system_prompt,
            reasoning_effort=settings.chat_reasoning_effort,
        )
    shell_mode: str | None = None
    shell_lines: list[str] = []

    while True:
        if shell_mode is not None:
            user_input = prompt_user(
                unsafe_mode=settings.unsafe_full_access,
                prompt_label=_shell_prompt_label(shell_mode),
                strip_input=False,
            )
        else:
            user_input = prompt_user(unsafe_mode=settings.unsafe_full_access)
        if not user_input and shell_mode is None:
            continue

        if shell_mode is not None:
            lowered_shell = user_input.strip().lower()
            if lowered_shell in {"/end", "/run"}:
                if not shell_lines:
                    print("\nShell buffer is empty.\n")
                    continue
                command_block = "\n".join(shell_lines)
                shell_lines = []
                current_shell = shell_mode
                shell_mode = None
                try:
                    response = agent.handle_user_message(
                        f"{current_shell} {command_block}"
                    )
                    print(f"\n{response}\n")
                except KeyboardInterrupt:
                    print("\nInterrupted by user.\n")
                except Exception as exc:
                    print(f"\n[error] {exc}\n")
                continue
            if lowered_shell in {"/cancel", "/cancel-shell"}:
                shell_lines = []
                shell_mode = None
                print("\nShell buffer discarded.\n")
                continue
            if lowered_shell in {"/show", "/buffer"}:
                preview = "\n".join(shell_lines) if shell_lines else "<empty>"
                print(f"\nBuffered {shell_mode} script:\n{preview}\n")
                continue
            if lowered_shell in {"/quit", "/q", "/exit"}:
                print("Goodbye.")
                break

            shell_lines.append(user_input)
            continue

        lowered = user_input.strip().lower()
        if lowered in {"/help", "help cli"}:
            print(f"\n{_cli_help_text(settings.unsafe_full_access, agent_mode)}\n")
            continue

        if lowered in {"/reset", "reset chat"}:
            agent.reset()
            print("\nSession reset.\n")
            continue

        if lowered in {"/status", "status cli"}:
            print(f"\n{_cli_status_text(selected_model, selected_timeout, agent_mode)}\n")
            continue

        if lowered in {"/tools", "tools cli"}:
            if not agent_mode:
                print("\nДля діагностики ПК та інструментів запустіть run.bat --agent.\n")
                continue
            tool_names = "\n".join(f"- {tool.name}" for tool in agent.tool_registry)
            print(f"\nRegistered tools:\n{tool_names}\n")
            continue

        if lowered in {"/ps", "/powershell", "/shell", "/shell powershell"}:
            if not settings.unsafe_full_access:
                print("\nShell mode is available only with --unsafe-full-access.\n")
                continue
            shell_mode = "powershell"
            shell_lines = []
            print(
                "\nEntered multi-line PowerShell mode. Use /end to run, /cancel to discard, /show to preview.\n"
            )
            continue

        if lowered in {"/cmd", "/shell cmd"}:
            if not settings.unsafe_full_access:
                print("\nShell mode is available only with --unsafe-full-access.\n")
                continue
            shell_mode = "cmd"
            shell_lines = []
            print(
                "\nEntered multi-line CMD mode. Use /end to run, /cancel to discard, /show to preview.\n"
            )
            continue

        if lowered in {"/quit", "/q", "/exit", "exit", "quit", "q"}:
            print("Goodbye.")
            break

        try:
            response = agent.handle_user_message(user_input, stream=enable_streaming)
            if not enable_streaming or not agent.last_response_streamed():
                print(f"\n{response}\n")
            else:
                print()
        except KeyboardInterrupt:
            print("\nInterrupted by user.\n")
        except Exception as exc:
            print(f"\n[error] {exc}\n")


if __name__ == "__main__":
    sys.exit(main())
