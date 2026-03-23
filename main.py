from __future__ import annotations

import argparse
import time
import sys

from config import settings
from core.agent import MedfarlAgent
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


def run_healthcheck(model: str | None = None, timeout: int | None = None) -> int:
    client = build_client_with_timeout(model, timeout)
    result = client.healthcheck()

    if result["ok"]:
        print(f"[ok] Ollama reachable at {result['base_url']}")
        print(f"[ok] Model available: {result['model']}")
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
        help="check Ollama connectivity, model availability, and tool support, then exit",
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
        "--timeout",
        type=int,
        help="override the HTTP timeout in seconds for this run",
    )
    parser.add_argument(
        "--unsafe-full-access",
        action="store_true",
        help="enable unrestricted local filesystem, shell, and program access for this session",
    )
    return parser.parse_args()


def _cli_help_text(unsafe_mode: bool) -> str:
    lines = [
        "CLI commands:",
        "- /help   show interactive help",
        "- /reset  clear session history and bootstrap context",
        "- /status show current model and mode",
        "- /tools  list registered tools for this session",
        "- /quit   exit the session",
        "- /q      short exit alias",
        "- exit    exit the session",
    ]
    if unsafe_mode:
        lines.append(
            "- unsafe mode is ON: full filesystem, CMD, PowerShell, and program execution are available"
        )
    else:
        lines.append(
            "- unsafe mode is OFF: guarded tool access and approval gates remain enabled"
        )
    return "\n".join(lines)


def _cli_status_text(selected_model: str, selected_timeout: int) -> str:
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


def main() -> None:
    configure_console()
    args = parse_args()

    if args.unsafe_full_access:
        settings.enable_unsafe_full_access()

    selected_model = args.model or settings.model
    selected_timeout = args.timeout or settings.timeout

    if args.list_models:
        raise SystemExit(list_models(selected_model, selected_timeout))

    if args.healthcheck:
        raise SystemExit(run_healthcheck(selected_model, selected_timeout))

    if args.benchmark_models:
        raise SystemExit(run_benchmark(args.benchmark_models, selected_timeout))

    if not args.skip_healthcheck:
        preflight_code = run_healthcheck(selected_model, selected_timeout)
        if preflight_code != 0:
            print(
                "[hint] Run `python main.py --healthcheck` for details after fixing Ollama."
            )
            raise SystemExit(preflight_code)

    print_banner(unsafe_mode=settings.unsafe_full_access)
    agent = MedfarlAgent(model=selected_model, timeout=selected_timeout)

    while True:
        user_input = prompt_user(unsafe_mode=settings.unsafe_full_access)
        if not user_input:
            continue

        lowered = user_input.strip().lower()
        if lowered in {"/help", "help cli"}:
            print(f"\n{_cli_help_text(settings.unsafe_full_access)}\n")
            continue

        if lowered in {"/reset", "reset chat"}:
            agent.reset()
            print("\nSession reset.\n")
            continue

        if lowered in {"/status", "status cli"}:
            print(f"\n{_cli_status_text(selected_model, selected_timeout)}\n")
            continue

        if lowered in {"/tools", "tools cli"}:
            tool_names = "\n".join(f"- {tool.name}" for tool in agent.tool_registry)
            print(f"\nRegistered tools:\n{tool_names}\n")
            continue

        if lowered in {"/quit", "/q", "/exit", "exit", "quit", "q"}:
            print("Goodbye.")
            break

        try:
            response = agent.handle_user_message(user_input)
            print(f"\n{response}\n")
        except KeyboardInterrupt:
            print("\nInterrupted by user.\n")
        except Exception as exc:
            print(f"\n[error] {exc}\n")


if __name__ == "__main__":
    sys.exit(main())
