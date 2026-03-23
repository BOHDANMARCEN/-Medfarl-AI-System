from __future__ import annotations

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.agent import (
    MedfarlAgent,
    ROUTE_CLARIFICATION,
    ROUTE_DIRECT_RESPONSE,
    ROUTE_GUIDED_MANUAL_MODE,
    ROUTE_TOOL_USE,
)


LINUX_ONLY_TOKENS = (
    "systemctl",
    "journalctl",
    "/proc",
    "/var/log",
    "apt install",
    "sudo apt",
)


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _expect_contains(reply: str, needle: str, label: str) -> None:
    _assert(
        needle in reply,
        f"{label}: expected '{needle}' in reply, got: {reply[:300]}",
    )


def _expect_no_linux_tokens(reply: str, label: str) -> None:
    lowered = reply.casefold()
    for token in LINUX_ONLY_TOKENS:
        _assert(token not in lowered, f"{label}: unexpected linux-only token '{token}'")


def _run_classifier_assertions() -> None:
    agent = MedfarlAgent(timeout=60)

    help_route = agent.classify_request("а що ти ще можеш")
    _assert(help_route.get("route") == ROUTE_DIRECT_RESPONSE, "help route")
    _assert(help_route.get("kind") == "help_menu", "help kind")
    _assert("діагностика ПК" in (help_route.get("direct_reply") or ""), "help menu")

    diag_route = agent.classify_request("діагностика ПК")
    _assert(diag_route.get("route") == ROUTE_TOOL_USE, "diagnostic route")
    _assert(diag_route.get("kind") == "summary_intent", "diagnostic kind")

    install_route = agent.classify_request("встанови пакет rich")
    _assert(install_route.get("route") == ROUTE_TOOL_USE, "install route")
    _assert(install_route.get("kind") == "maintenance_or_files", "install kind")
    _assert(
        install_route["payload"].get("tool_name") == "pip_install_package",
        "install tool_name",
    )

    path_route = agent.classify_request(r"C:\clamav-1.5.1.win.x64")
    _assert(path_route.get("route") == ROUTE_GUIDED_MANUAL_MODE, "path route")

    blocked_route = agent.classify_request(r"запусти C:\Windows\System32\cmd.exe")
    _assert(
        blocked_route.get("route") == ROUTE_GUIDED_MANUAL_MODE,
        "blocked path route",
    )

    ambiguous = agent.classify_request("воно не працює")
    _assert(ambiguous.get("route") == ROUTE_CLARIFICATION, "ambiguous route")


def _run_chat_flow_assertions() -> None:
    agent = MedfarlAgent(timeout=60)

    greeting = agent.handle_user_message("привіт")
    _expect_contains(greeting, "Що саме перевірити", "uk greeting")

    greeting_ru = agent.handle_user_message("привет")
    _expect_contains(greeting_ru, "Что именно проверить", "ru greeting")

    greeting_en = agent.handle_user_message("hello")
    _expect_contains(greeting_en, "What should I check first", "en greeting")

    help_menu = agent.handle_user_message("help")
    _expect_contains(help_menu, "1. PC diagnostics", "help menu en")

    help_choice = agent.handle_user_message("1")
    _expect_contains(help_choice, "CPU", "help choice diagnostic")

    path_reply = agent.handle_user_message(r"C:\clamav-1.5.1.win.x64")
    _expect_contains(path_reply, "clamscan.exe", "path clarification/manual")
    _expect_no_linux_tokens(path_reply, "path reply")

    follow_up = agent.handle_user_message("там антивірус його треба запустити")
    _expect_contains(follow_up, "clamscan.exe", "recent path follow-up")
    _expect_no_linux_tokens(follow_up, "follow-up guidance")

    diagnostic = agent.handle_user_message("діагностикою ПК")
    _expect_contains(diagnostic, "базову діагностику", "diagnostic flow")

    network = agent.handle_user_message("мережа")
    _expect_contains(network, "мережі", "network flow")

    clarification = agent.handle_user_message("воно не працює")
    _expect_contains(clarification, "що саме перевірити", "clarification flow")


def main() -> None:
    _run_classifier_assertions()
    _run_chat_flow_assertions()
    print("Intent smoke tests passed.")


if __name__ == "__main__":
    main()
