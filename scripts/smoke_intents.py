from __future__ import annotations

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.agent import (
    MedfarlAgent,
    ROUTE_DETERMINISTIC_ACTION,
    ROUTE_DETERMINISTIC_SUMMARY,
    ROUTE_LLM_REASONING,
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


def _expect_absent(reply: str, needle: str, label: str) -> None:
    _assert(
        needle not in reply,
        f"{label}: unexpected '{needle}' in reply: {reply[:300]}",
    )


def _expect_no_linux_tokens(reply: str, label: str) -> None:
    lowered = reply.casefold()
    for token in LINUX_ONLY_TOKENS:
        _assert(token not in lowered, f"{label}: unexpected linux-only token '{token}'")


def _fake_help_menu(messages, tools=None, **kwargs):
    return {
        "assistant_message": {
            "content": (
                "Що тобі зараз ближче?\n\n"
                "1. діагностика ПК\n"
                "2. обслуговування / дії\n"
                "3. інше запитання"
            )
        }
    }


def _run_classifier_assertions() -> None:
    agent = MedfarlAgent(timeout=60)

    help_route = agent.classify_request("а що ти ще можеш")
    _assert(help_route.get("route") == ROUTE_LLM_REASONING, "help should route to llm")
    _assert(help_route.get("kind") == "help", "help kind")
    _assert(help_route.get("fallback_reply") is not None, "help fallback reply")

    diag_route = agent.classify_request("діагностика ПК")
    _assert(
        diag_route.get("route") == ROUTE_DETERMINISTIC_SUMMARY,
        "diagnostic should route to deterministic_summary",
    )
    _assert(diag_route.get("kind") == "summary_intent", "diagnostic kind")

    install_route = agent.classify_request("встанови пакет rich")
    _assert(
        install_route.get("route") == ROUTE_DETERMINISTIC_ACTION,
        "install should route to deterministic_action",
    )
    _assert(install_route.get("kind") == "maintenance_or_files", "install kind")
    _assert(install_route.get("payload") is not None, "install payload")
    _assert(
        install_route["payload"].get("tool_name") == "pip_install_package",
        "install tool_name",
    )
    _assert(
        install_route["payload"].get("arguments", {}).get("name") == "rich",
        "install package name",
    )

    show_quarantine_route = agent.classify_request("покажи що в карантині")
    _assert(
        show_quarantine_route.get("route") == ROUTE_DETERMINISTIC_ACTION,
        "show quarantine ua routes to action",
    )
    _assert(
        show_quarantine_route.get("kind") == "show_quarantine",
        "show quarantine ua kind",
    )

    restore_route = agent.classify_request(
        "віднови з карантину qk-1234abcd qk-deadbeef"
    )
    _assert(
        restore_route.get("route") == ROUTE_DETERMINISTIC_ACTION,
        "restore routes to action",
    )
    _assert(restore_route.get("kind") == "restore_quarantine", "restore kind")
    _assert(restore_route.get("payload") is not None, "restore payload")
    _assert(
        "qk-1234abcd" in restore_route["payload"].get("entry_ids", []),
        "restore entry id 1",
    )
    _assert(
        "qk-deadbeef" in restore_route["payload"].get("entry_ids", []),
        "restore entry id 2",
    )

    restore_guided = agent.classify_request("віднови з карантину")
    _assert(
        restore_guided.get("guided_reply") is not None,
        "restore guided reply",
    )

    av_update = agent.classify_request("онови бази антивіруса")
    _assert(av_update.get("kind") == "antivirus_update", "av update kind")
    _assert(
        av_update["payload"].get("tool_name") == "update_antivirus_definitions",
        "av update tool name",
    )

    av_threats = agent.classify_request("покажи загрози антивіруса")
    _assert(av_threats.get("kind") == "antivirus_threats", "av threats kind")

    av_generic = agent.classify_request("перевір антивірусом")
    _assert(
        av_generic.get("kind") == "antivirus_detect_or_scan",
        "generic av kind",
    )

    blocked_path = agent.classify_request(
        "запусти C:\\Windows\\System32\\suspicious.exe"
    )
    _assert(blocked_path.get("kind") == "path_guidance", "blocked path kind")
    _assert(blocked_path.get("guided_reply") is not None, "blocked path guided")

    ambiguous = agent.classify_request("ну")
    _assert(
        ambiguous.get("route") == ROUTE_DETERMINISTIC_SUMMARY,
        "ambiguous routes to summary",
    )
    _assert(ambiguous.get("kind") == "ambiguous", "ambiguous kind")

    open_ended = agent.classify_request("чому мій комп працює повільно")
    _assert(
        open_ended.get("route") == ROUTE_LLM_REASONING,
        "open-ended routes to llm",
    )
    _assert(open_ended.get("kind") == "open_ended", "open-ended kind")


def _run_help_and_menu_assertions() -> None:
    agent = MedfarlAgent(timeout=60)
    original_chat = agent.client.chat

    def _timeout_chat(messages, tools=None, **kwargs):
        raise TimeoutError("timeout during help")

    agent.client.chat = _timeout_chat
    help_fallback = agent.handle_user_message("а що ти ще можеш")
    _expect_contains(help_fallback, "діагностика", "help timeout fallback has diag")
    _expect_contains(
        help_fallback, "створи файл", "help timeout fallback has create file"
    )

    def _error_chat(messages, tools=None, **kwargs):
        raise RuntimeError("model unavailable")

    agent.client.chat = _error_chat
    help_error_fallback = agent.handle_user_message("а що ти ще можеш")
    _expect_contains(
        help_error_fallback,
        "діагностика",
        "help non-timeout fallback has diag",
    )

    agent.client.chat = _fake_help_menu
    help_menu = agent.handle_user_message("а що ти ще можеш")
    _expect_contains(help_menu, "1. діагностика ПК", "interactive help option 1")
    _expect_contains(help_menu, "2. обслуговування / дії", "interactive help option 2")
    _expect_contains(help_menu, "3. інше запитання", "interactive help option 3")
    _expect_no_linux_tokens(help_menu, "interactive help menu")

    help_choice_1 = agent.handle_user_message("1")
    _expect_contains(
        help_choice_1, "Добре, запускаю базову діагностику системи.", "help choice 1"
    )

    agent.client.chat = _fake_help_menu
    agent.handle_user_message("а що ти ще можеш")
    help_choice_2 = agent.handle_user_message("2")
    _expect_contains(help_choice_2, "основні дії обслуговування", "help choice 2")
    _expect_contains(help_choice_2, "встанови пакет rich", "help choice 2 example")

    agent.client.chat = _fake_help_menu
    agent.handle_user_message("а що ти ще можеш")
    help_choice_3 = agent.handle_user_message("3")
    _expect_contains(help_choice_3, "напиши коротко", "help choice 3")

    agent.client.chat = original_chat
    real_help_reply = agent.handle_user_message("а що ти ще можеш")
    _assert(bool(real_help_reply.strip()), "real help reply should be non-empty")
    _assert(len(real_help_reply) < 800, "real help reply should stay concise")
    _expect_no_linux_tokens(real_help_reply, "real help reply")


def _run_pending_and_e2e_assertions() -> None:
    agent = MedfarlAgent(timeout=60)

    greeting = agent.handle_user_message("привіт")
    _expect_contains(greeting, "Що саме перевірити", "greeting flow")

    diagnostic = agent.handle_user_message("діагностикою ПК")
    _expect_contains(
        diagnostic, "Добре, запускаю базову діагностику системи.", "diagnostic flow"
    )
    _expect_contains(diagnostic, "- CPU:", "diagnostic cpu")

    processes = agent.handle_user_message("процеси")
    _expect_contains(processes, "найважчі процеси", "process flow")

    disks = agent.handle_user_message("диски")
    _expect_contains(disks, "перевіряю диски", "disk flow")

    network = agent.handle_user_message("мережа")
    _expect_contains(network, "стан мережі", "network flow")

    logs = agent.handle_user_message("логи")
    _assert(
        ("системні помилки" in logs)
        or ("критичних помилок" in logs)
        or ("Не вдалося" in logs),
        f"logs flow: unexpected reply: {logs[:300]}",
    )

    blocked_path = agent.handle_user_message(r"запусти C:\Windows\System32\cmd.exe")
    _expect_no_linux_tokens(blocked_path, "blocked path guidance")
    _expect_absent(blocked_path, "sudo", "blocked path should not mention sudo")

    antivirus = agent.handle_user_message("перевір антивірусом")
    _assert(
        ("Action ID" in antivirus)
        or ("антивірус" in antivirus.casefold())
        or ("defender" in antivirus.casefold()),
        f"antivirus detect flow: unexpected reply: {antivirus[:300]}",
    )
    _expect_no_linux_tokens(antivirus, "antivirus reply")
    if agent.approval.has_pending():
        cancel_antivirus = agent.handle_user_message(
            f"cancel {agent.approval.pending.id}"
        )
        _expect_contains(cancel_antivirus, "Скасовано", "cancel antivirus quick scan")

    pending_reply = agent.handle_user_message("створи файл alpha_pending_note.txt")
    _expect_contains(pending_reply, "Action ID", "create file pending")
    pending_id = agent.approval.pending.id

    help_during_pending = agent.handle_user_message("help")
    _assert(bool(help_during_pending.strip()), "help should work during pending")

    diag_during_pending = agent.handle_user_message("діагностика ПК")
    _expect_contains(
        diag_during_pending,
        "Добре, запускаю базову діагностику системи.",
        "diagnostic during pending",
    )

    quarantine_during_pending = agent.handle_user_message("покажи що в карантині")
    _expect_contains(
        quarantine_during_pending, "quarantine", "show quarantine during pending"
    )

    history_during_pending = agent.handle_user_message("history actions 5")
    _expect_contains(history_during_pending, "Останні дії", "history during pending")

    last_during_pending = agent.handle_user_message("last action")
    _expect_contains(
        last_during_pending, "Остання зафіксована дія", "last during pending"
    )

    second_mutating = agent.handle_user_message("встанови пакет rich")
    _expect_contains(
        second_mutating, "одна pending-дія", "new mutating blocked while pending"
    )
    _assert(agent.approval.pending.id == pending_id, "pending id should stay the same")

    wrong_approve = agent.handle_user_message("approve wrongid")
    _expect_contains(wrong_approve, "не збігається", "wrong approve id")

    cancel_bare = agent.handle_user_message("ні")
    _expect_contains(cancel_bare, "Скасовано", "bare no should cancel pending")
    _assert(not agent.approval.has_pending(), "pending should be cleared after bare no")

    yes_file = Path("alpha_yes_note.txt")
    yes_file.unlink(missing_ok=True)
    yes_pending = agent.handle_user_message("створи файл alpha_yes_note.txt")
    _expect_contains(yes_pending, "Action ID", "yes test pending")
    approved_bare = agent.handle_user_message("так")
    _expect_contains(approved_bare, "Підтверджено. Виконую дію:", "bare yes approves")
    _assert(yes_file.exists(), "bare yes should execute pending file creation")
    yes_file.unlink(missing_ok=True)


def main() -> None:
    _run_classifier_assertions()
    _run_help_and_menu_assertions()
    _run_pending_and_e2e_assertions()
    print("Intent smoke tests passed.")


if __name__ == "__main__":
    main()
