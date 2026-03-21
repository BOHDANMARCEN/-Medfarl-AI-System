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


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _expect_contains(reply: str, needle: str, label: str) -> None:
    _assert(
        needle in reply, f"{label}: expected '{needle}' in reply, got: {reply[:300]}"
    )


def main() -> None:
    agent = MedfarlAgent(timeout=60)

    # --- Classifier route assertions ---
    route_help = agent.classify_request("а що ти ще можеш")
    _assert(route_help.get("route") == ROUTE_LLM_REASONING, "help should route to llm")
    _assert(route_help.get("kind") == "help", "help kind")
    _assert(route_help.get("fallback_reply") is not None, "help has fallback_reply")

    route_diag = agent.classify_request("діагностика ПК")
    _assert(
        route_diag.get("route") == ROUTE_DETERMINISTIC_SUMMARY,
        "diagnostic should route to deterministic_summary",
    )
    _assert(route_diag.get("kind") == "summary_intent", "diagnostic kind")

    route_action = agent.classify_request("встанови пакет rich")
    _assert(
        route_action.get("route") == ROUTE_DETERMINISTIC_ACTION,
        "install should route to deterministic_action",
    )
    _assert(route_action.get("kind") == "maintenance_or_files", "install kind")
    _assert(route_action.get("payload") is not None, "install has payload")
    _assert(
        route_action["payload"].get("tool_name") == "pip_install_package",
        "install tool_name",
    )
    _assert(
        route_action["payload"].get("arguments", {}).get("name") == "rich",
        "install package name",
    )

    restore_cls = agent.classify_request(
        "restore from quarantine qk-1234abcd qk-deadbeef"
    )
    _assert(
        restore_cls.get("route") == ROUTE_DETERMINISTIC_ACTION,
        "restore routes to action",
    )
    _assert(restore_cls.get("kind") == "restore_quarantine", "restore kind")
    _assert(restore_cls.get("payload") is not None, "restore has payload")
    _assert(
        "qk-1234abcd" in restore_cls["payload"].get("entry_ids", []),
        "restore entry_ids",
    )
    _assert(
        "qk-deadbeef" in restore_cls["payload"].get("entry_ids", []),
        "restore entry_ids 2",
    )

    restore_guided = agent.classify_request("restore from quarantine")
    _assert(
        restore_guided.get("route") == ROUTE_DETERMINISTIC_ACTION,
        "guided restore routes to action",
    )
    _assert(
        restore_guided.get("guided_reply") is not None,
        "guided restore has guided_reply",
    )

    av_update = agent.classify_request("онови бази антивіруса")
    _assert(
        av_update.get("route") == ROUTE_DETERMINISTIC_ACTION,
        "av update routes to action",
    )
    _assert(av_update.get("kind") == "antivirus_update", "av update kind")
    _assert(
        av_update["payload"].get("tool_name") == "update_antivirus_definitions",
        "av update tool_name",
    )

    av_threats = agent.classify_request("покажи загрози антивіруса")
    _assert(
        av_threats.get("route") == ROUTE_DETERMINISTIC_ACTION,
        "av threats routes to action",
    )
    _assert(av_threats.get("kind") == "antivirus_threats", "av threats kind")

    av_generic = agent.classify_request("перевір антивірусом")
    _assert(
        av_generic.get("route") == ROUTE_DETERMINISTIC_ACTION,
        "generic av routes to action",
    )
    _assert(av_generic.get("kind") == "antivirus_detect_or_scan", "generic av kind")

    path_guidance_cls = agent.classify_request(
        "запусти C:\\Windows\\System32\\suspicious.exe"
    )
    _assert(
        path_guidance_cls.get("route") == ROUTE_DETERMINISTIC_ACTION,
        "blocked path routes to action",
    )
    _assert(path_guidance_cls.get("kind") == "path_guidance", "blocked path kind")
    _assert(
        path_guidance_cls.get("guided_reply") is not None,
        "blocked path has guided_reply",
    )

    ambiguous_cls = agent.classify_request("ну")
    _assert(
        ambiguous_cls.get("route") == ROUTE_DETERMINISTIC_SUMMARY,
        "ambiguous routes to summary",
    )
    _assert(ambiguous_cls.get("kind") == "ambiguous", "ambiguous kind")

    open_ended_cls = agent.classify_request("чому мій комп працює повільно")
    _assert(
        open_ended_cls.get("route") == ROUTE_LLM_REASONING, "open-ended routes to llm"
    )
    _assert(open_ended_cls.get("kind") == "open_ended", "open-ended kind")

    # --- Help timeout fallback (TimeoutError) ---
    original_loop = agent._run_agent_loop

    def _timeout_loop() -> str:
        raise TimeoutError("timeout during help reasoning")

    agent._run_agent_loop = _timeout_loop
    help_fallback = agent.handle_user_message("а що ти ще можеш")
    _expect_contains(help_fallback, "Я можу допомогти", "help timeout fallback")
    agent._run_agent_loop = original_loop

    # --- Help non-timeout error fallback ---
    def _error_loop() -> str:
        raise RuntimeError("model unavailable")

    agent._run_agent_loop = _error_loop
    help_error_fallback = agent.handle_user_message("а що ти ще можеш")
    _expect_contains(
        help_error_fallback, "Я можу допомогти", "help non-timeout fallback"
    )
    agent._run_agent_loop = original_loop

    # --- Pending action blocks new install but allows pending/cancel ---
    _assert(not agent.approval.has_pending(), "no pending at start")
    install_reply = agent.handle_user_message("встанови пакет requests")
    _expect_contains(install_reply, "Action ID", "install creates pending")
    install_id = agent.approval.pending.id
    pending_while_pending = agent.handle_user_message("pending")
    _expect_contains(pending_while_pending, install_id, "pending command sees existing")
    cancel_while_pending = agent.handle_user_message(f"cancel {install_id}")
    _expect_contains(cancel_while_pending, "Скасовано", "cancel works while pending")
    _assert(not agent.approval.has_pending(), "approval cleared after cancel")

    greeting = agent.handle_user_message("привіт")
    _expect_contains(greeting, "Що саме перевірити", "greeting flow")

    help_reply = agent.handle_user_message("а що ти ще можеш")
    _assert(bool(help_reply.strip()), "help flow should return non-empty reply")

    guided_create = agent.handle_user_message("файл створи")
    _expect_contains(guided_create, "мені потрібен шлях", "guided create file flow")

    guided_install = agent.handle_user_message("встанови пакет")
    _expect_contains(
        guided_install,
        "можу встановити Python-пакет",
        "guided install package flow",
    )

    diagnostic = agent.handle_user_message("діагностикою ПК")
    _expect_contains(
        diagnostic, "Добре, запускаю базову діагностику системи.", "diagnostic flow"
    )
    _expect_contains(diagnostic, "- CPU:", "diagnostic flow cpu")

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

    antivirus = agent.handle_user_message("перевір антивірусом")
    _assert(
        ("антивірус" in antivirus.casefold()) or ("defender" in antivirus.casefold()),
        f"antivirus detect flow: unexpected reply: {antivirus[:300]}",
    )

    antivirus_update = agent.handle_user_message("онови бази антивіруса")
    _expect_contains(antivirus_update, "Action ID", "antivirus update pending")
    _assert(agent.approval.has_pending(), "expected pending antivirus update action")
    pending_id = agent.approval.pending.id

    pending = agent.handle_user_message("pending")
    _expect_contains(pending, pending_id, "pending command")

    cancel = agent.handle_user_message(f"cancel {pending_id}")
    _expect_contains(cancel, "Скасовано", "cancel pending action")

    install = agent.handle_user_message("встанови пакет rich")
    _expect_contains(install, "Action ID", "install package pending")
    install_id = agent.approval.pending.id
    cancel_install = agent.handle_user_message(f"cancel {install_id}")
    _expect_contains(cancel_install, "Скасовано", "cancel package install")

    create_file = agent.handle_user_message("створи файл alpha_smoke_note.txt")
    _expect_contains(create_file, "Action ID", "create file pending")
    file_id = agent.approval.pending.id
    cancel_file = agent.handle_user_message(f"cancel {file_id}")
    _expect_contains(cancel_file, "Скасовано", "cancel create file")

    quarantine = agent.handle_user_message("show quarantine")
    _expect_contains(quarantine, "quarantine", "show quarantine")

    history = agent.handle_user_message("history actions 5")
    _expect_contains(history, "Останні дії", "history command")

    last = agent.handle_user_message("last action")
    _expect_contains(last, "Остання зафіксована дія", "last action command")

    print("Intent smoke tests passed.")


if __name__ == "__main__":
    main()
