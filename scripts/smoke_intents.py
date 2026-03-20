from __future__ import annotations

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.agent import MedfarlAgent


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _expect_contains(reply: str, needle: str, label: str) -> None:
    _assert(
        needle in reply, f"{label}: expected '{needle}' in reply, got: {reply[:300]}"
    )


def main() -> None:
    agent = MedfarlAgent(timeout=60)

    greeting = agent.handle_user_message("привіт")
    _expect_contains(greeting, "Що саме перевірити", "greeting flow")

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
