from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.agent import MedfarlAgent


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _extract_result_payload(reply: str) -> dict:
    marker = "Результат:\n"
    _assert(marker in reply, f"Expected result marker in reply: {reply[:200]}")
    payload = reply.split(marker, 1)[1].strip()
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"Could not parse JSON payload: {exc}\n{payload[:300]}")


def main() -> None:
    agent = MedfarlAgent(timeout=60)

    # request -> pending
    reply = agent.handle_user_message("встанови пакет rich")
    _assert("Action ID" in reply, "Expected pending action message for install request")
    _assert(
        agent.approval.has_pending(),
        "Pending action should be present after install intent",
    )
    pending_id = agent.approval.pending.id

    # wrong id -> safe refusal
    wrong = agent.handle_user_message("approve wrongid")
    _assert("не збігається" in wrong, "Expected ID mismatch safeguard message")

    # cancel -> clear pending
    cancelled = agent.handle_user_message(f"cancel {pending_id}")
    _assert("Скасовано" in cancelled, "Expected cancellation confirmation")
    _assert(
        not agent.approval.has_pending(),
        "Pending action should be cleared after cancel",
    )

    # approve -> execute for deterministic create file
    test_file = Path("smoke_maintenance_note.txt")
    if test_file.exists():
        test_file.unlink()

    create_reply = agent.handle_user_message("створи файл smoke_maintenance_note.txt")
    _assert(
        agent.approval.has_pending(), "Expected pending action for create file intent"
    )
    create_id = agent.approval.pending.id
    approved_create = agent.handle_user_message(f"approve {create_id}")
    _assert("Підсумок:" in approved_create, "Expected execution summary after approve")
    _assert(test_file.exists(), "Create file action should create target file")
    test_file.unlink(missing_ok=True)

    # blocked exec path -> guided fallback
    blocked = agent.handle_user_message(r"запусти C:\Windows\System32\cmd.exe")
    _assert(
        ("не можу" in blocked.casefold()) or ("дозволен" in blocked.casefold()),
        "Expected safe guided fallback for blocked executable path",
    )

    # junk preview
    junk_preview = agent.handle_user_message("знайди сміття")
    _assert(
        "preview" in junk_preview.casefold(),
        "Expected deterministic junk preview report",
    )

    # quarantine -> delete via approval flow
    temp_junk = Path(tempfile.gettempdir()) / "medfarl_smoke_junk.tmp"
    temp_junk.write_text("junk", encoding="utf-8")

    move_request = agent.handle_user_message(f"move junk to quarantine {temp_junk}")
    _assert(
        agent.approval.has_pending(), "Expected pending action for move junk request"
    )
    move_id = agent.approval.pending.id
    move_result_reply = agent.handle_user_message(f"approve {move_id}")
    move_payload = _extract_result_payload(move_result_reply)
    moved = move_payload.get("moved", [])
    _assert(moved, "Expected at least one moved junk entry")
    moved_destination = Path(moved[0]["destination"])

    delete_request = agent.handle_user_message(f"delete junk {moved_destination}")
    _assert(
        agent.approval.has_pending(), "Expected pending action for delete junk request"
    )
    delete_id = agent.approval.pending.id
    delete_result_reply = agent.handle_user_message(f"approve {delete_id}")
    delete_payload = _extract_result_payload(delete_result_reply)
    _assert(
        delete_payload.get("deleted_count", 0) >= 1,
        "Expected at least one deleted junk entry",
    )

    # history / last action commands
    history = agent.handle_user_message("history actions 5")
    _assert("Останні дії" in history, "Expected action history response")
    last = agent.handle_user_message("last action")
    _assert("Остання зафіксована дія" in last, "Expected last action response")

    # antivirus deterministic phrase should produce a stable response
    antivirus = agent.handle_user_message("перевір антивірусом")
    _assert(
        ("антивірус" in antivirus.casefold()) or ("defender" in antivirus.casefold()),
        "Expected antivirus status/scan response",
    )

    print("Maintenance smoke tests passed.")


if __name__ == "__main__":
    main()
