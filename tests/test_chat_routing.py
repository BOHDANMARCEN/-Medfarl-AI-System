from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from config import settings
from core.agent import (
    LANG_EN,
    LANG_RU,
    LANG_UK,
    MedfarlAgent,
    ROUTE_CLARIFICATION,
    ROUTE_DIRECT_RESPONSE,
    ROUTE_GUIDED_MANUAL_MODE,
    ROUTE_TOOL_USE,
)


class FakeScanner:
    def to_dict(self) -> dict:
        return {
            "cpu": {
                "model": "Test CPU",
                "usage_percent": 24.0,
                "cores_logical": 8,
            },
            "memory": {
                "used_gb": 8.5,
                "total_gb": 16.0,
                "percent": 53.1,
                "swap_used_gb": 0.0,
                "swap_total_gb": 4.0,
            },
            "disks": [
                {
                    "mountpoint": "C:",
                    "device": "disk0",
                    "fstype": "NTFS",
                    "total_gb": 512.0,
                    "used_gb": 240.0,
                    "free_gb": 272.0,
                    "percent": 46.9,
                }
            ],
            "top_processes": [
                {
                    "pid": 101,
                    "name": "browser.exe",
                    "cpu_percent": 18.5,
                    "memory_mb": 2048.0,
                    "status": "running",
                },
                {
                    "pid": 202,
                    "name": "editor.exe",
                    "cpu_percent": 8.2,
                    "memory_mb": 512.0,
                    "status": "running",
                },
            ],
            "network": {
                "Ethernet": {
                    "addresses": ["192.168.1.10"],
                    "bytes_sent_mb": 12.3,
                    "bytes_recv_mb": 48.7,
                    "packets_sent": 1000,
                    "packets_recv": 1200,
                }
            },
        }


class FakeInspector:
    def summary_dict(self) -> dict:
        return {
            "pip_packages_count": 12,
            "system_packages_count": 34,
            "failed_services": [],
        }

    def pip_packages(self) -> list:
        return []

    def pip_outdated(self) -> list:
        return []

    def failed_services(self) -> list:
        return []


class FakeClient:
    def __init__(self) -> None:
        self.model = "fake-model"
        self._tool_turns = 0
        self.calls: list[dict[str, object]] = []

    def chat(self, messages, tools=None, stream=False):
        last_user = next(
            (
                entry.get("content", "")
                for entry in reversed(messages)
                if entry.get("role") == "user"
            ),
            "",
        )
        self.calls.append({"last_user": last_user, "tool_mode": bool(tools)})

        if tools:
            if self._tool_turns == 0:
                self._tool_turns += 1
                return {
                    "assistant_message": {
                        "role": "assistant",
                        "content": "Перевіряю процеси.",
                    },
                    "tool_call": {
                        "name": "get_top_processes",
                        "arguments": {"count": 3},
                    },
                    "tool_call_id": "call_1",
                }
            return {
                "assistant_message": {
                    "role": "assistant",
                    "content": "Зараз найбільше RAM споживає browser.exe.",
                },
                "tool_call": None,
                "tool_call_id": None,
            }

        planner_payload = {
            "route": ROUTE_TOOL_USE,
            "normalized_user_request": last_user,
        }
        return {
            "assistant_message": {
                "role": "assistant",
                "content": json.dumps(planner_payload, ensure_ascii=False),
            },
            "tool_call": None,
            "tool_call_id": None,
        }


class UnavailableClient:
    def __init__(self) -> None:
        self.model = "fake-model"
        self.base_url = "http://localhost:11434"

    def chat(self, messages, tools=None, stream=False):
        raise RuntimeError("[WinError 10061] Connection refused")


class UnavailableTimeoutClient:
    def __init__(self) -> None:
        self.model = "fake-model"
        self.base_url = "http://localhost:11434"

    def chat(self, messages, tools=None, stream=False):
        raise TimeoutError("timed out")

    def server_check(self, timeout=3):
        return {
            "reachable": False,
            "base_url": self.base_url,
            "error": "connection refused",
        }


class ChatRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_read_roots = list(settings.allowed_read_roots)
        self.original_edit_roots = list(settings.allowed_edit_roots)
        self.original_exec_roots = list(settings.allowed_exec_roots)

    def tearDown(self) -> None:
        settings.allowed_read_roots = self.original_read_roots
        settings.allowed_edit_roots = self.original_edit_roots
        settings.allowed_exec_roots = self.original_exec_roots

    def _make_agent(self, client=None) -> MedfarlAgent:
        return MedfarlAgent(
            client=client,
            scanner=FakeScanner(),
            inspector=FakeInspector(),
            timeout=1,
        )

    def test_language_preservation_for_greetings(self) -> None:
        agent = self._make_agent()

        uk_reply = agent.handle_user_message("привіт")
        ru_reply = agent.handle_user_message("привет")
        en_reply = agent.handle_user_message("hello")

        self.assertIn("Що саме перевірити", uk_reply)
        self.assertIn("Что именно проверить", ru_reply)
        self.assertIn("What should I check first", en_reply)

    def test_path_inside_allowed_roots_asks_clarification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings.allowed_read_roots = [tmp]
            settings.allowed_exec_roots = [tmp]
            settings.allowed_edit_roots = [tmp]

            agent = self._make_agent()
            plan = agent.classify_request(tmp)

            self.assertEqual(plan["route"], ROUTE_CLARIFICATION)
            self.assertEqual(plan["kind"], "path_clarification")
            self.assertIn("What do you want to do next", plan["direct_reply"])

    def test_ambiguous_input_becomes_clarification(self) -> None:
        agent = self._make_agent()
        plan = agent.classify_request("воно не працює")

        self.assertEqual(plan["route"], ROUTE_CLARIFICATION)
        self.assertIn("що саме перевірити", plan["direct_reply"].casefold())

    def test_blocked_exec_path_enters_guided_manual_mode(self) -> None:
        agent = self._make_agent()
        plan = agent.classify_request(r"запусти C:\Windows\System32\cmd.exe")

        self.assertEqual(plan["route"], ROUTE_GUIDED_MANUAL_MODE)
        self.assertEqual(plan["kind"], "path_guidance")
        self.assertIn("powershell", plan["guided_reply"].casefold())

    def test_fast_path_diagnostic_normalization_routes_to_tool_use(self) -> None:
        agent = self._make_agent()
        plan = agent.classify_request("діагностикою ПК")
        reply = agent.handle_user_message("діагностикою ПК")

        self.assertEqual(plan["route"], ROUTE_TOOL_USE)
        self.assertEqual(plan["kind"], "summary_intent")
        self.assertIn("CPU", reply)
        self.assertIn("базову діагностику", reply)

    def test_recent_path_context_stays_in_guided_manual_mode(self) -> None:
        agent = self._make_agent()
        agent.handle_user_message(r"C:\clamav-1.5.1.win.x64")

        plan = agent.classify_request("там антивірус його треба запустити")

        self.assertEqual(plan["route"], ROUTE_GUIDED_MANUAL_MODE)
        self.assertIn("clamscan.exe", plan["guided_reply"])

    def test_open_ended_chat_request_can_use_existing_tool_loop(self) -> None:
        client = FakeClient()
        agent = self._make_agent(client=client)

        plan = agent.classify_request("що жере RAM")
        reply = agent.handle_user_message("що жере RAM")

        self.assertEqual(plan["route"], ROUTE_TOOL_USE)
        self.assertEqual(plan["kind"], "open_ended")
        self.assertIn("browser.exe", reply.lower())
        self.assertTrue(any(call["tool_mode"] for call in client.calls))

    def test_unavailable_ollama_returns_friendly_runtime_message(self) -> None:
        agent = self._make_agent(client=UnavailableClient())

        reply = agent.handle_user_message("що жере RAM")

        self.assertIn("Ollama", reply)
        self.assertIn("healthcheck", reply)
        self.assertIn("процеси", reply)

    def test_timeout_with_unreachable_ollama_returns_friendly_runtime_message(
        self,
    ) -> None:
        agent = self._make_agent(client=UnavailableTimeoutClient())

        reply = agent.handle_user_message("what uses RAM")

        self.assertIn("Ollama", reply)
        self.assertIn("healthcheck", reply)
        self.assertIn("show quarantine", reply)


if __name__ == "__main__":
    unittest.main()
