from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from config import settings
from core.agent import MedfarlAgent, ROUTE_TOOL_USE
from tools.tools import build_tools


class DummyScanner:
    def to_dict(self) -> dict:
        return {
            "cpu": {},
            "memory": {},
            "disks": [],
            "top_processes": [],
            "network": {},
        }


class DummyInspector:
    def summary_dict(self) -> dict:
        return {
            "pip_packages_count": 0,
            "system_packages_count": 0,
            "failed_services": [],
        }

    def pip_packages(self) -> list:
        return []

    def pip_outdated(self) -> list:
        return []

    def failed_services(self) -> list:
        return []


class UnsafeModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original = {
            "unsafe_full_access": settings.unsafe_full_access,
            "allowed_read_roots": list(settings.allowed_read_roots),
            "allowed_edit_roots": list(settings.allowed_edit_roots),
            "allowed_exec_roots": list(settings.allowed_exec_roots),
            "require_confirmation_for_exec": settings.require_confirmation_for_exec,
            "require_confirmation_for_delete": settings.require_confirmation_for_delete,
            "require_confirmation_for_package_changes": settings.require_confirmation_for_package_changes,
            "require_confirmation_for_file_edits": settings.require_confirmation_for_file_edits,
        }

    def tearDown(self) -> None:
        settings.unsafe_full_access = self.original["unsafe_full_access"]
        settings.allowed_read_roots = self.original["allowed_read_roots"]
        settings.allowed_edit_roots = self.original["allowed_edit_roots"]
        settings.allowed_exec_roots = self.original["allowed_exec_roots"]
        settings.require_confirmation_for_exec = self.original[
            "require_confirmation_for_exec"
        ]
        settings.require_confirmation_for_delete = self.original[
            "require_confirmation_for_delete"
        ]
        settings.require_confirmation_for_package_changes = self.original[
            "require_confirmation_for_package_changes"
        ]
        settings.require_confirmation_for_file_edits = self.original[
            "require_confirmation_for_file_edits"
        ]

    def _make_agent(self) -> MedfarlAgent:
        return MedfarlAgent(
            scanner=DummyScanner(), inspector=DummyInspector(), timeout=1
        )

    def test_enable_unsafe_full_access_expands_roots_and_disables_confirmations(
        self,
    ) -> None:
        settings.enable_unsafe_full_access()

        self.assertTrue(settings.unsafe_full_access)
        self.assertTrue(settings.allowed_read_roots)
        self.assertTrue(settings.allowed_edit_roots)
        self.assertTrue(settings.allowed_exec_roots)
        self.assertFalse(settings.require_confirmation_for_exec)
        self.assertFalse(settings.require_confirmation_for_delete)
        self.assertFalse(settings.require_confirmation_for_package_changes)
        self.assertFalse(settings.require_confirmation_for_file_edits)

    def test_build_tools_includes_shell_tool_in_unsafe_mode(self) -> None:
        settings.enable_unsafe_full_access()

        tool_names = {tool.name for tool in build_tools()}

        self.assertIn("run_shell_command", tool_names)
        self.assertIn("copy_path", tool_names)
        self.assertIn("move_path", tool_names)
        self.assertIn("remove_path", tool_names)

    def test_explicit_powershell_request_routes_to_tool_use(self) -> None:
        settings.enable_unsafe_full_access()
        agent = self._make_agent()

        plan = agent.classify_request("powershell Get-Date")

        self.assertEqual(plan["route"], ROUTE_TOOL_USE)
        self.assertEqual(plan["kind"], "maintenance_or_files")
        self.assertEqual(plan["payload"]["tool_name"], "run_shell_command")
        self.assertEqual(plan["payload"]["arguments"]["shell"], "powershell")

    def test_blocked_executable_path_becomes_tool_use_in_unsafe_mode(self) -> None:
        settings.enable_unsafe_full_access()
        agent = self._make_agent()

        plan = agent.classify_request(r"запусти C:\Windows\System32\cmd.exe")

        self.assertEqual(plan["route"], ROUTE_TOOL_USE)
        self.assertEqual(plan["kind"], "maintenance_or_files")
        self.assertEqual(plan["payload"]["tool_name"], "run_program")

    def test_copy_move_remove_and_mkdir_route_to_tools_in_unsafe_mode(self) -> None:
        settings.enable_unsafe_full_access()
        agent = self._make_agent()

        copy_plan = agent.classify_request(
            r'copy "C:\src.txt" "C:\dst.txt"'.replace('"', '"')
        )
        move_plan = agent.classify_request(
            r'move "C:\src.txt" "C:\dst.txt"'.replace('"', '"')
        )
        remove_plan = agent.classify_request(r'rm "C:\temp\old.txt"'.replace('"', '"'))
        mkdir_plan = agent.classify_request(r'mkdir "C:\temp\newdir"'.replace('"', '"'))

        self.assertEqual(copy_plan["payload"]["tool_name"], "copy_path")
        self.assertEqual(move_plan["payload"]["tool_name"], "move_path")
        self.assertEqual(remove_plan["payload"]["tool_name"], "remove_path")
        self.assertEqual(mkdir_plan["payload"]["tool_name"], "create_directory")

    def test_multiline_shell_mode_executes_buffer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "unsafe_multiline_test.txt"
            command = (
                "$path = '"
                + str(target).replace("\\", "\\\\")
                + "'\n"
                + "Set-Content -Path $path -Value 'unsafe multiline ok'"
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    "main.py",
                    "--unsafe-full-access",
                    "--skip-healthcheck",
                ],
                input=f"/shell powershell\n{command}\n/end\n/q\n",
                text=True,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
            )

            self.assertEqual(proc.returncode, 0)
            self.assertTrue(target.exists())
            self.assertIn("Unsafe full access mode", proc.stdout)


if __name__ == "__main__":
    unittest.main()
