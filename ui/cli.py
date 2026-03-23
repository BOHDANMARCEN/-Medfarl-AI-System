from __future__ import annotations

import os
import sys


BANNER = r"""
  __  __          _  __           _
 |  \/  | ___  __| |/ _| __ _ _ _| |
 | |\/| |/ _ \/ _` |  _|/ _` | '_| |
 | |  | |  __/ (_| | | | (_| | | | |
 |_|  |_|\___|\__,_|_|  \__,_|_| |_|

            AI System - PC Doctor v0.1
"""


class C:
    ENABLED = (
        os.name != "nt" or bool(os.getenv("WT_SESSION")) or os.getenv("TERM") == "xterm"
    )
    RESET = "\033[0m" if ENABLED else ""
    BOLD = "\033[1m" if ENABLED else ""
    CYAN = "\033[96m" if ENABLED else ""
    GREEN = "\033[92m" if ENABLED else ""
    YELLOW = "\033[93m" if ENABLED else ""
    RED = "\033[91m" if ENABLED else ""
    DIM = "\033[2m" if ENABLED else ""
    MAGENTA = "\033[95m" if ENABLED else ""


def configure_console() -> None:
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass

    for stream_name in ("stdin", "stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


class CLI:
    def banner(self) -> None:
        print(C.CYAN + BANNER + C.RESET)
        print(
            C.DIM
            + "  Chat-first local diagnostics with guarded tool access. All data stays on your machine."
            + C.RESET
        )
        print(
            C.DIM
            + "  Ask naturally: hello, why is my PC slow, check the network, show heavy processes."
            + C.RESET
        )
        print()

    def prompt(self) -> str:
        try:
            return input(C.CYAN + "\n  medfarl> " + C.RESET).strip()
        except (KeyboardInterrupt, EOFError):
            return "exit"

    def print_response(self, text: str) -> None:
        print(f"\n{text}\n")

    def print_error(self, message: str) -> None:
        print(C.RED + f"\n[error] {message}\n" + C.RESET)


def print_banner() -> None:
    CLI().banner()


def prompt_user() -> str:
    return CLI().prompt()
