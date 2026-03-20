from __future__ import annotations

import re
import subprocess
import sys
from typing import Any


PACKAGE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")


def _validate_package_name(name: str) -> str | None:
    normalized = name.strip()
    if not normalized:
        return "Package name cannot be empty"
    if not PACKAGE_NAME_PATTERN.fullmatch(normalized):
        return f"Unsupported package name format: {name}"
    return None


def _run_pip_command(argv: list[str], timeout: int) -> dict[str, Any]:
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return {"command": argv, "error": str(exc)}

    return {
        "command": argv,
        "returncode": result.returncode,
        "stdout": result.stdout[-8000:],
        "stderr": result.stderr[-5000:],
    }


def pip_install_package(
    name: str,
    version: str | None = None,
    upgrade: bool = False,
) -> dict[str, Any]:
    validation_error = _validate_package_name(name)
    if validation_error:
        return {"error": validation_error}

    if version:
        package_spec = f"{name}=={version}"
    else:
        package_spec = name

    argv = [sys.executable, "-m", "pip", "install", package_spec]
    if upgrade:
        argv.append("--upgrade")

    return _run_pip_command(argv, timeout=420)


def pip_uninstall_package(name: str) -> dict[str, Any]:
    validation_error = _validate_package_name(name)
    if validation_error:
        return {"error": validation_error}

    argv = [sys.executable, "-m", "pip", "uninstall", "-y", name]
    return _run_pip_command(argv, timeout=240)


def pip_check() -> dict[str, Any]:
    argv = [sys.executable, "-m", "pip", "check"]
    return _run_pip_command(argv, timeout=90)


def pip_freeze() -> dict[str, Any]:
    argv = [sys.executable, "-m", "pip", "freeze"]
    return _run_pip_command(argv, timeout=90)
