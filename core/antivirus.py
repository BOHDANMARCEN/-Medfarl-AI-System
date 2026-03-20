from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
from typing import Any

from config import settings


SUPPORTED_PROVIDERS = ("windows_defender", "clamav")
DEFENDER_SERVICE_ERROR_CODE = "0x800106ba"


def detect_antivirus() -> dict[str, Any]:
    defender = _detect_windows_defender()
    clamav = _detect_clamav()

    providers = []
    if defender.get("available"):
        providers.append("windows_defender")
    if clamav.get("available"):
        providers.append("clamav")

    default_provider = None
    if "windows_defender" in providers:
        default_provider = "windows_defender"
    elif "clamav" in providers:
        default_provider = "clamav"

    return {
        "platform": platform.system(),
        "available": bool(providers),
        "providers": providers,
        "default_provider": default_provider,
        "hints": _build_detection_hints(defender, clamav),
        "details": {
            "windows_defender": defender,
            "clamav": clamav,
        },
    }


def update_antivirus_definitions(provider: str | None = None) -> dict[str, Any]:
    provider_name, error = _select_provider(provider)
    if error:
        return {"error": error}
    assert provider_name is not None

    if provider_name == "windows_defender":
        return _update_windows_defender_definitions()
    return _update_clamav_definitions()


def run_antivirus_quick_scan(provider: str | None = None) -> dict[str, Any]:
    provider_name, error = _select_provider(provider)
    if error:
        return {"error": error}
    assert provider_name is not None

    if provider_name == "windows_defender":
        return _run_windows_defender_quick_scan()
    return _run_clamav_quick_scan()


def run_antivirus_custom_scan(path: str, provider: str | None = None) -> dict[str, Any]:
    scan_path = _resolve_scan_path(path)
    if not scan_path.exists():
        return {"error": f"Scan path does not exist: {scan_path}"}

    provider_name, error = _select_provider(provider)
    if error:
        return {"error": error, "path": str(scan_path)}
    assert provider_name is not None

    if provider_name == "windows_defender":
        return _run_windows_defender_custom_scan(scan_path)
    return _run_clamav_custom_scan(scan_path)


def list_antivirus_threats(
    limit: int = 20, provider: str | None = None
) -> dict[str, Any]:
    limit = max(1, min(int(limit), 100))
    provider_name, error = _select_provider(provider)
    if error:
        return {"error": error}
    assert provider_name is not None

    if provider_name == "windows_defender":
        return _list_windows_defender_threats(limit)
    return _list_clamav_threats(limit)


def _select_provider(requested: str | None) -> tuple[str | None, str | None]:
    detection = detect_antivirus()
    details = detection.get("details", {})

    if requested:
        normalized = requested.strip().casefold()
        if normalized not in SUPPORTED_PROVIDERS:
            return None, (
                f"Unsupported provider '{requested}'. "
                f"Supported providers: {', '.join(SUPPORTED_PROVIDERS)}"
            )
        if not details.get(normalized, {}).get("available", False):
            return (
                None,
                f"Requested provider '{normalized}' is not available on this machine.",
            )
        return normalized, None

    default_provider = detection.get("default_provider")
    if default_provider:
        return default_provider, None

    return (
        None,
        "No supported antivirus provider detected (Windows Defender or ClamAV).",
    )


def _resolve_scan_path(path: str) -> Path:
    candidate = Path(os.path.expandvars(path)).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    return candidate.resolve()


def _run_powershell_json(
    script: str,
    *,
    timeout: int = 30,
    env_overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    powershell = _powershell_executable()
    if not powershell:
        return {"ok": False, "error": "PowerShell is not available."}

    prelude = (
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        "$OutputEncoding=[System.Text.Encoding]::UTF8; "
        "$ErrorActionPreference='Stop'; "
    )
    final_script = prelude + script

    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)

    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-Command", final_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            env=env,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    if result.returncode != 0:
        error_text = (
            result.stderr.strip()
            or result.stdout.strip()
            or "PowerShell command failed"
        )
        return {
            "ok": False,
            "error": _simplify_powershell_error(error_text),
            "raw_error": error_text[-4000:],
            "error_code": _extract_error_code(error_text),
            "returncode": result.returncode,
        }

    payload = result.stdout.strip()
    if not payload:
        return {"ok": True, "data": None}

    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError:
        return {
            "ok": False,
            "error": "PowerShell returned non-JSON output",
            "raw": payload[-4000:],
        }
    return {"ok": True, "data": parsed}


def _powershell_executable() -> str | None:
    return (
        shutil.which("powershell")
        or shutil.which("powershell.exe")
        or shutil.which("pwsh")
    )


def _detect_windows_defender() -> dict[str, Any]:
    if platform.system() != "Windows":
        return {
            "available": False,
            "reason": "Windows Defender adapter is available on Windows only.",
        }

    script = (
        "$status = Get-MpComputerStatus | "
        "Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,"
        "AntivirusSignatureVersion,AntispywareSignatureVersion,NISSignatureVersion; "
        "$status | ConvertTo-Json -Compress"
    )
    response = _run_powershell_json(script, timeout=20)
    if not response.get("ok"):
        issue = _friendly_windows_defender_issue(
            response.get("error") or "Windows Defender status query failed.",
            error_code=response.get("error_code"),
        )
        return {
            "available": False,
            "reason": issue["reason"],
            "error_code": issue.get("error_code"),
            "manual_checks": issue["manual_checks"],
        }

    data = response.get("data") or {}
    return {
        "available": True,
        "provider": "windows_defender",
        "status": data,
    }


def _update_windows_defender_definitions() -> dict[str, Any]:
    script = (
        "Update-MpSignature | Out-Null; "
        "$status = Get-MpComputerStatus | "
        "Select-Object AntivirusSignatureVersion,AntispywareSignatureVersion,NISSignatureVersion; "
        "$status | ConvertTo-Json -Compress"
    )
    response = _run_powershell_json(script, timeout=600)
    if not response.get("ok"):
        issue = _friendly_windows_defender_issue(
            response.get("error") or "Windows Defender definitions update failed.",
            error_code=response.get("error_code"),
        )
        return {
            "provider": "windows_defender",
            "updated": False,
            "error": issue["reason"],
            "error_code": issue.get("error_code"),
            "manual_checks": issue["manual_checks"],
        }

    return {
        "provider": "windows_defender",
        "updated": True,
        "signatures": response.get("data") or {},
    }


def _run_windows_defender_quick_scan() -> dict[str, Any]:
    script = (
        "Start-MpScan -ScanType QuickScan; "
        "$threats = @(Get-MpThreatDetection | "
        "Select-Object -First 20 ThreatID,ThreatName,ActionSuccess,Resources,InitialDetectionTime,LastThreatStatusChangeTime); "
        "$result = [pscustomobject]@{"
        "scan_type='quick'; "
        "threats_count=@($threats).Count; "
        "threats=$threats"
        "}; "
        "$result | ConvertTo-Json -Depth 5 -Compress"
    )
    response = _run_powershell_json(script, timeout=1800)
    if not response.get("ok"):
        issue = _friendly_windows_defender_issue(
            response.get("error") or "Windows Defender quick scan failed.",
            error_code=response.get("error_code"),
        )
        return {
            "provider": "windows_defender",
            "scan_type": "quick",
            "success": False,
            "error": issue["reason"],
            "error_code": issue.get("error_code"),
            "manual_checks": issue["manual_checks"],
        }

    data = response.get("data") or {}
    return {
        "provider": "windows_defender",
        "scan_type": "quick",
        "success": True,
        "threats_count": int(data.get("threats_count", 0)),
        "threats": _normalize_to_list(data.get("threats")),
    }


def _run_windows_defender_custom_scan(scan_path: Path) -> dict[str, Any]:
    script = (
        "$scanPath = $env:MEDFARL_SCAN_PATH; "
        "Start-MpScan -ScanType CustomScan -ScanPath $scanPath; "
        "$threats = @(Get-MpThreatDetection | "
        "Select-Object -First 20 ThreatID,ThreatName,ActionSuccess,Resources,InitialDetectionTime,LastThreatStatusChangeTime); "
        "$result = [pscustomobject]@{"
        "scan_type='custom'; "
        "scan_path=$scanPath; "
        "threats_count=@($threats).Count; "
        "threats=$threats"
        "}; "
        "$result | ConvertTo-Json -Depth 5 -Compress"
    )
    response = _run_powershell_json(
        script,
        timeout=3600,
        env_overrides={"MEDFARL_SCAN_PATH": str(scan_path)},
    )
    if not response.get("ok"):
        issue = _friendly_windows_defender_issue(
            response.get("error") or "Windows Defender custom scan failed.",
            error_code=response.get("error_code"),
        )
        return {
            "provider": "windows_defender",
            "scan_type": "custom",
            "scan_path": str(scan_path),
            "success": False,
            "error": issue["reason"],
            "error_code": issue.get("error_code"),
            "manual_checks": issue["manual_checks"],
        }

    data = response.get("data") or {}
    return {
        "provider": "windows_defender",
        "scan_type": "custom",
        "scan_path": str(scan_path),
        "success": True,
        "threats_count": int(data.get("threats_count", 0)),
        "threats": _normalize_to_list(data.get("threats")),
    }


def _list_windows_defender_threats(limit: int) -> dict[str, Any]:
    script = (
        "$items = Get-MpThreatDetection | "
        "Sort-Object InitialDetectionTime -Descending | "
        f"Select-Object -First {limit} ThreatID,ThreatName,ActionSuccess,Resources,InitialDetectionTime,LastThreatStatusChangeTime; "
        "$items | ConvertTo-Json -Depth 5 -Compress"
    )
    response = _run_powershell_json(script, timeout=60)
    if not response.get("ok"):
        issue = _friendly_windows_defender_issue(
            response.get("error") or "Failed to read Windows Defender threats.",
            error_code=response.get("error_code"),
        )
        return {
            "provider": "windows_defender",
            "count": 0,
            "threats": [],
            "error": issue["reason"],
            "error_code": issue.get("error_code"),
            "manual_checks": issue["manual_checks"],
        }

    threats = _normalize_to_list(response.get("data"))
    return {
        "provider": "windows_defender",
        "count": len(threats),
        "threats": threats,
    }


def _detect_clamav() -> dict[str, Any]:
    binaries = _find_clamav_binaries()
    clamscan = binaries.get("clamscan")
    freshclam = binaries.get("freshclam")
    hints = _clamav_binary_hints(binaries)
    if not clamscan:
        return {
            "available": False,
            "reason": "clamscan executable was not found.",
            "binaries": binaries,
            "guided_hints": hints,
        }

    version_info = _run_command([clamscan, "--version"], timeout=15)
    version_line = ""
    if not version_info.get("error"):
        version_line = (version_info.get("stdout") or "").strip().splitlines()[0:1]
        version_line = version_line[0] if version_line else ""

    return {
        "available": True,
        "provider": "clamav",
        "binaries": binaries,
        "version": version_line,
        "guided_hints": hints,
        "definitions_updatable": bool(freshclam),
    }


def _update_clamav_definitions() -> dict[str, Any]:
    binaries = _find_clamav_binaries()
    freshclam = binaries.get("freshclam")
    if not freshclam:
        return {
            "provider": "clamav",
            "updated": False,
            "error": "freshclam executable was not found.",
            "binaries": binaries,
        }

    result = _run_command([freshclam, "--stdout"], timeout=900)
    success = result.get("returncode") == 0
    return {
        "provider": "clamav",
        "updated": success,
        "returncode": result.get("returncode"),
        "stdout": (result.get("stdout") or "")[-4000:],
        "stderr": (result.get("stderr") or "")[-2000:],
        "error": result.get("error"),
    }


def _run_clamav_quick_scan() -> dict[str, Any]:
    targets = _quick_scan_targets()
    if not targets:
        return {
            "provider": "clamav",
            "scan_type": "quick",
            "success": False,
            "error": "No quick-scan targets were found.",
        }
    return _run_clamav_scan_targets(targets, scan_type="quick")


def _run_clamav_custom_scan(scan_path: Path) -> dict[str, Any]:
    return _run_clamav_scan_targets([scan_path], scan_type="custom")


def _run_clamav_scan_targets(targets: list[Path], *, scan_type: str) -> dict[str, Any]:
    binaries = _find_clamav_binaries()
    clamscan = binaries.get("clamscan")
    if not clamscan:
        return {
            "provider": "clamav",
            "scan_type": scan_type,
            "success": False,
            "error": "clamscan executable was not found.",
            "binaries": binaries,
        }

    per_target = []
    infected_total = 0
    had_errors = False
    for target in targets:
        args = [clamscan, "--infected"]
        if target.is_dir():
            args.extend(["--recursive", str(target)])
        else:
            args.append(str(target))

        result = _run_command(args, timeout=3600)
        summary = _parse_clamscan_summary(result.get("stdout") or "")
        infected = int(summary.get("infected_files", 0))
        infected_total += infected
        returncode = result.get("returncode")
        target_error = result.get("error")

        status = "clean"
        if target_error:
            status = "error"
            had_errors = True
        elif returncode == 1 or infected > 0:
            status = "threats_detected"
        elif returncode not in (0, 1):
            status = "error"
            had_errors = True

        per_target.append(
            {
                "path": str(target),
                "returncode": returncode,
                "status": status,
                "infected_files": infected,
                "summary": summary,
                "stdout": (result.get("stdout") or "")[-2500:],
                "stderr": (result.get("stderr") or "")[-1500:],
                "error": target_error,
            }
        )

    return {
        "provider": "clamav",
        "scan_type": scan_type,
        "success": not had_errors,
        "infected_files_total": infected_total,
        "targets": per_target,
    }


def _list_clamav_threats(limit: int) -> dict[str, Any]:
    entries = []
    for log_path in _clamav_log_candidates():
        if len(entries) >= limit:
            break
        lines = _read_last_lines(log_path, max_lines=800)
        for line in reversed(lines):
            parsed = _parse_clamav_found_line(line)
            if not parsed:
                continue
            entries.append(
                {
                    "source_log": str(log_path),
                    "target": parsed["target"],
                    "threat_name": parsed["threat_name"],
                    "raw": line[:220],
                }
            )
            if len(entries) >= limit:
                break

    return {
        "provider": "clamav",
        "count": len(entries),
        "threats": entries,
        "note": "Entries are parsed from available ClamAV logs.",
    }


def _quick_scan_targets() -> list[Path]:
    candidates: list[Path] = []
    home = Path.home()

    if platform.system() == "Windows":
        candidates.extend(
            [
                home / "Downloads",
                home / "Desktop",
                home / "Documents",
                Path(tempfile.gettempdir()),
            ]
        )
    else:
        candidates.extend(
            [
                home / "Downloads",
                home / "Desktop",
                Path(tempfile.gettempdir()),
            ]
        )

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        key = str(resolved).casefold()
        if key in seen or not resolved.exists():
            continue
        seen.add(key)
        unique.append(resolved)
    return unique[:5]


def _find_clamav_binaries() -> dict[str, str | None]:
    directories = _clamav_candidate_directories()
    return {
        "clamscan": _locate_binary(["clamscan", "clamscan.exe"], directories),
        "freshclam": _locate_binary(["freshclam", "freshclam.exe"], directories),
        "clamdscan": _locate_binary(
            ["clamdscan", "clamdscan.exe", "clamd.exe"], directories
        ),
    }


def _clamav_candidate_directories() -> list[Path]:
    candidates = []
    for env_name in ("CLAMAV_HOME", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
        raw = os.getenv(env_name)
        if not raw:
            continue
        base = Path(raw)
        if env_name in {"ProgramFiles", "ProgramFiles(x86)"}:
            candidates.append(base / "ClamAV")
        else:
            candidates.append(base)
            candidates.append(base / "ClamAV")

    candidates.append(Path.cwd())
    for root in settings.allowed_exec_roots:
        candidates.append(Path(root))

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        key = str(resolved).casefold()
        if key in seen:
            continue
        seen.add(key)
        unique.append(resolved)
    return unique


def _locate_binary(names: list[str], directories: list[Path]) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return str(Path(found).resolve())

    for directory in directories:
        for name in names:
            direct = directory / name
            if direct.is_file():
                return str(direct.resolve())

            in_bin = directory / "bin" / name
            if in_bin.is_file():
                return str(in_bin.resolve())
    return None


def _clamav_log_candidates() -> list[Path]:
    candidates = [
        Path("/var/log/clamav/clamav.log"),
        Path("/var/log/clamav/clamd.log"),
    ]

    program_data = os.getenv("ProgramData")
    if program_data:
        base = Path(program_data) / "ClamAV"
        candidates.extend(
            [
                base / "clamav.log",
                base / "clamd.log",
            ]
        )

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        key = str(resolved).casefold()
        if key in seen or not resolved.is_file():
            continue
        seen.add(key)
        unique.append(resolved)
    return unique


def _read_last_lines(path: Path, max_lines: int) -> list[str]:
    lines: deque[str] = deque(maxlen=max_lines)
    try:
        with path.open("r", encoding="utf-8", errors="replace") as file:
            for line in file:
                lines.append(line.strip())
    except OSError:
        return []
    return [line for line in lines if line]


def _parse_clamav_found_line(line: str) -> dict[str, str] | None:
    if not line.endswith(" FOUND"):
        return None

    payload = line[:-6]
    if ": " not in payload:
        return None
    target, threat_name = payload.rsplit(": ", 1)
    threat_name = threat_name.strip()
    target = target.strip()
    if not target or not threat_name:
        return None
    return {
        "target": target,
        "threat_name": threat_name,
    }


def _parse_clamscan_summary(output: str) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    patterns = {
        "known_viruses": r"Known viruses:\s*(\d+)",
        "engine_version": r"Engine version:\s*([^\n]+)",
        "scanned_directories": r"Scanned directories:\s*(\d+)",
        "scanned_files": r"Scanned files:\s*(\d+)",
        "infected_files": r"Infected files:\s*(\d+)",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output)
        if not match:
            continue
        value = match.group(1).strip()
        if value.isdigit():
            summary[key] = int(value)
        else:
            summary[key] = value

    found_entries = []
    for line in output.splitlines():
        parsed = _parse_clamav_found_line(line.strip())
        if parsed:
            found_entries.append(parsed)
    if found_entries:
        summary["threat_hits"] = found_entries[:30]

    return summary


def _normalize_to_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _extract_error_code(text: str) -> str | None:
    code_match = re.search(r"0x[0-9a-fA-F]{8}", text)
    if code_match:
        return code_match.group(0).lower()

    fallback = re.search(r"\b800106ba\b", text, flags=re.IGNORECASE)
    if fallback:
        return DEFENDER_SERVICE_ERROR_CODE
    return None


def _simplify_powershell_error(text: str) -> str:
    first_line = text.strip().splitlines()[0:1]
    if first_line:
        line = first_line[0].strip()
        if line:
            return line
    compact = " ".join(text.split())
    return compact[:220] if compact else "PowerShell command failed"


def _friendly_windows_defender_issue(
    error_text: str, *, error_code: str | None = None
) -> dict[str, Any]:
    code = error_code or _extract_error_code(error_text or "")
    if code == DEFENDER_SERVICE_ERROR_CODE:
        return {
            "reason": (
                "Windows Defender зараз недоступний: служба Microsoft Defender Antivirus "
                "вимкнена або не запущена (0x800106ba)."
            ),
            "error_code": DEFENDER_SERVICE_ERROR_CODE,
            "manual_checks": [
                "Відкрий Windows Security -> Virus & threat protection і перевір, чи увімкнений Defender.",
                "У services.msc перевір службу `WinDefend` (стан Running).",
                "Якщо встановлений інший антивірус, Defender може бути автоматично вимкнений.",
            ],
        }

    return {
        "reason": error_text or "Не вдалося виконати операцію Windows Defender.",
        "error_code": code,
        "manual_checks": [
            "Перевір, що відкривається Windows Security без помилок.",
            "Перевір статус служб Defender у services.msc.",
            "Запусти `Get-MpComputerStatus` у PowerShell для ручної перевірки.",
        ],
    }


def _clamav_binary_hints(binaries: dict[str, str | None]) -> list[str]:
    clamscan = binaries.get("clamscan")
    freshclam = binaries.get("freshclam")

    hints = [
        (
            f"clamscan.exe: знайдено ({clamscan})"
            if clamscan
            else "clamscan.exe: не знайдено (без нього сканування ClamAV недоступне)"
        ),
        (
            f"freshclam.exe: знайдено ({freshclam})"
            if freshclam
            else "freshclam.exe: не знайдено (оновлення баз ClamAV недоступне)"
        ),
    ]
    return hints


def _build_detection_hints(
    defender: dict[str, Any], clamav: dict[str, Any]
) -> list[str]:
    hints: list[str] = []
    if defender.get("available"):
        hints.append("Windows Defender: доступний і готовий до сканування.")
    else:
        reason = defender.get("reason") or "недоступний"
        hints.append(f"Windows Defender: {reason}")

    clamav_hints = clamav.get("guided_hints") or []
    if clamav_hints:
        hints.extend(clamav_hints)
    elif clamav.get("available"):
        hints.append("ClamAV: доступний.")
    else:
        hints.append("ClamAV: недоступний.")
    return hints


def _run_command(argv: list[str], *, timeout: int) -> dict[str, Any]:
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return {"command": argv, "error": str(exc)}

    return {
        "command": argv,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
