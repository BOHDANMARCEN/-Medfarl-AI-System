from __future__ import annotations

import json
import platform
import re
import uuid
from typing import Any, Dict, List, Optional

from config import settings
from core.action_guard import is_under_roots, resolve_path
from core.antivirus import (
    detect_antivirus,
    list_antivirus_threats,
    run_antivirus_custom_scan,
    run_antivirus_quick_scan,
    update_antivirus_definitions,
)
from core.approval import ApprovalState, PendingAction, PendingActionExistsError
from core.audit import log_action_event, read_action_history, read_last_action
from core.file_ops import find_junk_files, show_quarantine
from core.lib_inspector import LibInspector
from core.llm_client import LLMClient
from core.system_scanner import SystemScanner
from tools.tools import (
    build_tools,
    execute_tool,
    get_disk_summary,
    get_network_summary,
    get_recent_errors,
    get_top_processes,
    tool_schemas,
)


SYSTEM_PROMPT = """\
You are Medfarl AI System, a local-first PC diagnostics assistant with controlled tool access.

Core interaction model:
- Treat every user message as a conversational request first, not as a fragile command.
- Reply in the user's language only. Match Ukrainian, Russian, or English based on the latest user message.
- For a simple conversational turn that does not need tools, answer directly and naturally.
- If the request is ambiguous, ask exactly one short clarifying question.
- If tools are needed, decide that explicitly and use the available tool loop.
- If a request is blocked by permissions, unsupported execution, unsupported platform behavior, or missing capabilities, switch to guided manual mode instead of blunt refusal.

Tool rules:
- Never invent tool results.
- Use only registered tools.
- Always use real data before drawing conclusions.
- Call get_system_snapshot before diagnosing an unknown system issue when the current context is not enough.
- Prefer specialized tools over generic shell execution.

Guided manual mode rules:
- Explain what you can confirm.
- Explain what you cannot do directly.
- Give the safest next concrete manual step.
- Optionally end with one short follow-up question.
- Do not hallucinate unsupported commands, services, or executable names.
- For Windows software, mention `.exe` names only as plausible candidates unless confirmed by actual inspection.

Path handling rules:
- If the user sends a filesystem path, treat it as likely relevant context.
- If the path is inside allowed roots and inspection would help, use the existing file tools.
- If the path is outside allowed roots, explain the boundary briefly and offer a guided/manual path forward.
- If the user seems to want to run software from a folder, focus on practical next steps rather than access-policy jargon.

Operational safety rules:
- Read-only diagnostics may run through safe tools.
- Any mutating action must go through approval mode first.
- Never execute programs, edit files, or install/remove packages without explicit confirmation.
- Never claim you ran something unless the tool result proves it.

Formatting rules:
- Keep replies concise by default.
- Use plain text only.
- For concise diagnostic summaries, prefer 4-6 bullets in this order when possible: CPU, RAM, Disk, Processes, Services, Network.
"""

PLANNER_PROMPT = """\
You are the conversational planner for Medfarl AI System.

Decide the best next route for the user's latest message.
Return JSON only with this schema:
{
  "route": "DIRECT_RESPONSE" | "CLARIFICATION" | "TOOL_USE" | "GUIDED_MANUAL_MODE",
  "reply": "short reply or question in the user's language when route is DIRECT_RESPONSE, CLARIFICATION, or GUIDED_MANUAL_MODE",
  "normalized_user_request": "optional rewritten request for TOOL_USE, same language as the user"
}

Rules:
- The assistant is chat-first.
- Ask one concise clarifying question if the request is ambiguous.
- Choose TOOL_USE when inspecting the real machine state or allowed files would materially help.
- Choose GUIDED_MANUAL_MODE when the user wants something blocked by permissions, unsupported execution, unsupported platform behavior, or unavailable tools.
- Choose DIRECT_RESPONSE for greetings, simple help, or requests that can be answered without tools.
- Never invent tool results or claim execution already happened.
- Keep reply short and practical.
"""

DIRECT_RESPONSE_PROMPT = """\
You are Medfarl AI System answering a chat-first turn without tools.

Rules:
- Reply in the user's language only.
- Answer naturally and concisely.
- Do not mention tools unless they are relevant as a next step.
- If you lack information and the turn should really use tools, ask one short clarifying question instead of guessing.
"""

GUIDED_MANUAL_PROMPT = """\
You are Medfarl AI System in guided manual mode.

Rules:
- Reply in the user's language only.
- Explain what you can confirm and what you cannot do directly.
- Provide the safest next concrete manual step.
- If useful, ask one short follow-up question.
- Do not invent commands, services, files, or execution results.
"""

UNSAFE_FULL_ACCESS_PROMPT = """\
Unsafe full access mode is enabled.

- Full local filesystem access is available through the registered file tools.
- Local shell access is available through registered shell tools.
- Program execution is available without approval gating.
- Do not pretend a restriction exists if unsafe mode disables it.
- Still prefer real tool output over guessing.
"""


GREETING_PATTERN = re.compile(
    r"^\s*(hi|hello|hey|yo|hola|привіт|привет|вітаю|доброго дня|добрий день|добрий вечір)\s*[!.?]*\s*$",
    re.IGNORECASE,
)

DIAGNOSTIC_INTENT = "Зроби загальну діагностику ПК"
PROCESS_INTENT = "Покажи найважчі процеси"
DISK_INTENT = "Перевір диски і вільне місце"
NETWORK_INTENT = "Перевір стан мережі"
LOGS_INTENT = "Покажи помилки в системних логах"
HELP_INTENT = "Покажи можливості Medfarl"

ROUTE_DIRECT_RESPONSE = "DIRECT_RESPONSE"
ROUTE_CLARIFICATION = "CLARIFICATION"
ROUTE_TOOL_USE = "TOOL_USE"
ROUTE_GUIDED_MANUAL_MODE = "GUIDED_MANUAL_MODE"

LANG_UK = "uk"
LANG_RU = "ru"
LANG_EN = "en"

INTENT_NORMALIZATION: dict[str, str] = {
    "діагностика": DIAGNOSTIC_INTENT,
    "діагностика пк": DIAGNOSTIC_INTENT,
    "діагностикою пк": DIAGNOSTIC_INTENT,
    "процеси": PROCESS_INTENT,
    "процес": PROCESS_INTENT,
    "мережа": NETWORK_INTENT,
    "диск": DISK_INTENT,
    "диски": DISK_INTENT,
    "лог": LOGS_INTENT,
    "логи": LOGS_INTENT,
    "що ти ще можеш": HELP_INTENT,
    "а що ти ще можеш": HELP_INTENT,
    "що ти можеш": HELP_INTENT,
    "що ти вмієш": HELP_INTENT,
    "що вмієш": HELP_INTENT,
    "що ще можеш": HELP_INTENT,
    "що ще вмієш": HELP_INTENT,
    "можливості": HELP_INTENT,
    "допомога": HELP_INTENT,
    "help": HELP_INTENT,
    "команди": HELP_INTENT,
    "commands": HELP_INTENT,
}

HELP_PATTERNS = [
    re.compile(r"(?i)^а?\s*що\s+ти\s+ще\s+можеш\??$"),
    re.compile(r"(?i)^що\s+ти\s+можеш\??$"),
    re.compile(r"(?i)^що\s+вмієш\??$"),
    re.compile(r"(?i)^help$"),
    re.compile(r"(?i)^допомога$"),
    re.compile(r"(?i)^команди$"),
]

HELP_MENU_CHOICES = {"1", "2", "3"}

SHORT_ACTION_VERBS = {
    "перевір",
    "покажи",
    "зроби",
    "знайди",
    "проаналізуй",
    "діагностуй",
    "check",
    "show",
    "find",
    "analyze",
    "diagnose",
    "проверь",
    "покажи",
    "сделай",
    "створи",
    "создай",
    "create",
    "запусти",
    "запустити",
    "run",
    "launch",
    "install",
    "встанови",
    "установи",
    "видали",
    "удали",
    "delete",
    "редагуй",
    "edit",
    "зміни",
    "измени",
    "додай",
    "add",
}

WINDOWS_PATH_PATTERN = re.compile(r"(?i)\b[A-Z]:\\[^\n\r\t\"<>|?*]*")

SOFTWARE_CONTEXT_WORDS = {
    "антивірус",
    "antivirus",
    "запустити",
    "запусти",
    "запуск",
    "run",
    "start",
    "exe",
    "програма",
    "program",
}

OPERATIONAL_REQUEST_WORDS = {
    "треба",
    "запустити",
    "запусти",
    "run",
    "start",
    "launch",
    "перевірити",
    "scan",
    "антивірус",
}

MUTATING_TOOLS = {
    "copy_path",
    "move_path",
    "remove_path",
    "run_program",
    "run_shell_command",
    "run_antivirus_quick_scan",
    "update_antivirus_definitions",
    "run_antivirus_custom_scan",
    "pip_install_package",
    "pip_uninstall_package",
    "move_junk_to_quarantine",
    "restore_from_quarantine",
    "delete_junk_files",
    "create_directory",
    "create_text_file",
    "write_text_file",
    "append_text_file",
    "edit_text_file",
}

APPROVE_WORDS = {"approve", "yes", "confirm", "ok", "так", "підтверджую"}
CANCEL_WORDS = {"cancel", "no", "stop", "ні", "скасуй"}
PENDING_WORDS = {"pending", "status", "очікує", "очікує?", "статус", "pending action"}

HISTORY_WORDS = {
    "history actions",
    "history",
    "історія",
    "історія дій",
    "actions history",
}

LAST_ACTION_WORDS = {
    "last action",
    "last",
    "остання дія",
    "остання",
    "last event",
}

PIP_INSTALL_PATTERNS = [
    re.compile(
        r"(?i)\bpip\s+install\s+([A-Za-z0-9_.-]+)(?:==([A-Za-z0-9_.-]+))?(?:\s+--upgrade)?"
    ),
    re.compile(
        r"(?i)\b(?:встанови|встановити|install|установи|установить)\s+(?:pip\s+package\s+|package\s+|пакет\s+)?([A-Za-z0-9_.-]+)(?:==([A-Za-z0-9_.-]+))?"
    ),
]

CREATE_FILE_PATTERNS = [
    re.compile(r"(?i)\b(?:створи|створити|create)\s+(?:text\s+)?(?:file|файл)\s+(.+)"),
]

RUN_PROGRAM_PATTERNS = [
    re.compile(r"(?i)\b(?:запусти|запустити|run|launch|start)\b"),
]

FIND_JUNK_PATTERNS = [
    re.compile(
        r"(?i)\b(?:знайди|покажи|перевір|find|show|check)\b.*\b(?:сміт|junk|cache|tmp)"
    ),
    re.compile(r"(?i)\b(?:junk|temp|cache)\b.*\b(?:files|cleanup|preview)"),
]

PIP_UNINSTALL_PATTERNS = [
    re.compile(r"(?i)\bpip\s+uninstall\s+([A-Za-z0-9_.-]+)"),
    re.compile(
        r"(?i)\b(?:видали|видалити|uninstall|remove|удали|удалить)\s+(?:pip\s+package\s+|package\s+|пакет\s+)?([A-Za-z0-9_.-]+)"
    ),
]

APPEND_FILE_PATTERNS = [
    re.compile(
        r"(?i)\b(?:додай|додати|append)\s+(?:текст\s+)?(?:у|в|to)\s+(?:файл|file)\s+(.+)"
    ),
]

REPLACE_FILE_PATTERNS = [
    re.compile(
        r"(?i)\b(?:заміни|заміни\s+в|replace)\s+(?:в\s+файлі|in\s+file)?\s*(?P<path>[^\s]+)\s+(?:['\"](?P<find1>[^'\"]+)['\"]|`(?P<find2>[^`]+)`|(?P<find3>\S+))\s+(?:на|with)\s+(?:['\"](?P<rep1>[^'\"]+)['\"]|`(?P<rep2>[^`]+)`|(?P<rep3>\S+))"
    ),
]

MOVE_JUNK_PATTERNS = [
    re.compile(
        r"(?i)\b(?:перемісти|move)\b.*\b(?:сміт|junk)\b.*\b(?:quarantine|карантин)"
    ),
]

DELETE_JUNK_PATTERNS = [
    re.compile(r"(?i)\b(?:видали|delete|remove)\b.*\b(?:сміт|junk)\b"),
]

SHOW_QUARANTINE_PATTERNS = [
    re.compile(r"(?i)\b(?:show|list)\b.*\bquarantine\b"),
    re.compile(
        r"(?i)\b(?:покажи|що\s+в|покажи\s+що\s+в)\b.*\b(?:quarantine|карантин\w*)\b"
    ),
]

RESTORE_QUARANTINE_PATTERNS = [
    re.compile(r"(?i)\brestore\b.*\bquarantine\b"),
    re.compile(r"(?i)\b(?:віднови|поверни)\b.*\b(?:quarantine|карантин\w*)\b"),
]

QUARANTINE_ENTRY_ID_PATTERN = re.compile(r"\bqk-[0-9a-f]{8}\b", re.IGNORECASE)

ANTIVIRUS_QUICK_SCAN_PATTERNS = [
    re.compile(
        r"(?i)\b(?:перевір|проскануй|scan|check)\b.*\b(?:антивірус|antivirus|defender|clamav)"
    ),
]

ANTIVIRUS_UPDATE_PATTERNS = [
    re.compile(
        r"(?i)\b(?:онови|update)\b.*\b(?:бази|definitions|signature|антивірус|defender|clamav)"
    ),
]

ANTIVIRUS_CUSTOM_SCAN_PATTERNS = [
    re.compile(r"(?i)\b(?:проскануй|scan)\b.*\b(?:папк|folder|directory|path)"),
]

ANTIVIRUS_THREATS_PATTERNS = [
    re.compile(r"(?i)\b(?:покажи|show|list)\b.*\b(?:загроз|threats|detections)"),
]

UKRAINIAN_MARKERS = {
    "привіт",
    "будь",
    "ласка",
    "чому",
    "мережа",
    "диски",
    "діагностика",
    "процеси",
    "логи",
    "папка",
    "шлях",
    "хочу",
    "перевір",
    "запустити",
    "запусти",
    "антивірус",
    "гальмує",
    "повільно",
}

RUSSIAN_MARKERS = {
    "привет",
    "пожалуйста",
    "почему",
    "сеть",
    "диски",
    "диагностика",
    "процессы",
    "логи",
    "папка",
    "путь",
    "хочу",
    "проверь",
    "запустить",
    "запусти",
    "антивирус",
    "тормозит",
    "медленно",
}

SYSTEM_REQUEST_WORDS = {
    "cpu",
    "ram",
    "memory",
    "disk",
    "disks",
    "network",
    "internet",
    "slow",
    "lag",
    "freeze",
    "process",
    "processes",
    "logs",
    "diagnostic",
    "diagnostics",
    "system",
    "pc",
    "computer",
    "процес",
    "мереж",
    "диск",
    "лог",
    "діагност",
    "гальм",
    "повіль",
    "комп",
    "пк",
    "оператив",
    "пам'ять",
    "память",
    "сеть",
    "тормоз",
    "компьют",
    "систем",
    "процесс",
}

GENERIC_AMBIGUOUS_PATTERNS = [
    re.compile(r"(?i)^воно\s+не\s+працює$"),
    re.compile(r"(?i)^не\s+працює$"),
    re.compile(r"(?i)^it\s+does(?:n't| not)\s+work$"),
    re.compile(r"(?i)^не\s+работает$"),
]


def _t(lang: str, uk: str, ru: str, en: str) -> str:
    if lang == LANG_RU:
        return ru
    if lang == LANG_EN:
        return en
    return uk


def _language_name(lang: str) -> str:
    return {LANG_UK: "Ukrainian", LANG_RU: "Russian", LANG_EN: "English"}.get(
        lang, "the user's language"
    )


def _localized_scope(scope: str, lang: str) -> str:
    if scope == "user":
        return _t(
            lang,
            "профіль користувача",
            "профиль пользователя",
            "user profile",
        )
    return _t(
        lang,
        "безпечні системні каталоги",
        "безопасные системные каталоги",
        "safe system locations",
    )


def _localized_status(status: str, lang: str) -> str:
    normalized = (status or "").strip().casefold()
    translations = {
        "running": _t(lang, "працює", "работает", "running"),
        "sleeping": _t(lang, "очікує", "ожидает", "sleeping"),
        "disk-sleep": _t(lang, "очікує диск", "ожидает диск", "disk sleep"),
        "stopped": _t(lang, "зупинено", "остановлено", "stopped"),
        "tracing-stop": _t(
            lang,
            "зупинено трасуванням",
            "остановлено трассировкой",
            "tracing stop",
        ),
        "zombie": _t(lang, "зомбі", "зомби", "zombie"),
        "dead": _t(lang, "завершено", "завершено", "dead"),
        "idle": _t(lang, "бездіяльний", "простаивает", "idle"),
        "parked": _t(lang, "призупинено", "припарковано", "parked"),
        "moved": _t(lang, "переміщено", "перемещено", "moved"),
        "restored": _t(lang, "відновлено", "восстановлено", "restored"),
        "deleted": _t(lang, "видалено", "удалено", "deleted"),
        "quarantined": _t(lang, "у карантині", "в карантине", "in quarantine"),
        "pending": _t(lang, "очікує", "ожидает", "pending"),
        "unknown": _t(lang, "невідомо", "неизвестно", "unknown"),
    }
    return translations.get(normalized, status or translations["unknown"])


def _last_user_language(history: List[Dict[str, Any]]) -> Optional[str]:
    for entry in reversed(history):
        if entry.get("role") != "user":
            continue
        content = str(entry.get("content") or "")
        if content.strip():
            return _detect_language(content)
    return None


def _detect_language(text: str, history: Optional[List[Dict[str, Any]]] = None) -> str:
    lowered = text.casefold()
    words = set(re.findall(r"[A-Za-zА-Яа-яІіЇїЄєҐґ']{2,}", lowered))
    cyrillic_words = [word for word in words if re.search(r"[А-Яа-яІіЇїЄєҐґ]", word)]

    if re.search(r"[іїєґ]", lowered):
        return LANG_UK
    if re.search(r"[ёыэъ]", lowered):
        return LANG_RU
    if words & UKRAINIAN_MARKERS:
        return LANG_UK
    if words & RUSSIAN_MARKERS:
        return LANG_RU

    has_cyrillic = bool(re.search(r"[А-Яа-яІіЇїЄєҐґ]", text))
    has_latin = bool(re.search(r"[A-Za-z]", text))

    if has_latin and not has_cyrillic:
        return LANG_EN
    if cyrillic_words:
        if history:
            return _last_user_language(history) or LANG_UK
        return LANG_UK
    if has_cyrillic and not has_latin:
        if history:
            return _last_user_language(history) or LANG_UK
        return LANG_UK

    if history:
        return _last_user_language(history) or LANG_EN
    return LANG_EN


def _help_menu_reply(lang: str) -> str:
    return _t(
        lang,
        "Що тобі зараз ближче?\n1. діагностика ПК\n2. обслуговування / дії\n3. інше запитання",
        "Что тебе сейчас ближе?\n1. диагностика ПК\n2. обслуживание / действия\n3. другой вопрос",
        "What do you want to do first?\n1. PC diagnostics\n2. maintenance / actions\n3. another question",
    )


def _greeting_reply(message: str, lang: Optional[str] = None) -> Optional[str]:
    if not GREETING_PATTERN.match(message):
        return None

    selected_lang = lang or _detect_language(message)
    return _t(
        selected_lang,
        "Привіт! Що саме перевірити: загальний стан системи, процеси, диски, мережу чи логи?",
        "Привет! Что именно проверить: общее состояние системы, процессы, диски, сеть или логи?",
        "Hi! What should I check first: overall health, processes, disks, network, or logs?",
    )


def _compact(text: str) -> str:
    return " ".join(text.strip().split()).casefold()


def _is_help_request(message: str) -> bool:
    compact = " ".join(message.strip().split())
    return any(pattern.match(compact) for pattern in HELP_PATTERNS)


def _help_reply(lang: str) -> str:
    return _t(
        lang,
        "Я можу допомогти з такими задачами:\n"
        "- діагностика ПК\n"
        "- процеси\n"
        "- диски\n"
        "- мережа\n"
        "- логи\n"
        "- перевірка антивіруса і баз\n"
        "- створення файлів і папок\n"
        "- запис і редагування текстових файлів\n"
        "- запуск дозволених програм через approve\n"
        "- встановлення або видалення Python-пакетів через approve\n"
        "- попередній огляд сміття, карантин і відновлення\n\n"
        "Приклади:\n"
        "- діагностика ПК\n"
        "- покажи процеси\n"
        "- створи файл logs/report.txt\n"
        "- створи папку temp/data\n"
        "- встанови пакет rich\n"
        "- видали пакет requests\n"
        "- запусти C:\\Tools\\scan.exe\n"
        "- show quarantine",
        "Я могу помочь с такими задачами:\n"
        "- диагностика ПК\n"
        "- процессы\n"
        "- диски\n"
        "- сеть\n"
        "- логи\n"
        "- проверка антивируса и баз\n"
        "- создание файлов и папок\n"
        "- запись и редактирование текстовых файлов\n"
        "- запуск разрешенных программ через approve\n"
        "- установка или удаление Python-пакетов через approve\n"
        "- предпросмотр мусора, карантин и восстановление\n\n"
        "Примеры:\n"
        "- диагностика ПК\n"
        "- покажи процессы\n"
        "- создай файл logs/report.txt\n"
        "- создай папку temp/data\n"
        "- установи пакет rich\n"
        "- удали пакет requests\n"
        "- запусти C:\\Tools\\scan.exe\n"
        "- show quarantine",
        "I can help with tasks like:\n"
        "- PC diagnostics\n"
        "- heavy processes\n"
        "- disks\n"
        "- network\n"
        "- logs\n"
        "- antivirus checks and updates\n"
        "- creating files and folders\n"
        "- writing and editing text files\n"
        "- launching allowed programs via approve\n"
        "- installing or removing Python packages via approve\n"
        "- junk preview, quarantine, and restore\n\n"
        "Examples:\n"
        "- PC diagnostics\n"
        "- show processes\n"
        "- create file logs/report.txt\n"
        "- create folder temp/data\n"
        "- install package rich\n"
        "- uninstall package requests\n"
        "- run C:\\Tools\\scan.exe\n"
        "- show quarantine",
    )


def _maintenance_help_reply(lang: str) -> str:
    return _t(
        lang,
        "Добре, ось основні дії обслуговування.\n"
        "1. файли і папки: `створи файл notes.txt`\n"
        "2. Python-пакети: `встанови пакет rich`\n"
        "3. карантин: `show quarantine` або `віднови з карантину qk-1234abcd`",
        "Хорошо, вот основные действия обслуживания.\n"
        "1. файлы и папки: `создай файл notes.txt`\n"
        "2. Python-пакеты: `установи пакет rich`\n"
        "3. карантин: `show quarantine` или `восстанови из карантина qk-1234abcd`",
        "Here are the main maintenance actions.\n"
        "1. files and folders: `create file notes.txt`\n"
        "2. Python packages: `install package rich`\n"
        "3. quarantine: `show quarantine` or `restore from quarantine qk-1234abcd`",
    )


def _other_question_reply(lang: str) -> str:
    return _t(
        lang,
        "Добре, напиши коротко, що саме потрібно.\n"
        "Наприклад: `чому комп'ютер повільний?` або `що перевірити в логах?`",
        "Хорошо, напиши коротко, что именно нужно.\n"
        "Например: `почему компьютер медленный?` или `что проверить в логах?`",
        "Tell me briefly what you need.\n"
        "For example: `why is my computer slow?` or `what should I check in the logs?`",
    )


def _guided_create_file_reply(lang: str) -> str:
    return _t(
        lang,
        "Я можу створити файл, але мені потрібен шлях.\n"
        "Наприклад:\n"
        "- створи файл logs/report.txt\n"
        "- створи файл C:\\temp\\note.txt",
        "Я могу создать файл, но мне нужен путь.\n"
        "Например:\n"
        "- создай файл logs/report.txt\n"
        "- создай файл C:\\temp\\note.txt",
        "I can create a file, but I need a path.\n"
        "For example:\n"
        "- create file logs/report.txt\n"
        "- create file C:\\temp\\note.txt",
    )


def _guided_create_directory_reply(lang: str) -> str:
    return _t(
        lang,
        "Я можу створити папку, але мені потрібен шлях.\n"
        "Наприклад:\n"
        "- створи папку logs/archive\n"
        "- створи папку C:\\temp\\reports",
        "Я могу создать папку, но мне нужен путь.\n"
        "Например:\n"
        "- создай папку logs/archive\n"
        "- создай папку C:\\temp\\reports",
        "I can create a folder, but I need a path.\n"
        "For example:\n"
        "- create folder logs/archive\n"
        "- create folder C:\\temp\\reports",
    )


def _guided_run_program_reply(lang: str) -> str:
    return _t(
        lang,
        "Я можу підготувати запуск програми через підтвердження, але мені потрібен шлях.\n"
        "Якщо в шляху є пробіли, візьми його в лапки.\n"
        "Наприклад:\n"
        '- запусти "C:\\Program Files\\ClamAV\\clamscan.exe"\n'
        '- запусти "C:\\Tools\\scan.exe"',
        "Я могу подготовить запуск программы через подтверждение, но мне нужен путь.\n"
        "Если в пути есть пробелы, возьми его в кавычки.\n"
        "Например:\n"
        '- запусти "C:\\Program Files\\ClamAV\\clamscan.exe"\n'
        '- запусти "C:\\Tools\\scan.exe"',
        "I can prepare a program launch behind approval, but I need a path.\n"
        "If the path contains spaces, wrap it in quotes.\n"
        "For example:\n"
        '- run "C:\\Program Files\\ClamAV\\clamscan.exe"\n'
        '- run "C:\\Tools\\scan.exe"',
    )


def _guided_install_package_reply(lang: str) -> str:
    return _t(
        lang,
        "Я можу встановити Python-пакет після підтвердження.\n"
        "Наприклад:\n"
        "- встанови пакет rich\n"
        "- встанови пакет requests",
        "Я могу установить Python-пакет после подтверждения.\n"
        "Например:\n"
        "- установи пакет rich\n"
        "- установи пакет requests",
        "I can install a Python package after approval.\n"
        "For example:\n"
        "- install package rich\n"
        "- install package requests",
    )


def _guided_uninstall_package_reply(lang: str) -> str:
    return _t(
        lang,
        "Я можу видалити Python-пакет після підтвердження.\n"
        "Наприклад:\n"
        "- видали пакет rich\n"
        "- uninstall package requests",
        "Я могу удалить Python-пакет после подтверждения.\n"
        "Например:\n"
        "- удали пакет rich\n"
        "- uninstall package requests",
        "I can remove a Python package after approval.\n"
        "For example:\n"
        "- uninstall package rich\n"
        "- uninstall package requests",
    )


def _guided_append_file_reply(lang: str) -> str:
    return _t(
        lang,
        "Я можу додати текст у файл, але мені потрібен шлях і сам текст.\n"
        "Наприклад:\n"
        "- додай текст у файл notes.txt text: hello",
        "Я могу добавить текст в файл, но мне нужен путь и сам текст.\n"
        "Например:\n"
        "- добавь текст в файл notes.txt text: hello",
        "I can append text to a file, but I need both the path and the text.\n"
        "For example:\n"
        "- append text to file notes.txt text: hello",
    )


def _guided_replace_file_reply(lang: str) -> str:
    return _t(
        lang,
        "Я можу замінити текст у файлі, але мені потрібні шлях, старий і новий фрагмент.\n"
        "Наприклад:\n"
        "- заміни в файлі notes.txt old на new",
        "Я могу заменить текст в файле, но мне нужны путь, старый и новый фрагмент.\n"
        "Например:\n"
        "- замени в файле notes.txt old на new",
        "I can replace text in a file, but I need the path, old fragment, and new fragment.\n"
        "For example:\n"
        "- replace in file notes.txt old with new",
    )


def _guided_move_junk_reply(lang: str) -> str:
    return _t(
        lang,
        "Для переміщення сміття в карантин надай конкретні шляхи.\n"
        "Наприклад:\n"
        "- move junk to quarantine C:\\Users\\User\\AppData\\Local\\Temp\\old.tmp",
        "Чтобы переместить мусор в карантин, укажи конкретные пути.\n"
        "Например:\n"
        "- move junk to quarantine C:\\Users\\User\\AppData\\Local\\Temp\\old.tmp",
        "To move junk into quarantine, provide concrete paths.\n"
        "For example:\n"
        "- move junk to quarantine C:\\Users\\User\\AppData\\Local\\Temp\\old.tmp",
    )


def _guided_delete_junk_reply(lang: str) -> str:
    return _t(
        lang,
        "Для видалення сміття вкажи шляхи до файлів або папок.\n"
        "Краще спочатку зробити попередній огляд: `знайди сміття`.",
        "Для удаления мусора укажи пути к файлам или папкам.\n"
        "Лучше сначала сделать предпросмотр: `найди мусор`.",
        "To delete junk, provide file or folder paths.\n"
        "It is safer to start with a preview first: `find junk`.",
    )


def _guided_maintenance_reply(message: str, lang: str) -> Optional[str]:
    compact = _compact(message)

    if compact in {"файл створи", "створи файл", "create file", "создай файл"}:
        return _guided_create_file_reply(lang)
    if compact in {
        "папку створи",
        "створи папку",
        "створи директорію",
        "create folder",
        "create directory",
        "создай папку",
    }:
        return _guided_create_directory_reply(lang)
    if compact in {"встанови пакет", "install package", "установи пакет"}:
        return _guided_install_package_reply(lang)
    if compact in {"видали пакет", "uninstall package", "удали пакет"}:
        return _guided_uninstall_package_reply(lang)
    if compact in {"запусти", "запусти програму", "run", "run program"}:
        return _guided_run_program_reply(lang)
    if compact in {
        "додай текст",
        "додай текст у файл",
        "append text",
        "append to file",
    }:
        return _guided_append_file_reply(lang)
    if compact in {
        "заміни в файлі",
        "заміни текст",
        "replace in file",
        "replace text",
    }:
        return _guided_replace_file_reply(lang)
    if compact in {"перемісти сміття", "move junk", "move junk to quarantine"}:
        return _guided_move_junk_reply(lang)
    if compact in {"видали сміття", "delete junk", "remove junk"}:
        return _guided_delete_junk_reply(lang)

    return None


def _parse_control_command(message: str) -> tuple[Optional[str], Optional[str]]:
    compact = " ".join(message.strip().split())
    if not compact:
        return None, None

    lowered = compact.casefold()
    if lowered in PENDING_WORDS:
        return "pending", None
    if lowered in HISTORY_WORDS:
        return "history", None
    if lowered in LAST_ACTION_WORDS:
        return "last", None

    history_match = re.match(r"(?i)^history\s+actions\s+(\d{1,3})$", compact)
    if history_match:
        return "history", history_match.group(1)

    history_short_match = re.match(r"(?i)^history\s+(\d{1,3})$", compact)
    if history_short_match:
        return "history", history_short_match.group(1)

    parts = compact.split(maxsplit=1)
    head = parts[0].casefold()
    tail = parts[1].strip() if len(parts) > 1 else None

    if head in APPROVE_WORDS:
        return "approve", tail
    if head in CANCEL_WORDS:
        return "cancel", tail
    return None, None


def _extract_install_request(message: str) -> Optional[dict[str, Any]]:
    compact = " ".join(message.strip().split())
    for pattern in PIP_INSTALL_PATTERNS:
        match = pattern.search(compact)
        if not match:
            continue
        package = match.group(1)
        version = match.group(2)
        upgrade = "--upgrade" in compact.casefold() or "онови" in compact.casefold()
        payload: dict[str, Any] = {"name": package, "upgrade": upgrade}
        if version:
            payload["version"] = version
        return payload
    return None


def _extract_uninstall_request(message: str) -> Optional[dict[str, Any]]:
    compact = " ".join(message.strip().split())
    for pattern in PIP_UNINSTALL_PATTERNS:
        match = pattern.search(compact)
        if not match:
            continue
        package = match.group(1)
        if package:
            return {"name": package}
    return None


def _extract_create_file_request(message: str) -> Optional[dict[str, Any]]:
    compact = " ".join(message.strip().split())
    lowered = compact.casefold()
    for pattern in CREATE_FILE_PATTERNS:
        match = pattern.search(compact)
        if not match:
            continue
        tail = match.group(1).strip()
        path = _extract_quoted_text(tail) or tail.split()[0]
        if not path:
            return None

        content = ""
        content_markers = ["з текстом", "із текстом", "content:", "with text", "text:"]
        marker_positions = [
            lowered.find(marker)
            for marker in content_markers
            if lowered.find(marker) != -1
        ]
        if marker_positions:
            pos = min(marker_positions)
            content_fragment = compact[pos:]
            separator = ":"
            if separator in content_fragment:
                content = content_fragment.split(separator, 1)[1].strip()
            else:
                words = content_fragment.split(maxsplit=2)
                content = words[2] if len(words) >= 3 else ""

        return {"path": path, "content": content}
    return None


def _extract_append_file_request(message: str) -> Optional[dict[str, Any]]:
    compact = " ".join(message.strip().split())
    for pattern in APPEND_FILE_PATTERNS:
        match = pattern.search(compact)
        if not match:
            continue

        tail = match.group(1).strip()
        path = _extract_quoted_text(tail)
        if not path:
            tokens = tail.split()
            if not tokens:
                return None
            path = tokens[0]

        content = ""
        lowered = compact.casefold()
        marker = "text:"
        marker_pos = lowered.find(marker)
        if marker_pos == -1:
            marker = "текст:"
            marker_pos = lowered.find(marker)
        if marker_pos != -1:
            content = compact[marker_pos + len(marker) :].strip()
        else:
            quoted_payloads = _extract_all_quoted_texts(compact)
            if len(quoted_payloads) >= 2:
                content = quoted_payloads[-1]

        if not content:
            return None
        return {"path": path, "content": content}
    return None


def _extract_replace_file_request(message: str) -> Optional[dict[str, Any]]:
    compact = " ".join(message.strip().split())
    for pattern in REPLACE_FILE_PATTERNS:
        match = pattern.search(compact)
        if not match:
            continue

        path = (match.group("path") or "").strip()
        find_text = (
            match.group("find1") or match.group("find2") or match.group("find3") or ""
        ).strip()
        replace_text = (
            match.group("rep1") or match.group("rep2") or match.group("rep3") or ""
        ).strip()

        if not path or not find_text:
            continue
        return {
            "path": path,
            "find_text": find_text,
            "replace_text": replace_text,
        }

    return None


def _extract_run_program_request(message: str) -> Optional[dict[str, Any]]:
    compact = " ".join(message.strip().split())
    lowered = compact.casefold()
    if not any(pattern.search(compact) for pattern in RUN_PROGRAM_PATTERNS):
        return None

    path = _extract_windows_path(compact)
    if not path:
        quoted = _extract_quoted_text(compact)
        allowed_suffixes = (
            (".exe", ".cmd", ".bat", ".com")
            if settings.unsafe_full_access
            else (".exe",)
        )
        if quoted and quoted.casefold().endswith(allowed_suffixes):
            path = quoted
    if not path and settings.unsafe_full_access:
        tokens = compact.split()
        if len(tokens) >= 2:
            candidate = tokens[1].strip("`'\"")
            if candidate:
                path = candidate
    if not path:
        return None

    args: list[str] = []
    lower_path = path.casefold()
    marker = compact.casefold().find(lower_path)
    if marker != -1:
        after = compact[marker + len(path) :].strip()
        if after:
            args = [segment for segment in after.split()[:8] if segment]

    timeout = 120
    timeout_match = re.search(r"(?i)\btimeout\s*(\d{1,4})\b", lowered)
    if timeout_match:
        timeout = max(5, min(int(timeout_match.group(1)), 900))

    payload: dict[str, Any] = {"path": path, "timeout": timeout}
    if args:
        payload["args"] = args
    return payload


def _extract_shell_command_request(message: str) -> Optional[dict[str, Any]]:
    if not settings.unsafe_full_access:
        return None

    compact = message.strip()
    if not compact:
        return None

    cmd_match = re.match(r"(?is)^cmd(?:\.exe)?\s+(.+)$", compact)
    if cmd_match:
        return {
            "tool_name": "run_shell_command",
            "arguments": {
                "shell": "cmd",
                "command": cmd_match.group(1).strip(),
            },
        }

    powershell_match = re.match(r"(?is)^(?:powershell(?:\.exe)?|pwsh)\s+(.+)$", compact)
    if powershell_match:
        return {
            "tool_name": "run_shell_command",
            "arguments": {
                "shell": "powershell",
                "command": powershell_match.group(1).strip(),
            },
        }

    return None


def _extract_create_directory_request(message: str) -> Optional[dict[str, Any]]:
    compact = message.strip()
    match = re.match(
        r"(?is)^(?:mkdir|md|create\s+(?:dir|directory|folder)|створи\s+папку)\s+(.+)$",
        compact,
    )
    if not match:
        return None

    tail = match.group(1).strip()
    path = _extract_path_token(tail)
    if not path:
        return None
    return {"path": path}


def _extract_copy_path_request(message: str) -> Optional[dict[str, Any]]:
    if not settings.unsafe_full_access:
        return None

    compact = message.strip()
    match = re.match(r"(?is)^(?:copy|cp)\s+(.+)$", compact)
    if not match:
        return None

    source, destination = _extract_two_path_arguments(match.group(1).strip())
    if not source or not destination:
        return None

    overwrite = bool(
        re.search(r"(?i)(?:\s|^)(?:overwrite|replace|force|-f|/y)(?:\s|$)", compact)
    )
    return {
        "source": source,
        "destination": destination,
        "overwrite": overwrite,
    }


def _extract_move_path_request(message: str) -> Optional[dict[str, Any]]:
    if not settings.unsafe_full_access:
        return None

    compact = message.strip()
    normalized = " ".join(compact.split())
    if any(pattern.search(normalized) for pattern in MOVE_JUNK_PATTERNS):
        return None
    match = re.match(r"(?is)^(?:move|mv)\s+(.+)$", compact)
    if not match:
        return None

    source, destination = _extract_two_path_arguments(match.group(1).strip())
    if not source or not destination:
        return None

    overwrite = bool(
        re.search(r"(?i)(?:\s|^)(?:overwrite|replace|force|-f|/y)(?:\s|$)", compact)
    )
    return {
        "source": source,
        "destination": destination,
        "overwrite": overwrite,
    }


def _extract_remove_path_request(message: str) -> Optional[dict[str, Any]]:
    if not settings.unsafe_full_access:
        return None

    compact = message.strip()
    normalized = " ".join(compact.split())
    if any(pattern.search(normalized) for pattern in DELETE_JUNK_PATTERNS):
        return None
    match = re.match(r"(?is)^(?:rm|del|delete|remove|erase|rmdir)\s+(.+)$", compact)
    if not match:
        return None

    tail = match.group(1).strip()
    recursive = bool(
        re.search(r"(?i)(?:\s|^)(?:-r|-rf|/s|--recursive|recursive)(?:\s|$)", tail)
    )
    tail = re.sub(
        r"(?i)(?:\s|^)(?:-r|-rf|/s|--recursive|recursive)(?:\s|$)",
        " ",
        tail,
    ).strip()
    path = _extract_path_token(tail)
    if not path:
        return None
    return {
        "path": path,
        "recursive": recursive or compact.casefold().startswith("rmdir"),
    }


def _extract_path_token(text: str) -> Optional[str]:
    quoted = _extract_quoted_text(text)
    if quoted:
        return quoted

    paths = _extract_all_paths(text)
    if paths:
        return paths[0]

    cleaned = text.strip().strip("`'\"")
    return cleaned or None


def _extract_two_path_arguments(text: str) -> tuple[Optional[str], Optional[str]]:
    paths = _extract_all_paths(text)
    if len(paths) >= 2:
        return paths[0], paths[1]

    quoted = _extract_all_quoted_texts(text)
    if len(quoted) >= 2:
        return quoted[0], quoted[1]

    split = re.split(r"(?i)\s+(?:to|into|->)\s+", text, maxsplit=1)
    if len(split) == 2:
        return _extract_path_token(split[0]), _extract_path_token(split[1])

    tokens = text.split()
    if len(tokens) >= 2:
        return tokens[0].strip("`'\""), " ".join(tokens[1:]).strip("`'\"")

    return None, None


def _is_find_junk_request(message: str) -> bool:
    compact = " ".join(message.strip().split())
    return any(pattern.search(compact) for pattern in FIND_JUNK_PATTERNS)


def _extract_move_junk_request(message: str) -> Optional[dict[str, Any]]:
    compact = " ".join(message.strip().split())
    if not any(pattern.search(compact) for pattern in MOVE_JUNK_PATTERNS):
        return None

    paths = _extract_all_paths(compact)
    if not paths:
        return None
    return {"paths": paths}


def _extract_delete_junk_request(message: str) -> Optional[dict[str, Any]]:
    compact = " ".join(message.strip().split())
    if not any(pattern.search(compact) for pattern in DELETE_JUNK_PATTERNS):
        return None

    paths = _extract_all_paths(compact)
    if not paths:
        return None

    recursive = bool(
        re.search(r"(?i)\b(recursive|рекурсивно|включно з папками)\b", compact)
    )
    return {
        "paths": paths,
        "recursive": recursive,
    }


def _is_show_quarantine_request(message: str) -> bool:
    compact = " ".join(message.strip().split())
    return any(pattern.search(compact) for pattern in SHOW_QUARANTINE_PATTERNS)


def _extract_restore_quarantine_request(message: str) -> Optional[dict[str, Any]]:
    compact = " ".join(message.strip().split())
    if not any(pattern.search(compact) for pattern in RESTORE_QUARANTINE_PATTERNS):
        return None

    entry_ids = []
    for match in QUARANTINE_ENTRY_ID_PATTERN.finditer(compact):
        entry_id = match.group(0).lower()
        if entry_id not in entry_ids:
            entry_ids.append(entry_id)

    if not entry_ids:
        return None

    overwrite = bool(re.search(r"(?i)\b(overwrite|перезапис|замінити)\b", compact))
    payload: dict[str, Any] = {"entry_ids": entry_ids, "overwrite": overwrite}

    destination_root = _extract_restore_destination_root(compact)
    if destination_root:
        payload["destination_root"] = destination_root
    return payload


def _extract_restore_destination_root(message: str) -> Optional[str]:
    lowered = message.casefold()
    markers = [" destination ", " to ", " до ", " у ", " в "]
    for marker in markers:
        pos = lowered.rfind(marker)
        if pos == -1:
            continue
        tail = message[pos + len(marker) :].strip()
        if not tail:
            continue
        quoted = _extract_quoted_text(tail)
        if quoted:
            return quoted
        return tail.strip("`'\"")
    return None


def _extract_antivirus_provider(message: str) -> Optional[str]:
    lowered = message.casefold()
    if "defender" in lowered or "windows defender" in lowered:
        return "windows_defender"
    if "clamav" in lowered or "clam" in lowered:
        return "clamav"
    return None


def _is_antivirus_quick_scan_request(message: str) -> bool:
    compact = " ".join(message.strip().split())
    return any(pattern.search(compact) for pattern in ANTIVIRUS_QUICK_SCAN_PATTERNS)


def _is_antivirus_update_request(message: str) -> bool:
    compact = " ".join(message.strip().split())
    return any(pattern.search(compact) for pattern in ANTIVIRUS_UPDATE_PATTERNS)


def _extract_antivirus_custom_scan_request(message: str) -> Optional[dict[str, Any]]:
    compact = " ".join(message.strip().split())
    if not any(pattern.search(compact) for pattern in ANTIVIRUS_CUSTOM_SCAN_PATTERNS):
        return None

    path = _extract_windows_path(compact)
    if not path:
        quoted = _extract_quoted_text(compact)
        if quoted:
            path = quoted
    if not path:
        match = re.search(
            r"(?i)\b(?:папк[ауи]|folder|directory|path)\s+([^\s]+)", compact
        )
        if match:
            path = match.group(1).strip()

    if not path:
        return None

    payload: dict[str, Any] = {"path": path}
    provider = _extract_antivirus_provider(compact)
    if provider:
        payload["provider"] = provider
    return payload


def _is_antivirus_threats_request(message: str) -> bool:
    compact = " ".join(message.strip().split())
    return any(pattern.search(compact) for pattern in ANTIVIRUS_THREATS_PATTERNS)


def _extract_older_than_days(message: str) -> int:
    lowered = message.casefold()
    match = re.search(r"(?i)\b(\d{1,4})\s*(?:дн|дні|днів|days|day)\b", lowered)
    if match:
        return max(0, min(int(match.group(1)), 3650))
    return 7


def _extract_quoted_text(text: str) -> Optional[str]:
    quote_match = re.search(r"['\"]([^'\"]+)['\"]", text)
    if quote_match:
        return quote_match.group(1).strip()
    backtick_match = re.search(r"`([^`]+)`", text)
    if backtick_match:
        return backtick_match.group(1).strip()
    return None


def _extract_all_quoted_texts(text: str) -> list[str]:
    results = []
    for match in re.finditer(r"['\"]([^'\"]+)['\"]", text):
        value = match.group(1).strip()
        if value:
            results.append(value)
    for match in re.finditer(r"`([^`]+)`", text):
        value = match.group(1).strip()
        if value:
            results.append(value)
    return results


def _extract_all_paths(text: str) -> list[str]:
    paths = []
    windows_paths = WINDOWS_PATH_PATTERN.findall(text)
    for candidate in windows_paths:
        candidate = candidate.rstrip(" .,")
        if candidate and candidate not in paths:
            paths.append(candidate)

    for quoted in _extract_all_quoted_texts(text):
        if (
            "/" in quoted
            or "\\" in quoted
            or quoted.endswith((".tmp", ".log", ".dmp", ".old"))
        ):
            if quoted not in paths:
                paths.append(quoted)
    return paths


def _deterministic_junk_preview_report(message: str, lang: str) -> str:
    scope = (
        "user"
        if "user" in message.casefold() or "користувач" in message.casefold()
        else "safe"
    )
    older_days = _extract_older_than_days(message)
    result = find_junk_files(scope=scope, older_than_days=older_days, limit=30)
    scope_label = _localized_scope(scope, lang)

    if result.get("error"):
        return _t(
            lang,
            f"Не вдалося зібрати попередній огляд сміття: {result['error']}",
            f"Не удалось собрать предпросмотр мусора: {result['error']}",
            f"Could not collect a junk preview: {result['error']}",
        )

    count = int(result.get("count", 0))
    size_mb = float(result.get("total_size_mb", 0.0))
    items = result.get("items", [])

    lines = [
        _t(
            lang,
            "Добре, показую попередній огляд можливого сміття.",
            "Хорошо, показываю предпросмотр возможного мусора.",
            "Here is a preview of possible junk.",
        ),
        _t(
            lang,
            f"- Область перевірки: {scope_label}.",
            f"- Область проверки: {scope_label}.",
            f"- Scope: {scope_label}.",
        ),
        _t(
            lang,
            f"- Знайдено: {count} елементів, приблизний обсяг {size_mb:.2f} MB.",
            f"- Найдено: {count} элементов, примерный объем {size_mb:.2f} MB.",
            f"- Found: {count} items, about {size_mb:.2f} MB.",
        ),
    ]

    if not items:
        lines.append(
            _t(
                lang,
                "- Наразі нічого підозрілого для безпечного прибирання не знайдено.",
                "- Сейчас ничего подозрительного для безопасной очистки не найдено.",
                "- Nothing suspicious for safe cleanup was found right now.",
            )
        )
        return "\n".join(lines)

    lines.append(_t(lang, "- Топ елементи:", "- Топ элементы:", "- Top items:"))
    for item in items[:5]:
        path = item.get("path", "")
        size = float(item.get("size_bytes", 0)) / 1024**2
        age = item.get("age_days", "?")
        category = item.get("category", "unknown")
        age_label = _t(lang, f"{age} дн.", f"{age} дн.", f"{age} days")
        lines.append(f"  - {path} ({category}, {size:.2f} MB, {age_label})")

    lines.append(
        _t(
            lang,
            "- Якщо хочеш прибрати це безпечно: спочатку `move_junk_to_quarantine`, потім за потреби `delete_junk_files` після підтвердження.",
            "- Если хочешь убрать это безопасно: сначала `move_junk_to_quarantine`, потом при необходимости `delete_junk_files` после подтверждения.",
            "- If you want to clean this up safely, start with `move_junk_to_quarantine`, then use `delete_junk_files` after approval if needed.",
        )
    )
    return "\n".join(lines)


def _deterministic_quarantine_report(lang: str, limit: int = 20) -> str:
    result = show_quarantine(limit=limit)
    entries = result.get("entries", [])
    lines = [
        _t(
            lang,
            "Показую вміст карантину.",
            "Показываю содержимое карантина.",
            "Here is the quarantine contents.",
        ),
        _t(
            lang,
            f"- Елементів: {int(result.get('count', 0))}.",
            f"- Элементов: {int(result.get('count', 0))}.",
            f"- Items: {int(result.get('count', 0))}.",
        ),
        _t(
            lang,
            f"- Орієнтовний обсяг: {float(result.get('total_size_mb', 0.0)):.2f} MB.",
            f"- Примерный объем: {float(result.get('total_size_mb', 0.0)):.2f} MB.",
            f"- Approximate size: {float(result.get('total_size_mb', 0.0)):.2f} MB.",
        ),
    ]

    if not entries:
        lines.append(
            _t(
                lang,
                "- Карантин зараз порожній.",
                "- Карантин сейчас пустой.",
                "- Quarantine is empty right now.",
            )
        )
        return "\n".join(lines)

    lines.append(
        _t(lang, "- Останні записи:", "- Последние записи:", "- Recent entries:")
    )
    for entry in entries[:limit]:
        entry_id = entry.get("entry_id") or "no-id"
        source = entry.get("source") or _t(
            lang,
            "невідоме джерело",
            "неизвестный источник",
            "unknown source",
        )
        status = _localized_status(str(entry.get("status") or "unknown"), lang)
        size_mb = float(entry.get("size_bytes", 0)) / 1024**2
        lines.append(
            _t(
                lang,
                f"  - {entry_id}: {source} (статус: {status}, {size_mb:.2f} MB)",
                f"  - {entry_id}: {source} (статус: {status}, {size_mb:.2f} MB)",
                f"  - {entry_id}: {source} (status: {status}, {size_mb:.2f} MB)",
            )
        )
    return "\n".join(lines)


def _missing_quarantine_entries(entry_ids: list[str]) -> list[str]:
    result = show_quarantine(limit=500)
    available = {
        str(entry.get("entry_id")).lower()
        for entry in result.get("entries", [])
        if entry.get("entry_id")
    }
    return [entry_id for entry_id in entry_ids if entry_id.lower() not in available]


def _deterministic_antivirus_detect_report(lang: str) -> str:
    detection = detect_antivirus()
    lines = [
        _t(
            lang,
            "Добре, перевірив доступні антивіруси.",
            "Хорошо, я проверил доступные антивирусы.",
            "I checked the available antivirus providers.",
        )
    ]

    providers = detection.get("providers", [])
    if providers:
        lines.append(
            _t(
                lang,
                f"- Доступні провайдери: {', '.join(providers)}.",
                f"- Доступные провайдеры: {', '.join(providers)}.",
                f"- Available providers: {', '.join(providers)}.",
            )
        )
        lines.append(
            _t(
                lang,
                f"- Провайдер за замовчуванням: {detection.get('default_provider') or providers[0]}.",
                f"- Провайдер по умолчанию: {detection.get('default_provider') or providers[0]}.",
                f"- Default provider: {detection.get('default_provider') or providers[0]}.",
            )
        )
    else:
        lines.append(
            _t(
                lang,
                "- Жоден підтримуваний провайдер (Defender/ClamAV) зараз не готовий.",
                "- Ни один поддерживаемый провайдер (Defender/ClamAV) сейчас не готов.",
                "- No supported provider (Defender/ClamAV) is ready right now.",
            )
        )

    for hint in detection.get("hints", [])[:5]:
        lines.append(f"- {hint}")

    details = detection.get("details", {})
    defender = details.get("windows_defender", {})
    if defender.get("error_code") == "0x800106ba":
        lines.append(
            _t(
                lang,
                "- Defender недоступний через 0x800106ba: зазвичай служба WinDefend вимкнена або зупинена.",
                "- Defender недоступен из-за 0x800106ba: обычно служба WinDefend отключена или остановлена.",
                "- Defender is unavailable because of 0x800106ba: WinDefend is usually disabled or stopped.",
            )
        )
        for step in (defender.get("manual_checks") or [])[:3]:
            lines.append(f"  - {step}")

    return "\n".join(lines)


def _format_antivirus_scan_report(result: dict[str, Any], lang: str) -> str:
    if result.get("error"):
        lines = [
            _t(
                lang,
                "Не вдалося виконати антивірусну операцію.",
                "Не удалось выполнить антивирусную операцию.",
                "The antivirus operation could not be completed.",
            ),
            _t(
                lang,
                f"- Причина: {result['error']}",
                f"- Причина: {result['error']}",
                f"- Reason: {result['error']}",
            ),
        ]
        for step in (result.get("manual_checks") or [])[:3]:
            lines.append(
                _t(
                    lang,
                    f"- Перевір вручну: {step}",
                    f"- Проверь вручную: {step}",
                    f"- Check manually: {step}",
                )
            )
        return "\n".join(lines)

    provider = result.get("provider", "unknown")
    lines = [
        _t(
            lang,
            f"Готово, операція виконана через `{provider}`.",
            f"Готово, операция выполнена через `{provider}`.",
            f"Done, the operation ran through `{provider}`.",
        )
    ]
    scan_type = result.get("scan_type")
    if scan_type:
        lines.append(
            _t(
                lang,
                f"- Тип сканування: {scan_type}.",
                f"- Тип сканирования: {scan_type}.",
                f"- Scan type: {scan_type}.",
            )
        )

    if "success" in result:
        lines.append(
            _t(
                lang,
                f"- Статус: {'успіх' if result.get('success') else 'помилка'}.",
                f"- Статус: {'успех' if result.get('success') else 'ошибка'}.",
                f"- Status: {'success' if result.get('success') else 'error'}.",
            )
        )

    if "threats_count" in result:
        lines.append(
            _t(
                lang,
                f"- Виявлено загроз: {int(result.get('threats_count', 0))}.",
                f"- Обнаружено угроз: {int(result.get('threats_count', 0))}.",
                f"- Threats found: {int(result.get('threats_count', 0))}.",
            )
        )

    if "infected_files_total" in result:
        lines.append(
            _t(
                lang,
                f"- Підозрілих файлів: {int(result.get('infected_files_total', 0))}.",
                f"- Подозрительных файлов: {int(result.get('infected_files_total', 0))}.",
                f"- Suspicious files: {int(result.get('infected_files_total', 0))}.",
            )
        )

    if result.get("error_code"):
        lines.append(
            _t(
                lang,
                f"- Код помилки: {result['error_code']}.",
                f"- Код ошибки: {result['error_code']}.",
                f"- Error code: {result['error_code']}.",
            )
        )

    return "\n".join(lines)


def _format_antivirus_threats_report(result: dict[str, Any], lang: str) -> str:
    if result.get("error"):
        lines = [
            _t(
                lang,
                "Не вдалося отримати список загроз.",
                "Не удалось получить список угроз.",
                "Could not get the threat list.",
            ),
            _t(
                lang,
                f"- Причина: {result['error']}",
                f"- Причина: {result['error']}",
                f"- Reason: {result['error']}",
            ),
        ]
        for step in (result.get("manual_checks") or [])[:3]:
            lines.append(
                _t(
                    lang,
                    f"- Перевір вручну: {step}",
                    f"- Проверь вручную: {step}",
                    f"- Check manually: {step}",
                )
            )
        return "\n".join(lines)

    threats = result.get("threats", [])
    count = int(result.get("count", len(threats)))
    provider = result.get("provider", "unknown")
    lines = [
        _t(
            lang,
            f"Ось останні загрози з `{provider}`.",
            f"Вот последние угрозы из `{provider}`.",
            f"Here are the recent threats from `{provider}`.",
        ),
        _t(
            lang,
            f"- Кількість записів: {count}.",
            f"- Количество записей: {count}.",
            f"- Entries: {count}.",
        ),
    ]
    if not threats:
        lines.append(
            _t(
                lang,
                "- Наразі записів про загрози не знайдено.",
                "- Сейчас записей об угрозах не найдено.",
                "- No threat records were found.",
            )
        )
        return "\n".join(lines)

    for entry in threats[:5]:
        name = entry.get("threat_name") or entry.get("ThreatName") or "unknown"
        target = entry.get("target") or entry.get("Resources") or "unknown target"
        lines.append(f"- {name}: {target}")
    return "\n".join(lines)


def _normalize_intent(message: str) -> str:
    compact = " ".join(message.strip().split()).casefold()
    return INTENT_NORMALIZATION.get(compact, message.strip())


def _is_short_ambiguous_message(message: str) -> bool:
    compact = message.strip()
    if not compact:
        return False
    words = re.findall(r"[A-Za-zА-Яа-яІіЇїЄєҐґ0-9]+", compact.casefold())
    if not words or len(words) > 3:
        return False
    if any(word in SHORT_ACTION_VERBS for word in words):
        return False
    return True


def _needs_clarification(message: str) -> bool:
    compact = " ".join(message.strip().split())
    if _looks_like_system_request(compact):
        return False
    if _is_find_junk_request(compact) or _is_show_quarantine_request(compact):
        return False
    if _is_short_ambiguous_message(compact):
        return True
    return any(pattern.match(compact) for pattern in GENERIC_AMBIGUOUS_PATTERNS)


def _ambiguous_input_reply(lang: str) -> str:
    return _t(
        lang,
        "Уточни, будь ласка: що саме перевірити зараз - загальний стан ПК, процеси, диски, мережу чи логи?",
        "Уточни, пожалуйста: что именно проверить сейчас - общее состояние ПК, процессы, диски, сеть или логи?",
        "What should I check right now: overall PC health, processes, disks, network, or logs?",
    )


def _looks_mixed_language(text: str) -> bool:
    words = re.findall(r"[A-Za-zА-Яа-яІіЇїЄєҐґ]{3,}", text)
    latin_words = [word for word in words if re.fullmatch(r"[A-Za-z]{3,}", word)]
    cyrillic_words = [
        word for word in words if re.fullmatch(r"[А-Яа-яІіЇїЄєҐґ]{3,}", word)
    ]
    if len(latin_words) < 3 or len(cyrillic_words) < 3:
        return False
    smaller = min(len(latin_words), len(cyrillic_words))
    larger = max(len(latin_words), len(cyrillic_words))
    return (smaller / larger) >= 0.35


def _extract_windows_path(text: str) -> Optional[str]:
    match = WINDOWS_PATH_PATTERN.search(text)
    if not match:
        return None
    return match.group(0).rstrip(" .,")


def _find_recent_windows_path(history: List[Dict[str, Any]]) -> Optional[str]:
    for entry in reversed(history):
        if entry.get("role") != "user":
            continue
        content = str(entry.get("content") or "")
        path = _extract_windows_path(content)
        if path:
            return path
    return None


def _last_assistant_content(history: List[Dict[str, Any]]) -> Optional[str]:
    for entry in reversed(history):
        if entry.get("role") != "assistant":
            continue
        content = entry.get("content")
        if isinstance(content, str) and content.strip():
            return content
    return None


def _looks_like_software_path_request(message: str, recent_path: Optional[str]) -> bool:
    lowered = message.casefold()
    if _extract_windows_path(message):
        return True
    if recent_path and any(word in lowered for word in SOFTWARE_CONTEXT_WORDS):
        return True
    return False


def _looks_like_operational_request(message: str) -> bool:
    lowered = message.casefold()
    return any(word in lowered for word in OPERATIONAL_REQUEST_WORDS)


def _looks_like_system_request(message: str) -> bool:
    lowered = message.casefold()
    return any(word in lowered for word in SYSTEM_REQUEST_WORDS)


def _extract_candidate_path(message: str) -> Optional[str]:
    path = _extract_windows_path(message)
    if path:
        return path

    quoted = _extract_quoted_text(message)
    if quoted and ("/" in quoted or "\\" in quoted):
        return quoted
    return None


def _is_path_only_input(message: str) -> bool:
    path = _extract_candidate_path(message)
    if not path:
        return False
    stripped = message.strip().strip("`")
    return stripped == path or stripped == f'"{path}"' or stripped == f"'{path}'"


def _guess_windows_candidates(path: str) -> list[str]:
    lowered = path.casefold()
    if "clam" in lowered:
        return ["clamscan.exe", "freshclam.exe", "clamd.exe"]
    return ["app.exe", "launcher.exe", "setup.exe"]


def _path_clarification_reply(path: str, lang: str) -> str:
    return _t(
        lang,
        f"Бачу шлях `{path}`. Що ти хочеш зробити далі: переглянути вміст, знайти файл запуску чи перевірити цю папку?",
        f"Вижу путь `{path}`. Что ты хочешь сделать дальше: посмотреть содержимое, найти файл запуска или проверить эту папку?",
        f"I can see the path `{path}`. What do you want to do next: inspect its contents, find the launcher, or check that folder?",
    )


def _path_guided_reply(path: str, message: str, lang: str) -> str:
    candidates = _guess_windows_candidates(path)
    looks_operational = _looks_like_operational_request(message)
    intro = _t(
        lang,
        f"Бачу шлях у Windows: `{path}`. Схоже, ти маєш на увазі програму в цій папці.",
        f"Вижу путь в Windows: `{path}`. Похоже, ты имеешь в виду программу в этой папке.",
        f"I can see a Windows path: `{path}`. It looks like you mean software in that folder.",
    )
    limitation = _t(
        lang,
        "Я не можу сам запускати `.exe` або читати цю папку, якщо вона поза дозволеними шляхами.",
        "Я не могу сам запускать `.exe` или читать эту папку, если она вне разрешенных путей.",
        "I cannot directly run `.exe` files or inspect that folder if it is outside the allowed roots.",
    )
    next_step = _t(
        lang,
        f"Найбезпечніший наступний крок: відкрий цю папку вручну й перевір, чи є там `{candidates[0]}` або `{candidates[1]}`.",
        f"Самый безопасный следующий шаг: открой эту папку вручную и проверь, есть ли там `{candidates[0]}` или `{candidates[1]}`.",
        f"The safest next step is to open that folder manually and check whether `{candidates[0]}` or `{candidates[1]}` is there.",
    )

    options = [
        _t(
            lang,
            f"1. знайти ймовірний файл запуску (`{candidates[0]}`, `{candidates[1]}`, `{candidates[2]}`);",
            f"1. найти вероятный файл запуска (`{candidates[0]}`, `{candidates[1]}`, `{candidates[2]}`);",
            f"1. identify the likely launcher (`{candidates[0]}`, `{candidates[1]}`, `{candidates[2]}`);",
        ),
        _t(
            lang,
            "2. підказати, що саме запускати вручну в CMD або PowerShell;",
            "2. подсказать, что именно запускать вручную в CMD или PowerShell;",
            "2. explain what to launch manually in CMD or PowerShell;",
        ),
        _t(
            lang,
            "3. допомогти безпечно додати цей шлях у дозволені для читання, якщо хочеш перевірити вміст через Medfarl;",
            "3. помочь безопасно добавить этот путь в разрешенные для чтения, если хочешь проверить содержимое через Medfarl;",
            "3. help you add this path to the allowed read roots safely if you want Medfarl to inspect it;",
        ),
        _t(
            lang,
            "4. пояснити, який файл потрібен для оновлення баз, а який для самого сканування.",
            "4. объяснить, какой файл нужен для обновления баз, а какой для самого сканирования.",
            "4. explain which file is typically for updates and which one is for scanning.",
        ),
    ]

    if looks_operational:
        intro = _t(
            lang,
            f"Бачу, ти хочеш запустити програму з шляху `{path}`.",
            f"Вижу, ты хочешь запустить программу по пути `{path}`.",
            f"It looks like you want to launch something from `{path}`.",
        )

    return "\n".join([intro, limitation, next_step, *options])


def _format_disk_summary(disks: list[dict], lang: str) -> str:
    if not disks:
        return _t(
            lang,
            "дані про диски недоступні",
            "данные о дисках недоступны",
            "disk data is unavailable",
        )
    by_usage = sorted(disks, key=lambda disk: disk.get("percent", 0), reverse=True)
    top = by_usage[:3]
    fragments = []
    for disk in top:
        mount = disk.get("mountpoint") or disk.get("device") or "disk"
        percent = float(disk.get("percent", 0))
        free_gb = float(disk.get("free_gb", 0))
        fragments.append(
            _t(
                lang,
                f"{mount} {percent:.1f}% (вільно {free_gb:.0f} GB)",
                f"{mount} {percent:.1f}% (свободно {free_gb:.0f} GB)",
                f"{mount} {percent:.1f}% ({free_gb:.0f} GB free)",
            )
        )
    return "; ".join(fragments)


def _format_process_summary(processes: list[dict], lang: str) -> str:
    if not processes:
        return _t(
            lang,
            "дані про процеси недоступні",
            "данные о процессах недоступны",
            "process data is unavailable",
        )
    top = processes[:3]
    return ", ".join(
        f"{proc.get('name', 'unknown')} ({float(proc.get('cpu_percent', 0)):.1f}% CPU)"
        for proc in top
    )


def _format_network_summary(network: dict[str, dict], lang: str) -> str:
    if not network:
        return _t(
            lang,
            "інтерфейси не знайдено",
            "интерфейсы не найдены",
            "no interfaces found",
        )
    active = [
        name
        for name, details in network.items()
        if any(
            addr and not str(addr).startswith("127.") and str(addr) != "::1"
            for addr in details.get("addresses", [])
        )
    ]
    sent_mb = sum(
        float(details.get("bytes_sent_mb", 0)) for details in network.values()
    )
    recv_mb = sum(
        float(details.get("bytes_recv_mb", 0)) for details in network.values()
    )
    if not active:
        return _t(
            lang,
            f"активні адреси не виявлені, трафік {sent_mb:.1f}/{recv_mb:.1f} MB",
            f"активные адреса не найдены, трафик {sent_mb:.1f}/{recv_mb:.1f} MB",
            f"no active addresses found, traffic {sent_mb:.1f}/{recv_mb:.1f} MB",
        )
    preview = ", ".join(active[:3])
    return _t(
        lang,
        f"активні інтерфейси: {preview}; трафік {sent_mb:.1f}/{recv_mb:.1f} MB",
        f"активные интерфейсы: {preview}; трафик {sent_mb:.1f}/{recv_mb:.1f} MB",
        f"active interfaces: {preview}; traffic {sent_mb:.1f}/{recv_mb:.1f} MB",
    )


def _format_recent_errors_summary(errors: dict[str, Any], lang: str) -> str:
    entries = errors.get("entries", [])
    if not entries:
        if errors.get("error"):
            return _t(
                lang,
                f"читання помилок недоступне: {errors['error']}",
                f"чтение ошибок недоступно: {errors['error']}",
                f"error reading is unavailable: {errors['error']}",
            )
        return _t(
            lang,
            "критичних помилок не виявлено",
            "критических ошибок не найдено",
            "no critical errors found",
        )

    fragments = []
    for entry in entries[:2]:
        provider = entry.get("provider") or entry.get("level") or "source"
        message = entry.get("message") or entry.get("Message") or ""
        cleaned = " ".join(str(message).split())[:120]
        fragments.append(f"{provider}: {cleaned}")
    return "; ".join(fragments)


def _deterministic_diagnostic_report(
    scanner: SystemScanner, inspector: LibInspector, lang: str
) -> str:
    snapshot = scanner.to_dict()
    software = inspector.summary_dict()
    disk_summary = get_disk_summary(scanner, top_n=3)
    process_summary = get_top_processes(scanner, count=3)
    network_summary = get_network_summary(scanner)
    recent_errors = get_recent_errors(limit=3)

    cpu = snapshot.get("cpu", {})
    memory = snapshot.get("memory", {})

    failed_services = software.get("failed_services", [])
    failed_services_text = (
        ", ".join(failed_services[:3])
        if failed_services
        else _t(
            lang,
            "критичних збоїв не виявлено",
            "критических сбоев не найдено",
            "no critical failures found",
        )
    )
    lines = [
        _t(
            lang,
            "Добре, запускаю базову діагностику системи.",
            "Хорошо, запускаю базовую диагностику системы.",
            "Running a basic system diagnostic.",
        ),
        _t(
            lang,
            f"- CPU: {cpu.get('model', 'невідомо')}, {cpu.get('usage_percent', 0):.1f}% навантаження, {cpu.get('cores_logical', '?')} логічних ядер.",
            f"- CPU: {cpu.get('model', 'неизвестно')}, {cpu.get('usage_percent', 0):.1f}% нагрузки, {cpu.get('cores_logical', '?')} логических ядер.",
            f"- CPU: {cpu.get('model', 'unknown')}, {cpu.get('usage_percent', 0):.1f}% load, {cpu.get('cores_logical', '?')} logical cores.",
        ),
        _t(
            lang,
            f"- RAM: {memory.get('used_gb', 0):.1f}/{memory.get('total_gb', 0):.1f} GB ({memory.get('percent', 0):.1f}%), swap {memory.get('swap_used_gb', 0):.1f}/{memory.get('swap_total_gb', 0):.1f} GB.",
            f"- RAM: {memory.get('used_gb', 0):.1f}/{memory.get('total_gb', 0):.1f} GB ({memory.get('percent', 0):.1f}%), swap {memory.get('swap_used_gb', 0):.1f}/{memory.get('swap_total_gb', 0):.1f} GB.",
            f"- RAM: {memory.get('used_gb', 0):.1f}/{memory.get('total_gb', 0):.1f} GB ({memory.get('percent', 0):.1f}%), swap {memory.get('swap_used_gb', 0):.1f}/{memory.get('swap_total_gb', 0):.1f} GB.",
        ),
        _t(
            lang,
            f"- Диски: {_format_disk_summary(disk_summary.get('disks', []), lang)}.",
            f"- Диски: {_format_disk_summary(disk_summary.get('disks', []), lang)}.",
            f"- Disks: {_format_disk_summary(disk_summary.get('disks', []), lang)}.",
        ),
        _t(
            lang,
            f"- Процеси: {_format_process_summary(process_summary.get('processes', []), lang)}.",
            f"- Процессы: {_format_process_summary(process_summary.get('processes', []), lang)}.",
            f"- Processes: {_format_process_summary(process_summary.get('processes', []), lang)}.",
        ),
        _t(
            lang,
            f"- Сервіси, пакети й помилки: pip {software.get('pip_packages_count', 0)}, системні пакети {software.get('system_packages_count', 0)}, проблемні сервіси: {failed_services_text}; останні помилки: {_format_recent_errors_summary(recent_errors, lang)}.",
            f"- Сервисы, пакеты и ошибки: pip {software.get('pip_packages_count', 0)}, системные пакеты {software.get('system_packages_count', 0)}, проблемные сервисы: {failed_services_text}; последние ошибки: {_format_recent_errors_summary(recent_errors, lang)}.",
            f"- Services, packages, and errors: pip {software.get('pip_packages_count', 0)}, system packages {software.get('system_packages_count', 0)}, failed services: {failed_services_text}; recent errors: {_format_recent_errors_summary(recent_errors, lang)}.",
        ),
        _t(
            lang,
            f"- Мережа: {_format_network_summary({entry['name']: entry for entry in network_summary.get('active_interfaces', [])}, lang) if network_summary.get('active_interfaces') else _format_network_summary({}, lang)}.",
            f"- Сеть: {_format_network_summary({entry['name']: entry for entry in network_summary.get('active_interfaces', [])}, lang) if network_summary.get('active_interfaces') else _format_network_summary({}, lang)}.",
            f"- Network: {_format_network_summary({entry['name']: entry for entry in network_summary.get('active_interfaces', [])}, lang) if network_summary.get('active_interfaces') else _format_network_summary({}, lang)}.",
        ),
    ]
    return "\n".join(lines)


def _deterministic_process_report(scanner: SystemScanner, lang: str) -> str:
    summary = get_top_processes(scanner, count=5)
    processes = summary.get("processes", [])
    if not processes:
        return _t(
            lang,
            "Не бачу активних процесів із помітним навантаженням прямо зараз.",
            "Сейчас не вижу активных процессов с заметной нагрузкой.",
            "I do not see active processes with noticeable load right now.",
        )

    lines = [
        _t(
            lang,
            "Добре, показую найважчі процеси зараз:",
            "Хорошо, показываю самые тяжелые процессы сейчас:",
            "Here are the heaviest processes right now:",
        )
    ]
    for process in processes:
        status = _localized_status(str(process.get("status") or "unknown"), lang)
        lines.append(
            _t(
                lang,
                f"- {process['name']} (PID {process['pid']}): {process['cpu_percent']:.1f}% CPU, {process['memory_mb']:.1f} MB RAM, статус: {status}.",
                f"- {process['name']} (PID {process['pid']}): {process['cpu_percent']:.1f}% CPU, {process['memory_mb']:.1f} MB RAM, статус: {status}.",
                f"- {process['name']} (PID {process['pid']}): {process['cpu_percent']:.1f}% CPU, {process['memory_mb']:.1f} MB RAM, status: {status}.",
            )
        )
    return "\n".join(lines)


def _deterministic_disk_report(scanner: SystemScanner, lang: str) -> str:
    summary = get_disk_summary(scanner, top_n=6)
    disks = summary.get("disks", [])
    if not disks:
        return _t(
            lang,
            "Не вдалося отримати дані про диски.",
            "Не удалось получить данные о дисках.",
            "Could not get disk data.",
        )

    lines = [
        _t(
            lang,
            "Добре, перевіряю диски і вільне місце:",
            "Хорошо, проверяю диски и свободное место:",
            "Checking disks and free space:",
        )
    ]
    for disk in disks:
        mount = disk.get("mountpoint") or disk.get("device") or "disk"
        severity = (
            _t(lang, "критично", "критично", "critical")
            if disk["percent"] >= 90
            else _t(lang, "увага", "внимание", "warning")
            if disk["percent"] >= 80
            else _t(lang, "норма", "норма", "normal")
        )
        lines.append(
            _t(
                lang,
                f"- {mount}: {disk['used_gb']:.0f}/{disk['total_gb']:.0f} GB, {disk['percent']:.1f}% зайнято, вільно {disk['free_gb']:.0f} GB ({severity}).",
                f"- {mount}: {disk['used_gb']:.0f}/{disk['total_gb']:.0f} GB, {disk['percent']:.1f}% занято, свободно {disk['free_gb']:.0f} GB ({severity}).",
                f"- {mount}: {disk['used_gb']:.0f}/{disk['total_gb']:.0f} GB, {disk['percent']:.1f}% used, {disk['free_gb']:.0f} GB free ({severity}).",
            )
        )
    return "\n".join(lines)


def _deterministic_network_report(scanner: SystemScanner, lang: str) -> str:
    summary = get_network_summary(scanner)
    active_interfaces = summary.get("active_interfaces", [])
    if not active_interfaces:
        return _t(
            lang,
            "Добре, перевірив мережу. Активних мережевих інтерфейсів із зовнішніми адресами зараз не видно.",
            "Хорошо, я проверил сеть. Активных сетевых интерфейсов с внешними адресами сейчас не видно.",
            "I checked the network. No active interfaces with external addresses are visible right now.",
        )

    lines = [
        _t(
            lang,
            "Добре, перевірив стан мережі.",
            "Хорошо, я проверил состояние сети.",
            "I checked the network state.",
        ),
        _t(
            lang,
            f"- Загальний трафік: {summary.get('total_sent_mb', 0):.1f} MB відправлено, {summary.get('total_recv_mb', 0):.1f} MB отримано.",
            f"- Общий трафик: {summary.get('total_sent_mb', 0):.1f} MB отправлено, {summary.get('total_recv_mb', 0):.1f} MB получено.",
            f"- Total traffic: {summary.get('total_sent_mb', 0):.1f} MB sent, {summary.get('total_recv_mb', 0):.1f} MB received.",
        ),
    ]
    for interface in active_interfaces[:4]:
        addresses = ", ".join(interface.get("addresses", [])[:2]) or _t(
            lang, "без адрес", "без адресов", "no addresses"
        )
        lines.append(
            _t(
                lang,
                f"- {interface['name']}: адреси {addresses}, трафік {interface['bytes_sent_mb']:.1f}/{interface['bytes_recv_mb']:.1f} MB.",
                f"- {interface['name']}: адреса {addresses}, трафик {interface['bytes_sent_mb']:.1f}/{interface['bytes_recv_mb']:.1f} MB.",
                f"- {interface['name']}: addresses {addresses}, traffic {interface['bytes_sent_mb']:.1f}/{interface['bytes_recv_mb']:.1f} MB.",
            )
        )
    return "\n".join(lines)


def _deterministic_logs_report(lang: str, limit: int = 5) -> str:
    errors = get_recent_errors(limit=limit)
    entries = errors.get("entries", [])
    if not entries:
        if errors.get("error"):
            return _t(
                lang,
                f"Не вдалося прочитати системні помилки: {errors['error']}",
                f"Не удалось прочитать системные ошибки: {errors['error']}",
                f"Could not read recent system errors: {errors['error']}",
            )
        return _t(
            lang,
            "Останніх критичних помилок у доступних системних логах не виявлено.",
            "Последних критических ошибок в доступных системных логах не найдено.",
            "No recent critical errors were found in the available system logs.",
        )

    lines = [
        _t(
            lang,
            "Добре, показую останні системні помилки:",
            "Хорошо, показываю последние системные ошибки:",
            "Here are the recent system errors:",
        )
    ]
    for entry in entries[:limit]:
        provider = (
            entry.get("provider")
            or entry.get("level")
            or errors.get("source", "source")
        )
        event_id = f" #{entry['id']}" if entry.get("id") else ""
        message = " ".join(
            str(entry.get("message") or entry.get("Message") or "").split()
        )[:160]
        lines.append(f"- {provider}{event_id}: {message}")
    return "\n".join(lines)


def _build_snapshot_context(
    scanner: SystemScanner, inspector: LibInspector
) -> Optional[Dict[str, Any]]:
    try:
        return {
            "system": scanner.to_dict(),
            "software": inspector.summary_dict(),
        }
    except Exception as exc:
        return {"error": f"Failed to collect initial snapshot: {exc}"}


class MedfarlAgent:
    def __init__(
        self,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
        *,
        client: Optional[LLMClient] = None,
        scanner: Optional[SystemScanner] = None,
        inspector: Optional[LibInspector] = None,
    ) -> None:
        self.scanner = scanner or SystemScanner()
        self.inspector = inspector or LibInspector()
        self.client = client or LLMClient(
            base_url=settings.llm_url,
            model=model or settings.model,
            timeout=timeout or settings.timeout,
        )
        self.tool_registry = build_tools(self.scanner, self.inspector)
        self.schemas = tool_schemas(self.tool_registry)
        self.approval = ApprovalState()
        self._history: List[Dict[str, Any]] = []
        self._awaiting_help_menu = False
        self._bootstrap()

    def classify_request(self, message: str) -> dict[str, Any]:
        cleaned_message = message.strip()
        normalized_message = _normalize_intent(cleaned_message)
        control_action, control_id = _parse_control_command(cleaned_message)
        language = _detect_language(cleaned_message, self._history)
        recent_path = _find_recent_windows_path(self._history)
        candidate_path = _extract_candidate_path(cleaned_message) or recent_path
        shell_request = _extract_shell_command_request(cleaned_message)

        base: dict[str, Any] = {
            "route": None,
            "kind": None,
            "cleaned_message": cleaned_message,
            "normalized_message": normalized_message,
            "language": language,
            "control_action": control_action,
            "control_id": control_id,
            "payload": None,
            "guided_reply": None,
            "direct_reply": None,
            "planning_note": None,
            "recent_path": candidate_path,
        }

        if control_action in {"pending", "history", "last", "approve", "cancel"}:
            return {**base, "route": ROUTE_DIRECT_RESPONSE, "kind": "control"}

        if cleaned_message not in HELP_MENU_CHOICES:
            self._awaiting_help_menu = False

        if self._awaiting_help_menu and cleaned_message in HELP_MENU_CHOICES:
            self._awaiting_help_menu = False
            if cleaned_message == "1":
                return {
                    **base,
                    "route": ROUTE_TOOL_USE,
                    "kind": "summary_intent",
                    "normalized_message": DIAGNOSTIC_INTENT,
                }
            if cleaned_message == "2":
                return {
                    **base,
                    "route": ROUTE_DIRECT_RESPONSE,
                    "kind": "maintenance_help",
                    "direct_reply": _maintenance_help_reply(language),
                }
            return {
                **base,
                "route": ROUTE_DIRECT_RESPONSE,
                "kind": "other_question",
                "direct_reply": _other_question_reply(language),
            }

        if _is_help_request(cleaned_message) or normalized_message == HELP_INTENT:
            return {
                **base,
                "route": ROUTE_DIRECT_RESPONSE,
                "kind": "help_menu",
                "direct_reply": _help_menu_reply(language),
            }

        if shell_request:
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "maintenance_or_files",
                "payload": shell_request,
            }

        greeting_reply = _greeting_reply(cleaned_message, language)
        if greeting_reply is not None:
            return {
                **base,
                "route": ROUTE_DIRECT_RESPONSE,
                "kind": "greeting",
                "direct_reply": greeting_reply,
            }

        guided_maintenance = _guided_maintenance_reply(cleaned_message, language)
        if guided_maintenance is not None:
            return {
                **base,
                "route": ROUTE_GUIDED_MANUAL_MODE,
                "kind": "guided_maintenance",
                "guided_reply": guided_maintenance,
            }

        if normalized_message in {
            DIAGNOSTIC_INTENT,
            PROCESS_INTENT,
            DISK_INTENT,
            NETWORK_INTENT,
            LOGS_INTENT,
        }:
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "summary_intent",
            }

        if _is_path_only_input(cleaned_message):
            if candidate_path and is_under_roots(
                candidate_path, settings.allowed_read_roots
            ):
                return {
                    **base,
                    "route": ROUTE_CLARIFICATION,
                    "kind": "path_clarification",
                    "direct_reply": _path_clarification_reply(candidate_path, language),
                }
            return {
                **base,
                "route": ROUTE_GUIDED_MANUAL_MODE,
                "kind": "path_guidance",
                "guided_reply": _path_guided_reply(
                    candidate_path or cleaned_message, cleaned_message, language
                ),
            }

        if _needs_clarification(cleaned_message):
            return {
                **base,
                "route": ROUTE_CLARIFICATION,
                "kind": "clarification",
                "direct_reply": _ambiguous_input_reply(language),
            }

        if _is_show_quarantine_request(cleaned_message):
            return {**base, "route": ROUTE_TOOL_USE, "kind": "show_quarantine"}

        if _is_find_junk_request(cleaned_message):
            return {**base, "route": ROUTE_TOOL_USE, "kind": "junk_preview"}

        restore_request = _extract_restore_quarantine_request(cleaned_message)
        restore_pattern_match = any(
            p.search(" ".join(cleaned_message.strip().split()))
            for p in RESTORE_QUARANTINE_PATTERNS
        )
        if restore_request:
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "restore_quarantine",
                "payload": restore_request,
            }
        if restore_pattern_match:
            return {
                **base,
                "route": ROUTE_GUIDED_MANUAL_MODE,
                "kind": "restore_quarantine_guidance",
                "guided_reply": _t(
                    language,
                    "Щоб відновити файл з карантину, вкажи `entry_id`.\nПриклад: `restore from quarantine qk-1234abcd`.",
                    "Чтобы восстановить файл из карантина, укажи `entry_id`.\nПример: `restore from quarantine qk-1234abcd`.",
                    "To restore from quarantine, provide the `entry_id`.\nExample: `restore from quarantine qk-1234abcd`.",
                ),
            }

        if _is_antivirus_update_request(cleaned_message):
            provider = _extract_antivirus_provider(cleaned_message)
            arguments: dict[str, Any] = {}
            if provider:
                arguments["provider"] = provider
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "antivirus_update",
                "payload": {
                    "tool_name": "update_antivirus_definitions",
                    "arguments": arguments,
                },
            }

        antivirus_custom = _extract_antivirus_custom_scan_request(cleaned_message)
        antivirus_custom_pattern = any(
            p.search(" ".join(cleaned_message.strip().split()))
            for p in ANTIVIRUS_CUSTOM_SCAN_PATTERNS
        )
        if antivirus_custom:
            scan_path = str(antivirus_custom.get("path") or "")
            if scan_path and not is_under_roots(scan_path, settings.allowed_read_roots):
                return {
                    **base,
                    "route": ROUTE_GUIDED_MANUAL_MODE,
                    "kind": "path_guidance",
                    "recent_path": scan_path,
                    "guided_reply": _path_guided_reply(
                        scan_path, cleaned_message, language
                    ),
                }
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "antivirus_custom_scan",
                "payload": {
                    "tool_name": "run_antivirus_custom_scan",
                    "arguments": antivirus_custom,
                },
            }
        if antivirus_custom_pattern:
            return {
                **base,
                "route": ROUTE_GUIDED_MANUAL_MODE,
                "kind": "antivirus_custom_scan_guidance",
                "guided_reply": _t(
                    language,
                    "Щоб запустити кастомне антивірусне сканування, вкажи шлях.\nПриклад: `проскануй папку C:\\Users\\User\\Downloads`.",
                    "Чтобы запустить кастомное антивирусное сканирование, укажи путь.\nПример: `просканируй папку C:\\Users\\User\\Downloads`.",
                    "To run a custom antivirus scan, provide a path.\nExample: `scan folder C:\\Users\\User\\Downloads`.",
                ),
            }

        if _is_antivirus_threats_request(cleaned_message):
            provider = _extract_antivirus_provider(cleaned_message)
            arguments: dict[str, Any] = {"limit": 20}
            if provider:
                arguments["provider"] = provider
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "antivirus_threats",
                "payload": {
                    "tool_name": "list_antivirus_threats",
                    "arguments": arguments,
                },
            }

        if (
            recent_path
            and _looks_like_operational_request(cleaned_message)
            and not is_under_roots(recent_path, settings.allowed_read_roots)
        ):
            return {
                **base,
                "route": ROUTE_GUIDED_MANUAL_MODE,
                "kind": "path_guidance",
                "recent_path": recent_path,
                "guided_reply": _path_guided_reply(
                    recent_path, cleaned_message, language
                ),
            }

        if _is_antivirus_quick_scan_request(cleaned_message) or (
            "антивірус" in cleaned_message.casefold()
            or "antivirus" in cleaned_message.casefold()
        ):
            provider = _extract_antivirus_provider(cleaned_message)
            arguments: dict[str, Any] = {}
            if provider:
                arguments["provider"] = provider
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "antivirus_detect_or_scan",
                "payload": {
                    "tool_name": "antivirus_quick_scan_or_detect",
                    "arguments": arguments,
                },
            }

        install_req = _extract_install_request(cleaned_message)
        uninstall_req = _extract_uninstall_request(cleaned_message)
        create_dir_req = _extract_create_directory_request(cleaned_message)
        create_file_req = _extract_create_file_request(cleaned_message)
        append_file_req = _extract_append_file_request(cleaned_message)
        replace_file_req = _extract_replace_file_request(cleaned_message)
        copy_path_req = _extract_copy_path_request(cleaned_message)
        move_path_req = _extract_move_path_request(cleaned_message)
        remove_path_req = _extract_remove_path_request(cleaned_message)
        run_prog_req = _extract_run_program_request(cleaned_message)
        move_junk_req = _extract_move_junk_request(cleaned_message)
        delete_junk_req = _extract_delete_junk_request(cleaned_message)

        if install_req:
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "maintenance_or_files",
                "payload": {
                    "tool_name": "pip_install_package",
                    "arguments": install_req,
                },
            }
        if uninstall_req:
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "maintenance_or_files",
                "payload": {
                    "tool_name": "pip_uninstall_package",
                    "arguments": uninstall_req,
                },
            }
        if create_dir_req:
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "maintenance_or_files",
                "payload": {
                    "tool_name": "create_directory",
                    "arguments": create_dir_req,
                },
            }
        if create_file_req:
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "maintenance_or_files",
                "payload": {
                    "tool_name": "create_text_file",
                    "arguments": create_file_req,
                },
            }
        if append_file_req:
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "maintenance_or_files",
                "payload": {
                    "tool_name": "append_text_file",
                    "arguments": append_file_req,
                },
            }
        if replace_file_req:
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "maintenance_or_files",
                "payload": {
                    "tool_name": "edit_text_file",
                    "arguments": replace_file_req,
                },
            }
        if copy_path_req:
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "maintenance_or_files",
                "payload": {
                    "tool_name": "copy_path",
                    "arguments": copy_path_req,
                },
            }
        if move_path_req:
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "maintenance_or_files",
                "payload": {
                    "tool_name": "move_path",
                    "arguments": move_path_req,
                },
            }
        if remove_path_req:
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "maintenance_or_files",
                "payload": {
                    "tool_name": "remove_path",
                    "arguments": remove_path_req,
                },
            }

        if run_prog_req:
            run_path = str(run_prog_req.get("path", ""))
            if not is_under_roots(run_path, settings.allowed_exec_roots):
                return {
                    **base,
                    "route": ROUTE_GUIDED_MANUAL_MODE,
                    "kind": "path_guidance",
                    "recent_path": run_path,
                    "guided_reply": _path_guided_reply(
                        run_path, cleaned_message, language
                    ),
                }
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "maintenance_or_files",
                "payload": {"tool_name": "run_program", "arguments": run_prog_req},
            }

        if move_junk_req:
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "maintenance_or_files",
                "payload": {
                    "tool_name": "move_junk_to_quarantine",
                    "arguments": move_junk_req,
                },
            }
        if any(
            p.search(" ".join(cleaned_message.strip().split()))
            for p in MOVE_JUNK_PATTERNS
        ):
            return {
                **base,
                "route": ROUTE_GUIDED_MANUAL_MODE,
                "kind": "junk_guided",
                "guided_reply": _guided_move_junk_reply(language),
            }

        if delete_junk_req:
            return {
                **base,
                "route": ROUTE_TOOL_USE,
                "kind": "maintenance_or_files",
                "payload": {
                    "tool_name": "delete_junk_files",
                    "arguments": delete_junk_req,
                },
            }
        if any(
            p.search(" ".join(cleaned_message.strip().split()))
            for p in DELETE_JUNK_PATTERNS
        ):
            return {
                **base,
                "route": ROUTE_GUIDED_MANUAL_MODE,
                "kind": "junk_guided",
                "guided_reply": _guided_delete_junk_reply(language),
            }

        if _looks_like_software_path_request(cleaned_message, recent_path):
            if candidate_path and not is_under_roots(
                candidate_path, settings.allowed_read_roots
            ):
                return {
                    **base,
                    "route": ROUTE_GUIDED_MANUAL_MODE,
                    "kind": "path_guidance",
                    "recent_path": candidate_path,
                    "guided_reply": _path_guided_reply(
                        candidate_path, cleaned_message, language
                    ),
                }
            if candidate_path:
                return {
                    **base,
                    "route": ROUTE_TOOL_USE,
                    "kind": "path_context",
                    "planning_note": (
                        "The user mentioned a likely software path inside the allowed roots. "
                        "Inspect it with list_directory or read_file if that helps answer the request."
                    ),
                }
        if (
            recent_path
            and _looks_like_operational_request(cleaned_message)
            and not is_under_roots(recent_path, settings.allowed_read_roots)
        ):
            return {
                **base,
                "route": ROUTE_GUIDED_MANUAL_MODE,
                "kind": "path_guidance",
                "recent_path": recent_path,
                "guided_reply": _path_guided_reply(
                    recent_path, cleaned_message, language
                ),
            }

        planner = self._plan_with_llm(cleaned_message, language)
        if planner is not None:
            return {**base, **planner}

        if _looks_like_system_request(cleaned_message):
            return {**base, "route": ROUTE_TOOL_USE, "kind": "open_ended"}

        return {**base, "route": ROUTE_DIRECT_RESPONSE, "kind": "direct_chat"}

    def _handle_direct_response(self, classification: dict[str, Any]) -> str:
        kind = classification.get("kind")
        cleaned_message = classification.get("cleaned_message") or ""
        language = classification.get("language") or LANG_UK
        control_action = classification.get("control_action")
        control_id = classification.get("control_id")
        direct_reply = classification.get("direct_reply")

        if kind == "control":
            if control_action == "pending":
                reply = self._pending_action_reminder(language)
            elif control_action == "history":
                reply = self._history_actions_report(control_id, language)
            elif control_action == "last":
                reply = self._last_action_report(language)
            elif control_action == "approve":
                reply = self._approve_pending_action(
                    action_id=control_id, lang=language
                )
            else:
                reply = self._cancel_pending_action(action_id=control_id, lang=language)
            self._record_response(cleaned_message, reply)
            return reply

        if kind == "help_menu":
            self._awaiting_help_menu = True

        if direct_reply:
            self._record_response(cleaned_message, direct_reply)
            return direct_reply

        self._history.append({"role": "user", "content": cleaned_message})
        try:
            reply = self._run_direct_response_llm(cleaned_message, language)
        except Exception as exc:
            reply = self._friendly_runtime_error(exc, language)
        self._history.append({"role": "assistant", "content": reply})
        return reply

    def _handle_clarification(self, classification: dict[str, Any]) -> str:
        reply = classification.get("direct_reply") or ""
        cleaned_message = classification.get("cleaned_message") or ""
        self._record_response(cleaned_message, reply)
        return reply

    def _handle_tool_use(self, classification: dict[str, Any], stream: bool = False) -> str:
        kind = classification.get("kind")
        cleaned_message = classification.get("cleaned_message") or ""
        normalized_message = classification.get("normalized_message") or cleaned_message
        payload = classification.get("payload")
        language = classification.get("language") or LANG_UK
        planning_note = classification.get("planning_note")

        if kind == "summary_intent":
            if normalized_message == DIAGNOSTIC_INTENT:
                report = _deterministic_diagnostic_report(
                    self.scanner, self.inspector, language
                )
            elif normalized_message == PROCESS_INTENT:
                report = _deterministic_process_report(self.scanner, language)
            elif normalized_message == DISK_INTENT:
                report = _deterministic_disk_report(self.scanner, language)
            elif normalized_message == NETWORK_INTENT:
                report = _deterministic_network_report(self.scanner, language)
            else:
                report = _deterministic_logs_report(language, limit=5)
            self._record_response(normalized_message, report)
            return report

        if kind == "show_quarantine":
            report = _deterministic_quarantine_report(language, limit=20)
            self._record_response(cleaned_message, report)
            return report

        if kind == "junk_preview":
            report = _deterministic_junk_preview_report(cleaned_message, language)
            self._record_response(cleaned_message, report)
            return report

        if kind == "restore_quarantine" and payload:
            missing = _missing_quarantine_entries(
                [str(eid).lower() for eid in payload.get("entry_ids", [])]
            )
            if missing:
                msg = _t(
                    language,
                    "Не знайшов такі ID записів у карантині: "
                    + ", ".join(f"`{e}`" for e in missing)
                    + ". Спочатку виконай `show quarantine`.",
                    "Не нашел такие ID записей в карантине: "
                    + ", ".join(f"`{e}`" for e in missing)
                    + ". Сначала выполни `show quarantine`.",
                    "I could not find these quarantine entry ids: "
                    + ", ".join(f"`{e}`" for e in missing)
                    + ". Run `show quarantine` first.",
                )
                self._record_response(cleaned_message, msg)
                return msg
            response = self._queue_pending_action(
                tool_name="restore_from_quarantine",
                arguments=payload,
                note="Deterministic maintenance intent: restore from quarantine.",
                lang=language,
            )
            self._record_response(cleaned_message, response)
            return response

        if kind == "antivirus_threats" and payload:
            args = payload.get("arguments") or {}
            result = list_antivirus_threats(**args)
            report = _format_antivirus_threats_report(result, language)
            self._record_response(cleaned_message, report)
            return report

        if kind == "antivirus_detect_or_scan":
            detection = detect_antivirus()
            if not detection.get("available"):
                report = _deterministic_antivirus_detect_report(language)
                self._record_response(cleaned_message, report)
                return report
            provider_args = (payload or {}).get("arguments") or {}
            response = self._queue_pending_action(
                tool_name="run_antivirus_quick_scan",
                arguments=provider_args,
                note="Deterministic antivirus intent: quick scan.",
                lang=language,
            )
            self._record_response(cleaned_message, response)
            return response

        if kind in {
            "antivirus_update",
            "antivirus_custom_scan",
            "maintenance_or_files",
        }:
            if payload:
                response = self._queue_pending_action(
                    tool_name=payload.get("tool_name", ""),
                    arguments=payload.get("arguments") or {},
                    note=f"Deterministic maintenance intent: {payload.get('tool_name', '')}.",
                    lang=language,
                )
                self._record_response(normalized_message, response)
                return response

        self._history.append({"role": "user", "content": normalized_message})
        try:
            reply = self._run_agent_loop(language=language, planning_note=planning_note, stream=stream)
        except Exception as exc:
            reply = self._friendly_runtime_error(exc, language)
        else:
            reply = self._postprocess_reply(reply, language)
        self._history.append({"role": "assistant", "content": reply})
        return reply

    def _handle_guided_manual_mode(self, classification: dict[str, Any]) -> str:
        cleaned_message = classification.get("cleaned_message") or ""
        language = classification.get("language") or LANG_UK
        reply = classification.get("guided_reply")
        if not reply:
            reply = self._run_guided_manual_llm(cleaned_message, language)
        self._record_response(cleaned_message, reply)
        return reply

    def _run_direct_response_llm(self, message: str, lang: str) -> str:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "system",
                "content": f"{DIRECT_RESPONSE_PROMPT}\nReply in {_language_name(lang)}.",
            },
            *(
                [{"role": "system", "content": UNSAFE_FULL_ACCESS_PROMPT}]
                if settings.unsafe_full_access
                else []
            ),
            *self._history,
            {"role": "user", "content": message},
        ]
        response = self.client.chat(messages=messages, tools=None)
        return response.get("assistant_message", {}).get("content", "").strip() or _t(
            lang,
            "Не вдалося сформувати відповідь.",
            "Не удалось сформировать ответ.",
            "Could not produce a response.",
        )

    def _run_guided_manual_llm(self, message: str, lang: str) -> str:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "system",
                "content": f"{GUIDED_MANUAL_PROMPT}\nReply in {_language_name(lang)}.",
            },
            *(
                [{"role": "system", "content": UNSAFE_FULL_ACCESS_PROMPT}]
                if settings.unsafe_full_access
                else []
            ),
            {"role": "user", "content": message},
        ]
        response = self.client.chat(messages=messages, tools=None)
        return response.get("assistant_message", {}).get("content", "").strip() or _t(
            lang,
            "Я не можу виконати це напряму, але можу підказати безпечний ручний наступний крок.",
            "Я не могу выполнить это напрямую, но могу подсказать безопасный ручной следующий шаг.",
            "I cannot do that directly, but I can suggest the safest manual next step.",
        )

    def _plan_with_llm(self, message: str, lang: str) -> Optional[dict[str, Any]]:
        tool_names = ", ".join(tool.name for tool in self.tool_registry)
        messages = [
            {"role": "system", "content": PLANNER_PROMPT},
            *(
                [{"role": "system", "content": UNSAFE_FULL_ACCESS_PROMPT}]
                if settings.unsafe_full_access
                else []
            ),
            {
                "role": "user",
                "content": (
                    f"User language: {_language_name(lang)}\n"
                    f"Platform: {platform.system()}\n"
                    f"Allowed read roots: {', '.join(settings.allowed_read_roots)}\n"
                    f"Allowed exec roots: {', '.join(settings.allowed_exec_roots)}\n"
                    f"Unsafe full access mode: {'on' if settings.unsafe_full_access else 'off'}\n"
                    f"Available tools: {tool_names}\n"
                    f"Latest user message: {message}"
                ),
            },
        ]
        try:
            response = self.client.chat(messages=messages, tools=None)
        except Exception:
            return None

        content = response.get("assistant_message", {}).get("content", "").strip()
        if not content:
            return None

        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", content, re.DOTALL)
            if not match:
                return None
            try:
                payload = json.loads(match.group(0))
            except json.JSONDecodeError:
                return None

        route = payload.get("route")
        if route not in {
            ROUTE_DIRECT_RESPONSE,
            ROUTE_CLARIFICATION,
            ROUTE_TOOL_USE,
            ROUTE_GUIDED_MANUAL_MODE,
        }:
            return None

        normalized = payload.get("normalized_user_request")
        if route == ROUTE_TOOL_USE:
            return {
                "route": route,
                "kind": "open_ended",
                "normalized_message": normalized or message,
            }

        reply = str(payload.get("reply") or "").strip()
        if not reply:
            return None

        if route == ROUTE_GUIDED_MANUAL_MODE:
            return {"route": route, "kind": "guided_manual", "guided_reply": reply}

        return {"route": route, "kind": "planned_reply", "direct_reply": reply}

    def _record_response(self, user_content: str, reply: str) -> None:
        self._history.append({"role": "user", "content": user_content})
        if reply:
            self._history.append({"role": "assistant", "content": reply})

    def _is_timeout_error(self, exc: Exception) -> bool:
        lowered = str(exc).casefold()
        return "timed out" in lowered or "timeout" in lowered

    def handle_user_message(self, message: str, stream: bool = False) -> str:
        classification = self.classify_request(message)
        route = classification.get("route")

        if route == ROUTE_DIRECT_RESPONSE:
            return self._handle_direct_response(classification)
        if route == ROUTE_CLARIFICATION:
            return self._handle_clarification(classification)
        if route == ROUTE_TOOL_USE:
            return self._handle_tool_use(classification, stream=stream)
        if route == ROUTE_GUIDED_MANUAL_MODE:
            return self._handle_guided_manual_mode(classification)
        return ""

    def reset(self) -> None:
        self._bootstrap()

    def _bootstrap(self) -> None:
        snapshot = _build_snapshot_context(self.scanner, self.inspector)
        self._awaiting_help_menu = False
        self._history = [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "bootstrap_snapshot",
                        "type": "function",
                        "function": {
                            "name": "get_system_snapshot",
                            "arguments": "{}",
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "bootstrap_snapshot",
                "content": json.dumps(snapshot, ensure_ascii=False, indent=2),
            },
        ]

    def _run_agent_loop(
        self, *, language: str, planning_note: Optional[str] = None, stream: bool = False
    ) -> str:
        messages = self._full_messages(language=language, planning_note=planning_note)

        for _ in range(settings.max_tool_steps):
            response = self.client.chat(messages=messages, tools=self.schemas, stream=stream)
            assistant_message = response.get("assistant_message", {})
            tool_call = response.get("tool_call")

            if not tool_call:
                content = assistant_message.get("content") or _t(
                    language,
                    "Відповідь не згенерована.",
                    "Ответ не сгенерирован.",
                    "No response was generated.",
                )
                # Add newline after streaming completes
                if stream:
                    print()
                return content

            tool_call_id = response.get("tool_call_id") or "call_0"
            messages.append(
                {
                    "role": "assistant",
                    "content": assistant_message.get("content", ""),
                    "tool_calls": [
                        {
                            "id": tool_call_id,
                            "type": "function",
                            "function": {
                                "name": tool_call["name"],
                                "arguments": json.dumps(tool_call.get("arguments", {})),
                            },
                        }
                    ],
                }
            )

            tool_name = tool_call["name"]
            tool_arguments = tool_call.get("arguments", {})

            if tool_name in MUTATING_TOOLS and self._requires_confirmation(tool_name):
                return self._queue_pending_action(
                    tool_name=tool_name,
                    arguments=tool_arguments,
                    note="Awaiting explicit user confirmation.",
                    lang=language,
                )

            # Show tool execution indicator in streaming mode
            if stream:
                print(f"\n\n🔧 Using tool: {tool_name}...", flush=True)

            tool_result = execute_tool(tool_name, tool_arguments, self.tool_registry)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tool_call_id,
                    "content": tool_result,
                }
            )

        return _t(
            language,
            "Досягнуто ліміт кроків діагностики. Уточни, будь ласка, запит.",
            "Достигнут лимит шагов диагностики. Пожалуйста, уточни запрос.",
            "The diagnostic step limit was reached. Please refine the request.",
        )

    def _full_messages(
        self, *, language: str, planning_note: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        extra_system = [
            {"role": "system", "content": f"Reply in {_language_name(language)}."}
        ]
        if settings.unsafe_full_access:
            extra_system.append(
                {"role": "system", "content": UNSAFE_FULL_ACCESS_PROMPT}
            )
        if planning_note:
            extra_system.append({"role": "system", "content": planning_note})
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            *extra_system,
            *self._history,
        ]

    def _friendly_runtime_error(self, exc: Exception, lang: str) -> str:
        text = str(exc).strip()
        lowered = text.casefold()
        if self._is_ollama_unavailable_error(exc) or (
            ("timed out" in lowered or "timeout" in lowered)
            and self._is_ollama_server_unreachable()
        ):
            base_url = getattr(self.client, "base_url", settings.llm_url)
            return _t(
                lang,
                "Не вдається підключитися до локального LLM (Ollama).\n"
                f"- Адреса: {base_url}\n"
                "- Переконайся, що Ollama запущений.\n"
                "- Можеш перевірити командою: `python main.py --healthcheck`\n"
                "- Поки Ollama недоступний, спробуй deterministic запити: `привіт`, `діагностика ПК`, `процеси`, `покажи що в карантині`.",
                "Не удается подключиться к локальному LLM (Ollama).\n"
                f"- Адрес: {base_url}\n"
                "- Убедись, что Ollama запущен.\n"
                "- Можешь проверить командой: `python main.py --healthcheck`\n"
                "- Пока Ollama недоступен, попробуй deterministic запросы: `привет`, `діагностика ПК`, `процеси`, `покажи що в карантині`.",
                "Could not connect to the local LLM (Ollama).\n"
                f"- Address: {base_url}\n"
                "- Make sure Ollama is running.\n"
                "- You can check it with: `python main.py --healthcheck`\n"
                "- While Ollama is unavailable, try deterministic requests such as `hello`, `PC diagnostics`, `processes`, or `show quarantine`.",
            )
        if "timed out" in lowered or "timeout" in lowered:
            return _t(
                lang,
                "LLM не встиг відповісти в межах timeout.\nСпробуй коротший або конкретніший запит, наприклад:\n- help\n- діагностика ПК\n- процеси",
                "LLM не успел ответить в пределах timeout.\nПопробуй более короткий или конкретный запрос, например:\n- help\n- диагностика ПК\n- процессы",
                "The LLM timed out.\nTry a shorter or more specific request, for example:\n- help\n- PC diagnostics\n- processes",
            )
        return _t(
            lang,
            f"Не вдалося завершити запит: {text}",
            f"Не удалось завершить запрос: {text}",
            f"Could not complete the request: {text}",
        )

    def _is_ollama_unavailable_error(self, exc: Exception) -> bool:
        lowered = str(exc).casefold()
        markers = (
            "winerror 10061",
            "connection refused",
            "connecterror",
            "all connection attempts failed",
            "failed to establish a new connection",
            "nodename nor servname provided",
            "temporary failure in name resolution",
        )
        return any(marker in lowered for marker in markers)

    def _is_ollama_server_unreachable(self) -> bool:
        probe = getattr(self.client, "server_check", None)
        if not callable(probe):
            return False
        try:
            result = probe(timeout=3)
        except Exception:
            return False
        return not bool(result.get("reachable"))

    def _postprocess_reply(self, reply: str, lang: str) -> str:
        model_name = getattr(self.client, "model", "")
        if not str(model_name).startswith("llama3.2"):
            return reply
        if not _looks_mixed_language(reply):
            return reply

        rewrite_messages = [
            {
                "role": "system",
                "content": (
                    f"Rewrite the text in {_language_name(lang)} only. "
                    "Do not add facts, do not change the meaning, and remove mixed-language phrasing. "
                    "Keep it concise."
                ),
            },
            {"role": "user", "content": reply},
        ]

        try:
            rewritten = self.client.chat(messages=rewrite_messages, tools=None)
        except Exception:
            return reply

        candidate = rewritten.get("assistant_message", {}).get("content", "").strip()
        return candidate or reply

    def _requires_confirmation(self, tool_name: str) -> bool:
        if settings.unsafe_full_access:
            return False
        if tool_name == "run_program":
            return settings.require_confirmation_for_exec
        if tool_name in {
            "run_shell_command",
            "run_antivirus_quick_scan",
            "update_antivirus_definitions",
            "run_antivirus_custom_scan",
        }:
            return settings.require_confirmation_for_exec
        if tool_name in {"pip_install_package", "pip_uninstall_package"}:
            return settings.require_confirmation_for_package_changes
        if tool_name in {"move_junk_to_quarantine", "delete_junk_files"}:
            return settings.require_confirmation_for_delete
        if tool_name == "restore_from_quarantine":
            return settings.require_confirmation_for_file_edits
        if tool_name in {
            "create_directory",
            "create_text_file",
            "write_text_file",
            "append_text_file",
            "edit_text_file",
        }:
            return settings.require_confirmation_for_file_edits
        return False

    def _action_risk(self, tool_name: str) -> str:
        if tool_name in {"pip_uninstall_package", "delete_junk_files", "remove_path"}:
            return "high"
        if tool_name in {
            "copy_path",
            "move_path",
            "run_program",
            "run_shell_command",
            "run_antivirus_quick_scan",
            "update_antivirus_definitions",
            "run_antivirus_custom_scan",
            "pip_install_package",
            "move_junk_to_quarantine",
            "restore_from_quarantine",
            "create_directory",
            "create_text_file",
            "write_text_file",
            "append_text_file",
            "edit_text_file",
        }:
            return "medium"
        return "low"

    def _build_action_summary(
        self, tool_name: str, arguments: dict[str, Any], lang: str
    ) -> str:
        if tool_name == "copy_path":
            return _t(lang, "Копіювання шляху", "Копирование пути", "Copy path")
        if tool_name == "move_path":
            return _t(lang, "Переміщення шляху", "Перемещение пути", "Move path")
        if tool_name == "remove_path":
            return _t(lang, "Видалення шляху", "Удаление пути", "Remove path")
        if tool_name == "run_program":
            return _t(lang, "Запуск програми", "Запуск программы", "Program launch")
        if tool_name == "run_shell_command":
            return _t(
                lang,
                "Виконання shell-команди",
                "Выполнение shell-команды",
                "Shell command execution",
            )
        if tool_name == "run_antivirus_quick_scan":
            return _t(
                lang,
                "Швидке антивірусне сканування",
                "Быстрое антивирусное сканирование",
                "Quick antivirus scan",
            )
        if tool_name == "update_antivirus_definitions":
            return _t(
                lang,
                "Оновлення антивірусних баз",
                "Обновление антивирусных баз",
                "Antivirus definitions update",
            )
        if tool_name == "run_antivirus_custom_scan":
            return _t(
                lang,
                "Кастомне антивірусне сканування",
                "Кастомное антивирусное сканирование",
                "Custom antivirus scan",
            )
        if tool_name == "pip_install_package":
            return _t(
                lang,
                "Встановлення Python-пакета",
                "Установка Python-пакета",
                "Python package install",
            )
        if tool_name == "pip_uninstall_package":
            return _t(
                lang,
                "Видалення Python-пакета",
                "Удаление Python-пакета",
                "Python package uninstall",
            )
        if tool_name == "move_junk_to_quarantine":
            return _t(
                lang,
                "Переміщення сміття в карантин",
                "Перемещение мусора в карантин",
                "Move junk to quarantine",
            )
        if tool_name == "restore_from_quarantine":
            return _t(
                lang,
                "Відновлення з карантину",
                "Восстановление из карантина",
                "Restore from quarantine",
            )
        if tool_name == "delete_junk_files":
            return _t(lang, "Видалення сміття", "Удаление мусора", "Delete junk")
        if tool_name == "create_directory":
            return _t(
                lang,
                "Створення директорії",
                "Создание директории",
                "Create directory",
            )
        if tool_name in {"create_text_file", "write_text_file", "append_text_file"}:
            return _t(
                lang,
                "Запис текстового файла",
                "Запись текстового файла",
                "Write text file",
            )
        if tool_name == "edit_text_file":
            return _t(
                lang,
                "Редагування текстового файла",
                "Редактирование текстового файла",
                "Edit text file",
            )
        return _t(
            lang,
            f"Виконання дії `{tool_name}`",
            f"Выполнение действия `{tool_name}`",
            f"Execute `{tool_name}`",
        )

    def _build_action_plan(
        self, tool_name: str, arguments: dict[str, Any], lang: str
    ) -> list[str]:
        risk = self._action_risk(tool_name)
        if tool_name == "copy_path":
            source = arguments.get("source", "<missing>")
            destination = arguments.get("destination", "<missing>")
            overwrite = bool(arguments.get("overwrite", False))
            return [
                _t(
                    lang,
                    "Що: копіювання файла або папки.",
                    "Что: копирование файла или папки.",
                    "What: copy a file or directory.",
                ),
                _t(
                    lang,
                    f"Звідки: `{source}`.",
                    f"Откуда: `{source}`.",
                    f"Source: `{source}`.",
                ),
                _t(
                    lang,
                    f"Куди: `{destination}`.",
                    f"Куда: `{destination}`.",
                    f"Destination: `{destination}`.",
                ),
                _t(
                    lang,
                    f"Overwrite: {'так' if overwrite else 'ні'}.",
                    f"Overwrite: {'да' if overwrite else 'нет'}.",
                    f"Overwrite: {'yes' if overwrite else 'no'}.",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "move_path":
            source = arguments.get("source", "<missing>")
            destination = arguments.get("destination", "<missing>")
            overwrite = bool(arguments.get("overwrite", False))
            return [
                _t(
                    lang,
                    "Що: переміщення або перейменування файла чи папки.",
                    "Что: перемещение или переименование файла или папки.",
                    "What: move or rename a file or directory.",
                ),
                _t(
                    lang,
                    f"Звідки: `{source}`.",
                    f"Откуда: `{source}`.",
                    f"Source: `{source}`.",
                ),
                _t(
                    lang,
                    f"Куди: `{destination}`.",
                    f"Куда: `{destination}`.",
                    f"Destination: `{destination}`.",
                ),
                _t(
                    lang,
                    f"Overwrite: {'так' if overwrite else 'ні'}.",
                    f"Overwrite: {'да' if overwrite else 'нет'}.",
                    f"Overwrite: {'yes' if overwrite else 'no'}.",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "remove_path":
            path = arguments.get("path", "<missing>")
            recursive = bool(arguments.get("recursive", False))
            return [
                _t(
                    lang,
                    "Що: видалення локального файла або папки.",
                    "Что: удаление локального файла или папки.",
                    "What: remove a local file or directory.",
                ),
                _t(lang, f"Шлях: `{path}`.", f"Путь: `{path}`.", f"Path: `{path}`."),
                _t(
                    lang,
                    f"Рекурсивно: {'так' if recursive else 'ні'}.",
                    f"Рекурсивно: {'да' if recursive else 'нет'}.",
                    f"Recursive: {'yes' if recursive else 'no'}.",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "run_program":
            path = arguments.get("path", "<missing>")
            args = arguments.get("args") or []
            cwd = arguments.get("cwd") or _t(
                lang,
                "папка виконуваного файла",
                "папка исполняемого файла",
                "the executable folder",
            )
            timeout = arguments.get("timeout") or "120"
            return [
                _t(
                    lang,
                    "Що: запуск зовнішньої програми.",
                    "Что: запуск внешней программы.",
                    "What: launch an external program.",
                ),
                _t(lang, f"Файл: `{path}`.", f"Файл: `{path}`.", f"File: `{path}`."),
                _t(
                    lang,
                    f"Аргументи: {self._format_cli_args(args, lang)}.",
                    f"Аргументы: {self._format_cli_args(args, lang)}.",
                    f"Arguments: {self._format_cli_args(args, lang)}.",
                ),
                _t(
                    lang,
                    f"Робоча папка: `{cwd}`.",
                    f"Рабочая папка: `{cwd}`.",
                    f"Working directory: `{cwd}`.",
                ),
                _t(
                    lang,
                    f"Таймаут: {timeout} с.",
                    f"Таймаут: {timeout} с.",
                    f"Timeout: {timeout} s.",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "run_shell_command":
            shell = arguments.get("shell") or "powershell"
            command = arguments.get("command", "<missing>")
            cwd = arguments.get("cwd") or _t(
                lang,
                "поточна робоча папка",
                "текущая рабочая папка",
                "the current working directory",
            )
            timeout = arguments.get("timeout") or "120"
            return [
                _t(
                    lang,
                    "Що: виконання локальної shell-команди.",
                    "Что: выполнение локальной shell-команды.",
                    "What: execute a local shell command.",
                ),
                _t(
                    lang,
                    f"Shell: `{shell}`.",
                    f"Shell: `{shell}`.",
                    f"Shell: `{shell}`.",
                ),
                _t(
                    lang,
                    f"Команда: `{command}`.",
                    f"Команда: `{command}`.",
                    f"Command: `{command}`.",
                ),
                _t(
                    lang,
                    f"Робоча папка: `{cwd}`.",
                    f"Рабочая папка: `{cwd}`.",
                    f"Working directory: `{cwd}`.",
                ),
                _t(
                    lang,
                    f"Таймаут: {timeout} с.",
                    f"Таймаут: {timeout} с.",
                    f"Timeout: {timeout} s.",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "pip_install_package":
            name = arguments.get("name", "<missing>")
            version = arguments.get("version")
            upgrade = bool(arguments.get("upgrade", False))
            package_text = f"{name}=={version}" if version else str(name)
            return [
                _t(
                    lang,
                    "Що: встановлення Python-пакета.",
                    "Что: установка Python-пакета.",
                    "What: install a Python package.",
                ),
                _t(
                    lang,
                    f"Пакет: `{package_text}`.",
                    f"Пакет: `{package_text}`.",
                    f"Package: `{package_text}`.",
                ),
                _t(
                    lang,
                    f"Режим оновлення: {'так' if upgrade else 'ні'}.",
                    f"Режим обновления: {'да' if upgrade else 'нет'}.",
                    f"Upgrade mode: {'yes' if upgrade else 'no'}.",
                ),
                _t(
                    lang,
                    "Середовище: поточний інтерпретатор (`sys.executable -m pip`).",
                    "Среда: текущий интерпретатор (`sys.executable -m pip`).",
                    "Environment: current interpreter (`sys.executable -m pip`).",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "pip_uninstall_package":
            name = arguments.get("name", "<missing>")
            return [
                _t(
                    lang,
                    "Що: видалення Python-пакета.",
                    "Что: удаление Python-пакета.",
                    "What: uninstall a Python package.",
                ),
                _t(
                    lang,
                    f"Пакет: `{name}`.",
                    f"Пакет: `{name}`.",
                    f"Package: `{name}`.",
                ),
                _t(
                    lang,
                    "Середовище: поточний інтерпретатор (`sys.executable -m pip`).",
                    "Среда: текущий интерпретатор (`sys.executable -m pip`).",
                    "Environment: current interpreter (`sys.executable -m pip`).",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "update_antivirus_definitions":
            provider = arguments.get("provider") or "auto"
            return [
                _t(
                    lang,
                    "Що: оновлення антивірусних сигнатур.",
                    "Что: обновление антивирусных сигнатур.",
                    "What: update antivirus definitions.",
                ),
                _t(
                    lang,
                    f"Провайдер: `{provider}`.",
                    f"Провайдер: `{provider}`.",
                    f"Provider: `{provider}`.",
                ),
                _t(
                    lang,
                    "Система спробує оновити бази через структурований antivirus adapter.",
                    "Система попробует обновить базы через структурированный antivirus adapter.",
                    "The system will try to update definitions through the structured antivirus adapter.",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "run_antivirus_quick_scan":
            provider = arguments.get("provider") or "auto"
            return [
                _t(
                    lang,
                    "Що: запуск швидкого антивірусного сканування.",
                    "Что: запуск быстрого антивирусного сканирования.",
                    "What: start a quick antivirus scan.",
                ),
                _t(
                    lang,
                    f"Провайдер: `{provider}`.",
                    f"Провайдер: `{provider}`.",
                    f"Provider: `{provider}`.",
                ),
                _t(
                    lang,
                    "Сканування буде виконано через структурований antivirus adapter після підтвердження.",
                    "Сканирование будет выполнено через структурированный antivirus adapter после подтверждения.",
                    "The scan will run through the structured antivirus adapter after approval.",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "run_antivirus_custom_scan":
            provider = arguments.get("provider") or "auto"
            scan_path = arguments.get("path", "<missing>")
            return [
                _t(
                    lang,
                    "Що: запуск кастомного антивірусного сканування.",
                    "Что: запуск кастомного антивирусного сканирования.",
                    "What: start a custom antivirus scan.",
                ),
                _t(
                    lang,
                    f"Провайдер: `{provider}`.",
                    f"Провайдер: `{provider}`.",
                    f"Provider: `{provider}`.",
                ),
                _t(
                    lang,
                    f"Шлях сканування: `{scan_path}`.",
                    f"Путь сканирования: `{scan_path}`.",
                    f"Scan path: `{scan_path}`.",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "move_junk_to_quarantine":
            paths = arguments.get("paths") or []
            quarantine_dir = (
                arguments.get("quarantine_dir") or settings.junk_quarantine_dir
            )
            return [
                _t(
                    lang,
                    "Що: переміщення знайденого сміття в карантин.",
                    "Что: перемещение найденного мусора в карантин.",
                    "What: move detected junk into quarantine.",
                ),
                _t(
                    lang,
                    f"Елементів: {len(paths)}.",
                    f"Элементов: {len(paths)}.",
                    f"Items: {len(paths)}.",
                ),
                _t(
                    lang,
                    f"Папка карантину: `{quarantine_dir}`.",
                    f"Папка карантина: `{quarantine_dir}`.",
                    f"Quarantine folder: `{quarantine_dir}`.",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "restore_from_quarantine":
            entry_ids = arguments.get("entry_ids") or []
            destination_root = arguments.get("destination_root") or _t(
                lang,
                "оригінальні шляхи",
                "исходные пути",
                "original paths",
            )
            overwrite = bool(arguments.get("overwrite", False))
            return [
                _t(
                    lang,
                    "Що: відновлення файлів/папок з карантину.",
                    "Что: восстановление файлов/папок из карантина.",
                    "What: restore files or folders from quarantine.",
                ),
                _t(
                    lang,
                    f"ID записів карантину: {', '.join(f'`{entry}`' for entry in entry_ids[:8]) or 'немає'}.",
                    f"ID записей карантина: {', '.join(f'`{entry}`' for entry in entry_ids[:8]) or 'нет'}.",
                    f"Entry IDs: {', '.join(f'`{entry}`' for entry in entry_ids[:8]) or 'none'}.",
                ),
                _t(
                    lang,
                    f"Куди: `{destination_root}`.",
                    f"Куда: `{destination_root}`.",
                    f"Destination: `{destination_root}`.",
                ),
                _t(
                    lang,
                    f"Перезапис: {'так' if overwrite else 'ні'}.",
                    f"Перезапись: {'да' if overwrite else 'нет'}.",
                    f"Overwrite: {'yes' if overwrite else 'no'}.",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "delete_junk_files":
            paths = arguments.get("paths") or []
            recursive = bool(arguments.get("recursive", False))
            return [
                _t(
                    lang,
                    "Що: безповоротне видалення файлів/папок сміття.",
                    "Что: безвозвратное удаление файлов/папок мусора.",
                    "What: permanently delete junk files or folders.",
                ),
                _t(
                    lang,
                    f"Елементів: {len(paths)}.",
                    f"Элементов: {len(paths)}.",
                    f"Items: {len(paths)}.",
                ),
                _t(
                    lang,
                    f"Рекурсивно: {'так' if recursive else 'ні'}.",
                    f"Рекурсивно: {'да' if recursive else 'нет'}.",
                    f"Recursive: {'yes' if recursive else 'no'}.",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "create_directory":
            return [
                _t(
                    lang,
                    "Що: створення директорії.",
                    "Что: создание директории.",
                    "What: create a directory.",
                ),
                _t(
                    lang,
                    f"Шлях: `{arguments.get('path', '<missing>')}`.",
                    f"Путь: `{arguments.get('path', '<missing>')}`.",
                    f"Path: `{arguments.get('path', '<missing>')}`.",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "create_text_file":
            return [
                _t(
                    lang,
                    "Що: створення текстового файла.",
                    "Что: создание текстового файла.",
                    "What: create a text file.",
                ),
                _t(
                    lang,
                    f"Шлях: `{arguments.get('path', '<missing>')}`.",
                    f"Путь: `{arguments.get('path', '<missing>')}`.",
                    f"Path: `{arguments.get('path', '<missing>')}`.",
                ),
                _t(
                    lang,
                    f"Розмір контенту: {len(str(arguments.get('content', '')))} символів.",
                    f"Размер содержимого: {len(str(arguments.get('content', '')))} символов.",
                    f"Content size: {len(str(arguments.get('content', '')))} characters.",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "write_text_file":
            overwrite = bool(arguments.get("overwrite", False))
            return [
                _t(
                    lang,
                    "Що: повний перезапис текстового файла.",
                    "Что: полная перезапись текстового файла.",
                    "What: fully rewrite a text file.",
                ),
                _t(
                    lang,
                    f"Шлях: `{arguments.get('path', '<missing>')}`.",
                    f"Путь: `{arguments.get('path', '<missing>')}`.",
                    f"Path: `{arguments.get('path', '<missing>')}`.",
                ),
                _t(
                    lang,
                    f"Перезапис: {'так' if overwrite else 'ні'}.",
                    f"Перезапись: {'да' if overwrite else 'нет'}.",
                    f"Overwrite: {'yes' if overwrite else 'no'}.",
                ),
                _t(
                    lang,
                    f"Розмір контенту: {len(str(arguments.get('content', '')))} символів.",
                    f"Размер содержимого: {len(str(arguments.get('content', '')))} символов.",
                    f"Content size: {len(str(arguments.get('content', '')))} characters.",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "append_text_file":
            return [
                _t(
                    lang,
                    "Що: додавання тексту в кінець файла.",
                    "Что: добавление текста в конец файла.",
                    "What: append text to a file.",
                ),
                _t(
                    lang,
                    f"Шлях: `{arguments.get('path', '<missing>')}`.",
                    f"Путь: `{arguments.get('path', '<missing>')}`.",
                    f"Path: `{arguments.get('path', '<missing>')}`.",
                ),
                _t(
                    lang,
                    f"Розмір доданого контенту: {len(str(arguments.get('content', '')))} символів.",
                    f"Размер добавленного содержимого: {len(str(arguments.get('content', '')))} символов.",
                    f"Appended content size: {len(str(arguments.get('content', '')))} characters.",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        if tool_name == "edit_text_file":
            return [
                _t(
                    lang,
                    "Що: точкове редагування текстового файла.",
                    "Что: точечное редактирование текстового файла.",
                    "What: edit a specific text fragment in a file.",
                ),
                _t(
                    lang,
                    f"Шлях: `{arguments.get('path', '<missing>')}`.",
                    f"Путь: `{arguments.get('path', '<missing>')}`.",
                    f"Path: `{arguments.get('path', '<missing>')}`.",
                ),
                _t(
                    lang,
                    f"Знайти: `{arguments.get('find_text', '')}`.",
                    f"Найти: `{arguments.get('find_text', '')}`.",
                    f"Find: `{arguments.get('find_text', '')}`.",
                ),
                _t(
                    lang,
                    f"Замінити на: `{arguments.get('replace_text', '')}`.",
                    f"Заменить на: `{arguments.get('replace_text', '')}`.",
                    f"Replace with: `{arguments.get('replace_text', '')}`.",
                ),
                _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
            ]

        return [
            _t(
                lang,
                f"Що: виконання `{tool_name}`.",
                f"Что: выполнение `{tool_name}`.",
                f"What: run `{tool_name}`.",
            ),
            _t(
                lang,
                f"Аргументи: {json.dumps(arguments, ensure_ascii=False)}.",
                f"Аргументы: {json.dumps(arguments, ensure_ascii=False)}.",
                f"Arguments: {json.dumps(arguments, ensure_ascii=False)}.",
            ),
            _t(lang, f"Ризик: {risk}.", f"Риск: {risk}.", f"Risk: {risk}."),
        ]

    def _format_cli_args(self, args: list[Any], lang: str) -> str:
        if not args:
            return _t(lang, "без аргументів", "без аргументов", "no arguments")
        formatted = [f"`{str(arg)}`" for arg in args[:8]]
        if len(args) > 8:
            formatted.append("...")
        return " ".join(formatted)

    def _execute_action_now(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        note: str,
        lang: str,
    ) -> str:
        action = PendingAction(
            id=f"direct-{uuid.uuid4().hex[:8]}",
            action_type="mutation",
            tool_name=tool_name,
            arguments=arguments,
            summary=self._build_action_summary(tool_name, arguments, lang),
            risk=self._action_risk(tool_name),
            plan=self._build_action_plan(tool_name, arguments, lang),
        )
        log_action_event("executed_direct", action=action, note=note)
        tool_result = execute_tool(tool_name, arguments, self.tool_registry)
        decoded_result = self._decode_tool_result(tool_result)
        log_action_event(
            "executed_direct_result",
            action=action,
            result=decoded_result,
            note="Unsafe full access direct execution.",
        )
        result_summary = self._execution_result_summary(decoded_result, lang)
        return _t(
            lang,
            "Unsafe full access mode: виконую дію без approval-gate.\n"
            f"- Дія: {action.summary}\n"
            f"- Ризик: {action.risk}\n\n"
            f"Підсумок: {result_summary}\n"
            f"Лог: `{settings.action_audit_log_path}`\n\n"
            "Результат:\n"
            f"{tool_result}",
            "Unsafe full access mode: выполняю действие без approval-gate.\n"
            f"- Действие: {action.summary}\n"
            f"- Риск: {action.risk}\n\n"
            f"Итог: {result_summary}\n"
            f"Лог: `{settings.action_audit_log_path}`\n\n"
            "Результат:\n"
            f"{tool_result}",
            "Unsafe full access mode: executing the action without approval gating.\n"
            f"- Action: {action.summary}\n"
            f"- Risk: {action.risk}\n\n"
            f"Summary: {result_summary}\n"
            f"Log: `{settings.action_audit_log_path}`\n\n"
            "Result:\n"
            f"{tool_result}",
        )

    def _queue_pending_action(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        note: str,
        lang: str,
    ) -> str:
        if not self._requires_confirmation(tool_name):
            return self._execute_action_now(
                tool_name=tool_name,
                arguments=arguments,
                note=note,
                lang=lang,
            )

        if self.approval.has_pending():
            existing = self.approval.pending
            if existing is not None:
                log_action_event(
                    "pending_rejected_existing",
                    action=existing,
                    note=(
                        "Rejected new pending action because another action is still open: "
                        f"{tool_name}"
                    ),
                )
            return self._pending_action_reminder(lang)

        plan = self._build_action_plan(tool_name, arguments, lang)
        try:
            pending = self.approval.create(
                action_type="mutation",
                tool_name=tool_name,
                arguments=arguments,
                summary=self._build_action_summary(tool_name, arguments, lang),
                risk=self._action_risk(tool_name),
                plan=plan,
            )
        except PendingActionExistsError as exc:
            log_action_event(
                "pending_rejected_existing",
                action=exc.pending,
                note=(
                    "Rejected new pending action due to race/parallel create: "
                    f"{tool_name}"
                ),
            )
            return self._pending_action_reminder(lang)

        log_action_event("pending_created", action=pending, note=note)
        return self._pending_action_message(pending, lang)

    def _pending_action_message(self, pending: PendingAction, lang: str) -> str:
        plan_lines = pending.plan or [
            _t(
                lang,
                f"Дія: {pending.summary}.",
                f"Действие: {pending.summary}.",
                f"Action: {pending.summary}.",
            )
        ]
        plan_block = "\n".join(f"- {line}" for line in plan_lines)
        return _t(
            lang,
            "Потрібне підтвердження перед зміною системи.\n"
            f"- ID дії: {pending.id}\n"
            f"- Ризик: {pending.risk}\n"
            f"{plan_block}\n"
            f"Підтвердити: `approve {pending.id}`\n"
            f"Скасувати: `cancel {pending.id}`\n"
            "Переглянути поточну дію: `pending`",
            "Нужно подтверждение перед изменением системы.\n"
            f"- ID действия: {pending.id}\n"
            f"- Риск: {pending.risk}\n"
            f"{plan_block}\n"
            f"Подтвердить: `approve {pending.id}`\n"
            f"Отменить: `cancel {pending.id}`\n"
            "Посмотреть текущее действие: `pending`",
            "Confirmation is required before changing the system.\n"
            f"- Action ID: {pending.id}\n"
            f"- Risk: {pending.risk}\n"
            f"{plan_block}\n"
            f"Approve: `approve {pending.id}`\n"
            f"Cancel: `cancel {pending.id}`\n"
            "Show the current action: `pending`",
        )

    def _pending_action_reminder(self, lang: str) -> str:
        pending = self.approval.pending
        if pending is None:
            return _t(
                lang,
                "Немає дії, яка очікує підтвердження.",
                "Нет действия, которое ожидает подтверждения.",
                "There is no action waiting for confirmation.",
            )
        plan_lines = pending.plan or [pending.summary]
        plan_preview = "\n".join(f"- {line}" for line in plan_lines[:4])
        return _t(
            lang,
            "Зараз є незавершена дія, яка потребує підтвердження.\n"
            f"- ID дії: {pending.id}\n"
            f"{plan_preview}\n"
            f"Підтвердити: `approve {pending.id}`\n"
            f"Скасувати: `cancel {pending.id}`\n"
            "Одночасно підтримується лише одна дія на підтвердженні.",
            "Сейчас есть незавершенное действие, которое требует подтверждения.\n"
            f"- ID действия: {pending.id}\n"
            f"{plan_preview}\n"
            f"Подтвердить: `approve {pending.id}`\n"
            f"Отменить: `cancel {pending.id}`\n"
            "Одновременно поддерживается только одно действие на подтверждении.",
            "There is already a pending action that needs confirmation.\n"
            f"- Action ID: {pending.id}\n"
            f"{plan_preview}\n"
            f"Approve: `approve {pending.id}`\n"
            f"Cancel: `cancel {pending.id}`\n"
            "Only one pending action is supported at a time.",
        )

    def _history_actions_report(self, limit_raw: Optional[str], lang: str) -> str:
        try:
            limit = int(limit_raw) if limit_raw else 10
        except ValueError:
            limit = 10
        limit = max(1, min(limit, 30))

        history = read_action_history(limit=limit)
        if not history:
            return _t(
                lang,
                "Історія дій порожня. Лог ще не містить подій.",
                "История действий пуста. В логе пока нет событий.",
                "The action history is empty. The log does not contain events yet.",
            )

        lines = [
            _t(
                lang,
                f"Останні дії (до {limit}):",
                f"Последние действия (до {limit}):",
                f"Recent actions (up to {limit}):",
            )
        ]
        for record in reversed(history):
            event = record.get("event", "unknown")
            action_id = record.get("action_id", "-")
            tool = record.get("tool_name", "-")
            timestamp = str(record.get("timestamp", ""))
            short_time = timestamp.replace("T", " ")[:19] if timestamp else "?"
            lines.append(f"- [{short_time}] {event}: {tool} (id={action_id})")

        lines.append(
            _t(
                lang,
                f"Лог: `{settings.action_audit_log_path}`",
                f"Лог: `{settings.action_audit_log_path}`",
                f"Log: `{settings.action_audit_log_path}`",
            )
        )
        return "\n".join(lines)

    def _last_action_report(self, lang: str) -> str:
        record = read_last_action()
        if not record:
            return _t(
                lang,
                "Остання дія відсутня: лог порожній.",
                "Последнее действие отсутствует: лог пуст.",
                "There is no last action: the log is empty.",
            )

        event = record.get("event", "unknown")
        action_id = record.get("action_id", "-")
        tool = record.get("tool_name", "-")
        timestamp = str(record.get("timestamp", ""))
        note = record.get("note")
        result = record.get("result")

        lines = [
            _t(
                lang,
                "Остання зафіксована дія:",
                "Последнее зафиксированное действие:",
                "Last recorded action:",
            ),
            _t(
                lang, f"- Подія: {event}.", f"- Событие: {event}.", f"- Event: {event}."
            ),
            _t(
                lang,
                f"- ID дії: {action_id}.",
                f"- ID действия: {action_id}.",
                f"- Action ID: {action_id}.",
            ),
            _t(
                lang,
                f"- Інструмент: {tool}.",
                f"- Инструмент: {tool}.",
                f"- Tool: {tool}.",
            ),
            _t(
                lang,
                f"- Час: {timestamp}.",
                f"- Время: {timestamp}.",
                f"- Time: {timestamp}.",
            ),
        ]
        if note:
            lines.append(
                _t(
                    lang,
                    f"- Примітка: {note}",
                    f"- Примечание: {note}",
                    f"- Note: {note}",
                )
            )

        if isinstance(result, dict):
            returncode = result.get("returncode")
            if returncode is not None:
                lines.append(
                    _t(
                        lang,
                        f"- Код повернення: {returncode}",
                        f"- Код возврата: {returncode}",
                        f"- Return code: {returncode}",
                    )
                )

        lines.append(
            _t(
                lang,
                f"Лог: `{settings.action_audit_log_path}`",
                f"Лог: `{settings.action_audit_log_path}`",
                f"Log: `{settings.action_audit_log_path}`",
            )
        )
        return "\n".join(lines)

    def _approve_pending_action(
        self, action_id: Optional[str] = None, *, lang: str
    ) -> str:
        pending = self.approval.pending
        if pending is None:
            return _t(
                lang,
                "Немає дії, яка очікує підтвердження.",
                "Нет действия, которое ожидает подтверждения.",
                "There is no action waiting for confirmation.",
            )

        if action_id and action_id != pending.id:
            return _t(
                lang,
                "ID дії не збігається з поточною дією на підтвердженні.\n"
                f"Очікується: `{pending.id}`.\n"
                f"Використай: `approve {pending.id}` або `cancel {pending.id}`.",
                "ID действия не совпадает с текущим действием на подтверждении.\n"
                f"Ожидается: `{pending.id}`.\n"
                f"Используй: `approve {pending.id}` или `cancel {pending.id}`.",
                "The action ID does not match the current pending action.\n"
                f"Expected: `{pending.id}`.\n"
                f"Use: `approve {pending.id}` or `cancel {pending.id}`.",
            )

        log_action_event(
            "approved",
            action=pending,
            note="User approved pending action.",
        )

        tool_result = execute_tool(
            pending.tool_name,
            pending.arguments,
            self.tool_registry,
        )

        decoded_result = self._decode_tool_result(tool_result)
        log_action_event(
            "executed",
            action=pending,
            result=decoded_result,
            note="Pending action executed.",
        )

        self.approval.clear()
        result_summary = self._execution_result_summary(decoded_result, lang)
        return _t(
            lang,
            "Підтверджено. Виконую дію:\n"
            f"- ID дії: {pending.id}\n"
            f"- {pending.summary}\n\n"
            f"Підсумок: {result_summary}\n"
            f"Лог: `{settings.action_audit_log_path}`\n\n"
            "Результат:\n"
            f"{tool_result}",
            "Подтверждено. Выполняю действие:\n"
            f"- ID действия: {pending.id}\n"
            f"- {pending.summary}\n\n"
            f"Итог: {result_summary}\n"
            f"Лог: `{settings.action_audit_log_path}`\n\n"
            "Результат:\n"
            f"{tool_result}",
            "Confirmed. Executing the action:\n"
            f"- Action ID: {pending.id}\n"
            f"- {pending.summary}\n\n"
            f"Summary: {result_summary}\n"
            f"Log: `{settings.action_audit_log_path}`\n\n"
            "Result:\n"
            f"{tool_result}",
        )

    def _cancel_pending_action(
        self, action_id: Optional[str] = None, *, lang: str
    ) -> str:
        pending = self.approval.pending
        if pending is None:
            return _t(
                lang,
                "Немає дії, яку треба скасувати.",
                "Нет действия, которое нужно отменить.",
                "There is no action to cancel.",
            )

        if action_id and action_id != pending.id:
            return _t(
                lang,
                "ID дії не збігається з поточною дією на підтвердженні.\n"
                f"Очікується: `{pending.id}`.\n"
                f"Використай: `cancel {pending.id}`.",
                "ID действия не совпадает с текущим действием на подтверждении.\n"
                f"Ожидается: `{pending.id}`.\n"
                f"Используй: `cancel {pending.id}`.",
                "The action ID does not match the current pending action.\n"
                f"Expected: `{pending.id}`.\n"
                f"Use: `cancel {pending.id}`.",
            )

        log_action_event(
            "cancelled",
            action=pending,
            note="User cancelled pending action.",
        )

        self.approval.clear()
        return _t(
            lang,
            f"Скасовано дію: {pending.summary}",
            f"Действие отменено: {pending.summary}",
            f"Cancelled action: {pending.summary}",
        )

    def _decode_tool_result(self, tool_result: str) -> Any:
        try:
            return json.loads(tool_result)
        except json.JSONDecodeError:
            return {"raw": tool_result[:4000]}

    def _execution_result_summary(self, decoded_result: Any, lang: str) -> str:
        if isinstance(decoded_result, dict):
            if decoded_result.get("error"):
                return _t(
                    lang,
                    f"помилка ({decoded_result['error']})",
                    f"ошибка ({decoded_result['error']})",
                    f"failed ({decoded_result['error']})",
                )

            returncode = decoded_result.get("returncode")
            if isinstance(returncode, int):
                if returncode == 0:
                    return _t(
                        lang,
                        "успіх (returncode=0)",
                        "успех (returncode=0)",
                        "success (returncode=0)",
                    )
                return _t(
                    lang,
                    f"помилка (returncode={returncode})",
                    f"ошибка (returncode={returncode})",
                    f"failed (returncode={returncode})",
                )

            success_flag = decoded_result.get("success")
            if isinstance(success_flag, bool):
                return _t(
                    lang,
                    "успіх" if success_flag else "помилка",
                    "успех" if success_flag else "ошибка",
                    "success" if success_flag else "failed",
                )

        return _t(lang, "завершено", "завершено", "completed")
