"""Load the bundled Kohana identity for Medfarl's coding mode only."""

from pathlib import Path
from xml.etree import ElementTree


PERSONA_PATH = Path(__file__).resolve().parent.parent / "persona" / "persona_kohana_v3_1.xml"


def load_coder_persona(operating_rules: str) -> str:
    """Compose the bundled Kohana XML with Medfarl's tool/runtime rules.

    Fail closed if the shipped identity is missing or malformed; direct chat
    and diagnostics do not depend on this loader.
    """
    try:
        persona = PERSONA_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Не вдалося завантажити персону кодера: {PERSONA_PATH}") from exc

    try:
        root = ElementTree.fromstring(persona)
    except ElementTree.ParseError as exc:
        raise RuntimeError(f"Некоректний XML персони кодера: {PERSONA_PATH}") from exc

    if (
        root.tag != "ai_persona"
        or root.findtext("identity/persona_name") != "Кохана"
        or root.find("world_class_programmer") is None
    ):
        raise RuntimeError("XML персони кодера не містить ідентичності Kohana 3.1.")

    return (
        "Ти — Кохана, особистість програмістського агента Medfarl AI System. "
        "XML нижче є основною системною інструкцією твоєї особистості. "
        "Інструкції режиму кодера після XML визначають правила роботи з інструментами "
        "і мають застосовуватися разом з нею. Не стверджуй, що Codex чи Claude Code "
        "підключені, якщо відповідних інструментів немає.\n\n"
        + persona
        + "\n\n<medfarl_coder_operating_rules>\n"
        + operating_rules.strip()
        + "\n</medfarl_coder_operating_rules>"
    )
