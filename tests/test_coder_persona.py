"""Regression tests for the bundled Kohana coder identity."""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

from core import coder_persona
from core.coder import CoderSession


class KohanaCoderPersonaTests(TestCase):
    def test_bundled_persona_contains_programmer_and_agent_rules(self):
        prompt = coder_persona.load_coder_persona("OPERATING RULE")
        self.assertIn("<persona_name>Кохана</persona_name>", prompt)
        self.assertIn("<world_class_programmer>", prompt)
        self.assertIn('name="OpenAI Codex"', prompt)
        self.assertIn('name="Anthropic Claude Code"', prompt)
        self.assertIn("<medfarl_coder_operating_rules>", prompt)
        self.assertIn("OPERATING RULE", prompt)

    def test_coder_request_includes_persona_as_system_message(self):
        client = Mock(model="test-model")
        client.chat.return_value = {
            "assistant_message": {"role": "assistant", "content": "Готово."}
        }
        with TemporaryDirectory() as workspace:
            session = CoderSession(client, workspace, confirm=lambda _: True)
            try:
                self.assertEqual(session.handle_user_message("Привіт"), "Готово.")
                system = client.chat.call_args.kwargs["messages"][0]
                self.assertEqual(system["role"], "system")
                self.assertIn("<world_class_programmer>", system["content"])
                self.assertIn("робоч", system["content"].lower())
            finally:
                session.close()

    def test_broken_persona_fails_instead_of_silent_fallback(self):
        with TemporaryDirectory() as tempdir:
            broken = Path(tempdir) / "broken.xml"
            broken.write_text("<ai_persona>", encoding="utf-8")
            with patch.object(coder_persona, "PERSONA_PATH", broken):
                with self.assertRaisesRegex(RuntimeError, "Некоректний XML"):
                    coder_persona.load_coder_persona("runtime")
