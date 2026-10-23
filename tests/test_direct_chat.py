from __future__ import annotations

import contextlib
import io
import unittest
from unittest.mock import Mock, patch

import httpx

import main
from core.chat import ChatSession
from core.llm_client import LLMClient


class DirectChatTests(unittest.TestCase):
    def test_model_receives_greeting_and_conversation_once(self):
        client = Mock()
        client.chat.return_value = {"assistant_message": {"content": "Привіт!"}}
        chat = ChatSession(
            client, system_prompt="SYSTEM", reasoning_effort="none"
        )
        chat.handle_user_message("привіт", stream=True)
        self.assertTrue(chat.last_response_streamed())
        chat.handle_user_message("Як справи?", stream=False)
        self.assertEqual(client.chat.call_args.kwargs, {
            "messages": [
                {"role": "system", "content": "SYSTEM"},
                {"role": "user", "content": "привіт"},
                {"role": "assistant", "content": "Привіт!"},
                {"role": "user", "content": "Як справи?"},
            ],
            "stream": False,
            "reasoning_effort": "none",
        })
        self.assertFalse(chat.last_response_streamed())
        chat.reset()
        self.assertEqual(chat.history, [])

    def test_failed_or_interrupted_turn_does_not_pollute_history(self):
        for failure in (RuntimeError("offline"), KeyboardInterrupt()):
            client = Mock()
            client.chat.side_effect = failure
            chat = ChatSession(client)
            with self.assertRaises(type(failure)):
                chat.handle_user_message("hello", stream=True)
            self.assertEqual(chat.history, [])
            self.assertFalse(chat.last_response_streamed())

    def test_chat_preflight_does_not_require_tool_support(self):
        client = LLMClient("http://localhost:11434", "test-model")
        response = httpx.Response(
            200,
            json={"models": [{"name": "test-model"}]},
            request=httpx.Request("GET", "http://localhost:11434/api/tags"),
        )
        with (
            patch("core.llm_client.httpx.get", return_value=response),
            patch("core.llm_client.httpx.post") as post,
        ):
            self.assertTrue(client.healthcheck(require_tools=False)["ok"])
            post.assert_not_called()

    def test_default_launch_warms_model_and_opens_streaming_chat(self):
        client = Mock()
        client.warmup.return_value = {"ok": True, "model": main.settings.model}
        client.healthcheck.return_value = {"ok": True, "model": main.settings.model,
                                          "base_url": "http://localhost:11434"}
        client.chat.return_value = {"assistant_message": {"content": "Вітаю!"}}
        with patch("sys.argv", ["main.py"]), \
                patch.object(main.settings, "unsafe_full_access", False), \
                patch.object(main.settings, "warmup_on_start", True), \
                patch("main.configure_console"), \
                patch("main.build_client_with_timeout", return_value=client) as build, \
                patch("main.MedfarlAgent") as diagnostic_agent, \
                patch("main.prompt_user", side_effect=["привіт", "/quit"]), \
                contextlib.redirect_stdout(io.StringIO()):
            main.main()
        build.assert_called_with(main.settings.model, main.settings.timeout)
        client.warmup.assert_called_once()
        client.healthcheck.assert_called_once_with(require_tools=False)
        client.chat.assert_called_once_with(
            messages=[
                {
                    "role": "system",
                    "content": main.settings.chat_system_prompt.strip(),
                },
                {"role": "user", "content": "привіт"},
            ],
            stream=True,
            reasoning_effort=main.settings.chat_reasoning_effort,
        )
        diagnostic_agent.assert_not_called()


if __name__ == "__main__":
    unittest.main()
