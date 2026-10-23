from __future__ import annotations

from typing import Optional

from core.llm_client import LLMClient


class ChatSession:
    """A conversation with the selected model, without diagnostic routing."""

    def __init__(
        self,
        client: LLMClient,
        *,
        system_prompt: str = "",
        reasoning_effort: Optional[str] = None,
        max_history_messages: int = 40,
    ) -> None:
        self.client = client
        self.system_prompt = system_prompt.strip()
        self.reasoning_effort = reasoning_effort
        self.max_history_messages = max_history_messages
        self.tool_registry = []
        self.reset()

    def reset(self) -> None:
        self.history: list[dict[str, str]] = []
        self._last_response_streamed = False

    def last_response_streamed(self) -> bool:
        return self._last_response_streamed

    def _request_messages(
        self, user_message: dict[str, str]
    ) -> list[dict[str, str]]:
        messages: list[dict[str, str]] = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.extend(self.history)
        messages.append(user_message)
        return messages

    def _trim_history(self) -> None:
        if self.max_history_messages <= 0:
            return
        if len(self.history) <= self.max_history_messages:
            return
        self.history = self.history[-self.max_history_messages :]
        if self.history[0]["role"] == "assistant":
            self.history.pop(0)

    def handle_user_message(self, message: str, stream: bool = False) -> str:
        self._last_response_streamed = False
        user_message = {"role": "user", "content": message}
        response = self.client.chat(
            messages=self._request_messages(user_message),
            stream=stream,
            reasoning_effort=self.reasoning_effort,
        )
        reply = response.get("assistant_message", {}).get("content", "")
        if not reply.strip():
            raise RuntimeError("Модель повернула порожню відповідь. Спробуйте ще раз.")
        # Commit only completed turns so failed or interrupted requests can be retried.
        self.history.extend([user_message, {"role": "assistant", "content": reply}])
        self._trim_history()
        self._last_response_streamed = stream
        return reply
