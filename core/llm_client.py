from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

import httpx


@dataclass
class Tool:
    name: str
    description: str
    parameters: Dict[str, Any]
    fn: Callable[..., Any]


class LLMClient:
    def __init__(self, base_url: str, model: str, timeout: int = 120) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def chat(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools

        response = httpx.post(
            f"{self.base_url}/v1/chat/completions",
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()

        choice = data["choices"][0]["message"]
        tool_calls = choice.get("tool_calls") or []

        if tool_calls:
            raw = tool_calls[0]
            function = raw["function"]
            arguments = function.get("arguments") or "{}"

            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {}

            return {
                "assistant_message": {
                    "role": "assistant",
                    "content": choice.get("content", "") or "",
                },
                "tool_call": {
                    "name": function["name"],
                    "arguments": arguments,
                },
                "tool_call_id": raw.get("id", "call_0"),
            }

        return {
            "assistant_message": {
                "role": "assistant",
                "content": choice.get("content", "") or "",
            },
            "tool_call": None,
            "tool_call_id": None,
        }

    def healthcheck(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "ok": False,
            "base_url": self.base_url,
            "model": self.model,
            "server_reachable": False,
            "model_available": False,
            "tool_support": False,
        }

        try:
            response = httpx.get(
                f"{self.base_url}/api/tags", timeout=min(self.timeout, 10)
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            result["error"] = f"Cannot reach Ollama at {self.base_url}: {exc}"
            return result

        result["server_reachable"] = True

        try:
            payload = response.json()
        except ValueError:
            result["error"] = "Ollama returned invalid JSON from /api/tags"
            return result

        models = payload.get("models", [])
        available_models = [
            model.get("name", "") for model in models if model.get("name")
        ]
        result["available_models"] = available_models
        result["model_available"] = self.model in available_models

        if not result["model_available"]:
            result["error"] = (
                f"Model '{self.model}' is not available in Ollama. "
                "Pull it first or set MEDFARL_MODEL to an installed model."
            )
            return result

        tool_payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": "healthcheck"}],
            "stream": False,
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "healthcheck_tool",
                        "description": "Small test tool for compatibility checks.",
                        "parameters": {
                            "type": "object",
                            "properties": {},
                            "required": [],
                        },
                    },
                }
            ],
        }

        try:
            tool_response = httpx.post(
                f"{self.base_url}/v1/chat/completions",
                json=tool_payload,
                timeout=max(60, min(self.timeout, 180)),
            )
        except httpx.HTTPError as exc:
            result["error"] = f"Tool support check failed for '{self.model}': {exc}"
            return result

        if tool_response.status_code >= 400:
            try:
                error_payload = tool_response.json()
                error_message = (
                    error_payload.get("error", {}).get("message") or tool_response.text
                )
            except ValueError:
                error_message = tool_response.text
            result["error"] = (
                f"Model '{self.model}' failed tool-support check: {error_message}"
            )
            return result

        result["tool_support"] = True

        result["ok"] = True
        return result

    def list_models(self) -> List[str]:
        response = httpx.get(f"{self.base_url}/api/tags", timeout=min(self.timeout, 10))
        response.raise_for_status()
        payload = response.json()
        models = payload.get("models", [])
        return [model.get("name", "") for model in models if model.get("name")]
