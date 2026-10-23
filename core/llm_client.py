from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
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
        stream: bool = False,
        reasoning_effort: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": stream,
        }
        if tools:
            payload["tools"] = tools
        if reasoning_effort:
            payload["reasoning_effort"] = reasoning_effort

        # Streaming mode for interactive output
        if stream:
            return self._stream_response(payload)

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

    def _stream_response(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Stream response tokens in real-time like Gemini CLI."""
        full_content = ""
        tool_calls = []
        tool_call_id = None

        with httpx.stream(
            "POST",
            f"{self.base_url}/v1/chat/completions",
            json=payload,
            timeout=self.timeout,
        ) as response:
            response.raise_for_status()

            for line in response.iter_lines():
                line = line.strip()
                if not line or not line.startswith("data: "):
                    continue

                data_str = line[6:]  # Remove "data: " prefix
                if data_str == "[DONE]":
                    break

                try:
                    chunk = json.loads(data_str)
                    delta = chunk.get("choices", [{}])[0].get("delta", {})

                    # Collect tool calls if present
                    if delta.get("tool_calls"):
                        for tc in delta["tool_calls"]:
                            tool_calls.append(tc)
                            if tc.get("id"):
                                tool_call_id = tc["id"]

                    # Collect content tokens
                    content = delta.get("content", "")
                    if content:
                        full_content += content
                        # Print token immediately for interactive feel
                        print(content, end="", flush=True)

                except (json.JSONDecodeError, IndexError, KeyError):
                    continue

        # Parse tool calls if any
        parsed_tool_call = None
        if tool_calls:
            raw = tool_calls[0]
            function = raw.get("function", {})
            arguments = function.get("arguments") or "{}"

            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {}

            parsed_tool_call = {
                "name": function.get("name", ""),
                "arguments": arguments,
            }

        return {
            "assistant_message": {
                "role": "assistant",
                "content": full_content,
            },
            "tool_call": parsed_tool_call,
            "tool_call_id": tool_call_id,
        }

    def healthcheck(self, *, require_tools: bool = True) -> Dict[str, Any]:
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

        if not require_tools:
            result["ok"] = True
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

    def server_check(self, timeout: int = 3) -> Dict[str, Any]:
        try:
            response = httpx.get(f"{self.base_url}/api/tags", timeout=timeout)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            return {
                "reachable": False,
                "base_url": self.base_url,
                "error": str(exc),
            }
        return {"reachable": True, "base_url": self.base_url}

    def ensure_server(self, start_timeout: int = 20) -> Dict[str, Any]:
        if self.server_check(timeout=2)["reachable"]:
            return {
                "ok": True,
                "started": False,
                "base_url": self.base_url,
            }

        if not self._start_ollama_server():
            return {
                "ok": False,
                "started": False,
                "base_url": self.base_url,
                "error": (
                    f"Ollama is not reachable at {self.base_url} and the "
                    "'ollama' executable was not found."
                ),
            }

        deadline = time.monotonic() + max(1, start_timeout)
        while time.monotonic() < deadline:
            if self.server_check(timeout=2)["reachable"]:
                return {
                    "ok": True,
                    "started": True,
                    "base_url": self.base_url,
                }
            time.sleep(0.5)

        return {
            "ok": False,
            "started": True,
            "base_url": self.base_url,
            "error": (
                f"Ollama was started but did not become reachable at "
                f"{self.base_url} within {start_timeout}s."
            ),
        }

    def _start_ollama_server(self) -> bool:
        executable = shutil.which("ollama")
        if not executable:
            return False

        kwargs: Dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if os.name == "nt":
            kwargs["creationflags"] = (
                subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
            )
        else:
            kwargs["start_new_session"] = True

        try:
            subprocess.Popen([executable, "serve"], **kwargs)
        except OSError:
            return False
        return True

    def warmup(
        self,
        keep_alive: Optional[str] = None,
        autostart: bool = True,
    ) -> Dict[str, Any]:
        if autostart:
            server = self.ensure_server()
        else:
            reachable = self.server_check(timeout=2)["reachable"]
            server = {
                "ok": reachable,
                "started": False,
                "base_url": self.base_url,
                "error": f"Cannot reach Ollama at {self.base_url}.",
            }

        if not server["ok"]:
            return {
                "ok": False,
                "model": self.model,
                "started": server.get("started", False),
                "error": server.get("error", "Ollama is not reachable."),
            }

        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": "",
            "stream": False,
        }
        if keep_alive:
            payload["keep_alive"] = keep_alive

        try:
            response = httpx.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=max(self.timeout, 60),
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text if exc.response is not None else str(exc)
            return {
                "ok": False,
                "model": self.model,
                "started": server.get("started", False),
                "error": f"Cannot load model '{self.model}': {detail}",
            }
        except httpx.HTTPError as exc:
            return {
                "ok": False,
                "model": self.model,
                "started": server.get("started", False),
                "error": f"Cannot load model '{self.model}': {exc}",
            }

        return {
            "ok": True,
            "model": self.model,
            "started": server.get("started", False),
        }

    def list_models(self) -> List[str]:
        response = httpx.get(f"{self.base_url}/api/tags", timeout=min(self.timeout, 10))
        response.raise_for_status()
        payload = response.json()
        models = payload.get("models", [])
        return [model.get("name", "") for model in models if model.get("name")]
