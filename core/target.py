"""Target interface — wraps any LLM application under test."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

import httpx


class Target(ABC):
    """Abstract base for any LLM application being attacked."""

    name: str = "unnamed"
    description: str = ""

    @abstractmethod
    def query(self, prompt: str, **kwargs: Any) -> str:
        """Send a prompt and return the raw string response."""


class MockTarget(Target):
    """Deterministic target for testing — returns scripted responses."""

    name = "mock"
    description = "Deterministic mock for unit tests"

    def __init__(self, responses: dict[str, str] | None = None, default: str = "I cannot help with that.") -> None:
        self._responses = responses or {}
        self._default = default
        self.call_log: list[str] = []

    def query(self, prompt: str, **kwargs: Any) -> str:
        self.call_log.append(prompt)
        for key, resp in self._responses.items():
            if key.lower() in prompt.lower():
                return resp
        return self._default


class HttpTarget(Target):
    """Calls an HTTP endpoint that accepts POST JSON with a 'prompt' field."""

    def __init__(
        self,
        url: str,
        name: str = "http-target",
        description: str = "",
        headers: dict[str, str] | None = None,
        prompt_field: str = "prompt",
        response_field: str = "response",
        timeout: float = 30.0,
    ) -> None:
        self.name = name
        self.description = description
        self._url = url
        self._headers = headers or {}
        self._prompt_field = prompt_field
        self._response_field = response_field
        self._timeout = timeout

    def query(self, prompt: str, **kwargs: Any) -> str:
        payload = {self._prompt_field: prompt, **kwargs}
        resp = httpx.post(
            self._url,
            json=payload,
            headers=self._headers,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, dict):
            return str(data.get(self._response_field, json.dumps(data)))
        return str(data)


class AnthropicTarget(Target):
    """Wraps an Anthropic Claude model as the target."""

    def __init__(
        self,
        model: str = "claude-haiku-4-5-20251001",
        system_prompt: str = "You are a helpful assistant.",
        name: str = "claude-target",
        description: str = "",
        max_tokens: int = 512,
    ) -> None:
        import anthropic  # deferred import

        self.name = name
        self.description = description
        self._model = model
        self._system = system_prompt
        self._max_tokens = max_tokens
        self._client = anthropic.Anthropic()

    def query(self, prompt: str, **kwargs: Any) -> str:
        msg = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=self._system,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text


class OpenAITarget(Target):
    """Wraps an OpenAI model as the target."""

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        system_prompt: str = "You are a helpful assistant.",
        name: str = "openai-target",
        description: str = "",
        max_tokens: int = 512,
    ) -> None:
        from openai import OpenAI  # deferred import

        self.name = name
        self.description = description
        self._model = model
        self._system = system_prompt
        self._max_tokens = max_tokens
        self._client = OpenAI()

    def query(self, prompt: str, **kwargs: Any) -> str:
        resp = self._client.chat.completions.create(
            model=self._model,
            max_tokens=self._max_tokens,
            messages=[
                {"role": "system", "content": self._system},
                {"role": "user", "content": prompt},
            ],
        )
        return resp.choices[0].message.content or ""
