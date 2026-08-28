"""
Optional LLM hook for the Security Copilot — ``LLM explains, never decides``.

Architecture reference: ``qtrust_ai/README.md`` §20.

The copilot's *security conclusions always come from the deterministic
scanners + ML models* (see :mod:`qtrust_ai.copilot.evidence`). The LLM only
**rephrases** the evidence into human-readable prose. If no LLM is configured
(or the call fails), the deterministic evidence text is returned unchanged —
the product never depends on a network call to answer a security question.

Providers:

* :class:`DeterministicProvider` — passthrough (default, no network).
* :class:`OpenAICompatibleProvider` — calls any OpenAI-compatible
  ``/chat/completions`` endpoint via stdlib ``urllib`` (no new deps).

Configuration via environment variables:

* ``QTRUST_LLM_API_KEY`` — enables the LLM provider (else deterministic).
* ``QTRUST_LLM_BASE_URL`` — default ``https://api.openai.com/v1``.
* ``QTRUST_LLM_MODEL`` — default ``gpt-4o-mini``.
* ``QTRUST_LLM_TIMEOUT`` — seconds (default 30).

Example:
    from qtrust_ai.copilot.llm import build_llm_provider

    provider = build_llm_provider()          # deterministic unless API key set
    out = provider.generate("you are a CISO copilot", "explain: ...")
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Dict, Optional

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_TIMEOUT = 30


class LLMProvider:
    """Interface: generate a completion from system + user prompts.

    Implementations must never raise on failure — return the fallback text.
    """

    name: str = "base"

    def generate(self, system_prompt: str, user_prompt: str, **kwargs: object) -> str:  # pragma: no cover
        raise NotImplementedError


class DeterministicProvider(LLMProvider):
    """Passthrough provider — returns the evidence text unchanged.

    This is the *safest* provider: no network, no key, deterministic output.
    """

    name = "deterministic"

    def __init__(self) -> None:
        pass

    def generate(self, system_prompt: str, user_prompt: str, **kwargs: object) -> str:
        return user_prompt


class OpenAICompatibleProvider(LLMProvider):
    """OpenAI-compatible chat completions via stdlib ``urllib``.

    On *any* failure (missing key, network, HTTP error, bad JSON) it falls
    back to the deterministic text — the copilot never breaks because the LLM
    is unavailable.
    """

    name = "openai-compatible"

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        temperature: float = 0.2,
    ) -> None:
        self.api_key = api_key or os.environ.get("QTRUST_LLM_API_KEY", "")
        self.base_url = (base_url or os.environ.get("QTRUST_LLM_BASE_URL", DEFAULT_BASE_URL)).rstrip("/")
        self.model = model or os.environ.get("QTRUST_LLM_MODEL", DEFAULT_MODEL)
        try:
            self.timeout = int(os.environ.get("QTRUST_LLM_TIMEOUT", str(timeout)))
        except ValueError:
            self.timeout = timeout
        self.temperature = temperature
        self._last_error: Optional[str] = None

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def generate(self, system_prompt: str, user_prompt: str, **kwargs: object) -> str:
        if not self.configured:
            self._last_error = "no QTRUST_LLM_API_KEY configured"
            return user_prompt
        try:
            return self._call(system_prompt, user_prompt)
        except Exception as exc:  # noqa: BLE001 — deliberate: never raise to caller
            self._last_error = f"{type(exc).__name__}: {exc}"
            return user_prompt

    def _call(self, system_prompt: str, user_prompt: str) -> str:
        payload: Dict[str, object] = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 — caller-controlled base URL
            body = json.loads(resp.read().decode("utf-8"))
        choices = body.get("choices") or []
        if not choices:
            self._last_error = "empty choices in LLM response"
            return user_prompt
        content = choices[0].get("message", {}).get("content")
        if not content:
            self._last_error = "empty content in LLM response"
            return user_prompt
        return str(content).strip()


def build_llm_provider() -> LLMProvider:
    """Env-aware provider factory.

    Returns an :class:`OpenAICompatibleProvider` when ``QTRUST_LLM_API_KEY`` is
    set, otherwise the deterministic passthrough.
    """
    if os.environ.get("QTRUST_LLM_API_KEY"):
        return OpenAICompatibleProvider()
    return DeterministicProvider()


def provider_info(provider: LLMProvider) -> Dict[str, object]:
    """Describe a provider for logs / dashboards (never exposes the key)."""
    return {
        "name": provider.name,
        "configured": getattr(provider, "configured", True),
        "model": getattr(provider, "model", None),
        "base_url": getattr(provider, "base_url", None),
        "last_error": getattr(provider, "_last_error", None),
    }


if __name__ == "__main__":
    print("=== LLM hook demo — deterministic by default, optional OpenAI-compatible ===\n")
    p = build_llm_provider()
    print(f"provider: {p.name} (configured={getattr(p, 'configured', True)})")
    out = p.generate("you are a CISO copilot", "Payment API: RSA-2048, 17 deps, CNSA violation")
    print(f"output  : {out}")
    assert out.startswith("Payment API")
    print("\nSet QTRUST_LLM_API_KEY (+ optional QTRUST_LLM_BASE_URL / QTRUST_LLM_MODEL) to enable LLM polish.")
