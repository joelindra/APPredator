"""
DeepSeek — OpenAI-compatible HTTPS API (no `openai` package required).

Docs: https://api.deepseek.com — chat completions at /v1/chat/completions.
Optional thinking mode + reasoning_effort for models such as deepseek-v4-pro.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

import requests

from .base import BaseLLMClient
from core import log


def _non_retryable_network_error(exc: BaseException) -> bool:
    """DNS / bad hostname failures will not heal with backoff."""
    msg = str(exc).lower()
    needles = (
        "failed to resolve",
        "name resolution",
        "getaddrinfo",
        "nodename nor servname",
        "name or service not known",
        "temporary failure in name resolution",
    )
    return any(n in msg for n in needles)


class DeepSeekClient(BaseLLMClient):
    """Same message shape as OpenAI; supports DeepSeek-specific thinking / reasoning fields."""

    def __init__(
        self,
        model: str,
        api_key: str,
        *,
        base_url: str = "https://api.deepseek.com",
        reasoning_effort: Optional[str] = "high",
        thinking_enabled: bool = True,
    ):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.url = f"{self.base_url}/v1/chat/completions"
        self.reasoning_effort = reasoning_effort
        self.thinking_enabled = thinking_enabled

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        prompt = self._construct_prompt(code_snippet, context)
        log.info(f"Sending analysis request to DeepSeek model: {self.model}...")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        data: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
        if self.reasoning_effort:
            data["reasoning_effort"] = self.reasoning_effort
        if self.thinking_enabled:
            data["thinking"] = {"type": "enabled"}

        max_retries = 5
        base_delay = 2

        for attempt in range(max_retries):
            try:
                response = requests.post(self.url, headers=headers, data=json.dumps(data), timeout=600)

                if response.status_code == 429:
                    delay = base_delay * (2**attempt)
                    log.warning(f"Rate limit hit (429). Retrying in {delay}s... ({attempt + 1}/{max_retries})")
                    time.sleep(delay)
                    continue

                if response.status_code == 503:
                    delay = base_delay * (2**attempt)
                    log.warning(f"Service Unavailable (503). Retrying in {delay}s... ({attempt + 1}/{max_retries})")
                    time.sleep(delay)
                    continue

                if response.status_code >= 400:
                    detail = response.text[:1200]
                    try:
                        err = response.json().get("error") or {}
                        if isinstance(err, dict) and err.get("message"):
                            detail = str(err.get("message"))
                    except Exception:
                        pass
                    # Unknown params (e.g. older endpoint): retry once without thinking / reasoning
                    if response.status_code == 400 and attempt == 0 and (self.thinking_enabled or self.reasoning_effort):
                        log.warning("DeepSeek returned 400; retrying without reasoning_effort / thinking flags.")
                        data_retry = {k: v for k, v in data.items() if k not in ("reasoning_effort", "thinking")}
                        response = requests.post(
                            self.url, headers=headers, data=json.dumps(data_retry), timeout=600
                        )
                        if response.status_code < 400:
                            result = response.json()
                            if "error" in result:
                                raise requests.exceptions.RequestException(str(result["error"]))
                            log.success("Received analysis from DeepSeek (fallback without thinking).")
                            return self._message_text(result)
                        detail = response.text[:1200]

                    log.error(f"DeepSeek API error {response.status_code}: {detail}")
                    response.raise_for_status()

                result = response.json()
                if "error" in result:
                    log.error(f"DeepSeek API returned error: {result['error']}")
                    raise requests.exceptions.RequestException(f"DeepSeek API Error: {result['error']}")

                log.success("Received analysis from DeepSeek.")
                return self._message_text(result)

            except requests.exceptions.RequestException as e:
                if _non_retryable_network_error(e):
                    log.error(f"DeepSeek unreachable (no retry): {e}")
                    raise
                if attempt < max_retries - 1:
                    delay = base_delay * (2**attempt)
                    log.warning(f"Network error: {e}. Retrying in {delay}s...")
                    time.sleep(delay)
                    continue
                log.error(f"Failed to communicate with DeepSeek API after {max_retries} attempts: {e}")
                raise

        log.error("DeepSeek API failed after retries.")
        return ""

    @staticmethod
    def _message_text(result: dict[str, Any]) -> str:
        msg = (result.get("choices") or [{}])[0].get("message") or {}
        text = msg.get("content")
        if isinstance(text, str) and text.strip():
            return text
        # Some responses may only expose reasoning stream fields in other builds
        alt = msg.get("reasoning_content")
        if isinstance(alt, str) and alt.strip():
            return alt
        return ""

    def _construct_prompt(self, code_snippet: str, context: Dict[str, Any]) -> str:
        system_prompt = context.get("system_prompt", "")
        vuln_prompt = context.get("vuln_prompt", "")

        formatted_prompt = vuln_prompt.format(
            code_snippet=code_snippet,
            file_path=context.get("file_path", "N/A"),
        )

        return f"{system_prompt}\\n\\n{formatted_prompt}"
