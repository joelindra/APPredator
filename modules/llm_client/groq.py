import json
import threading
import time
from typing import Any, Dict

import requests
from requests import HTTPError

from .base import BaseLLMClient
from core import log

# Groq uses its own model ids (see https://console.groq.com/docs/models). Ollama-style "llama3:8b" returns 404.
_GROQ_MODEL_ALIASES: dict[str, str] = {
    "llama3:8b": "llama-3.1-8b-instant",
    "llama3.1:8b": "llama-3.1-8b-instant",
    "llama3:70b": "llama-3.3-70b-versatile",
    "llama3:70b-versatile": "llama-3.3-70b-versatile",
}

# Serialize Groq HTTP calls to reduce 429 when Engine analyzes many files concurrently.
_groq_http_lock = threading.Lock()

# Groq/proxy rejects very large JSON bodies (413). Keep user message bounded.
_MAX_CODE_SNIPPET_CHARS = 72_000
_MAX_TOTAL_PROMPT_CHARS = 200_000


def _resolve_groq_model(model: str) -> str:
    m = (model or "").strip()
    if m in _GROQ_MODEL_ALIASES:
        mapped = _GROQ_MODEL_ALIASES[m]
        log.info(f"Groq: mapping model id {m!r} -> {mapped!r} (Ollama-style ids are not valid on Groq)")
        return mapped
    return m


def _clip_code_for_groq(code_snippet: str) -> str:
    if len(code_snippet) <= _MAX_CODE_SNIPPET_CHARS:
        return code_snippet
    log.warning(
        f"Groq: truncating code snippet from {len(code_snippet)} to {_MAX_CODE_SNIPPET_CHARS} chars (avoid 413 Payload Too Large)"
    )
    return (
        code_snippet[: _MAX_CODE_SNIPPET_CHARS - 120]
        + "\n\n// ... [truncated: payload limit for Groq API — disable scan_libraries or use a smaller file scope] ...\n"
    )


def _clip_full_prompt(prompt: str) -> str:
    if len(prompt) <= _MAX_TOTAL_PROMPT_CHARS:
        return prompt
    head = _MAX_TOTAL_PROMPT_CHARS // 2
    tail = _MAX_TOTAL_PROMPT_CHARS - head - 120
    log.warning(f"Groq: truncating full prompt from {len(prompt)} to ~{_MAX_TOTAL_PROMPT_CHARS} chars")
    return prompt[:head] + "\n\n[... truncated middle ...]\n\n" + prompt[-tail:]


class GroqClient(BaseLLMClient):
    def __init__(self, model: str, api_key: str):
        self.model = _resolve_groq_model(model)
        self.api_key = api_key
        self.url = "https://api.groq.com/openai/v1/chat/completions"

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        code_snippet = _clip_code_for_groq(code_snippet)
        prompt = _clip_full_prompt(self._construct_prompt(code_snippet, context))
        log.info(f"Sending analysis request to Groq model: {self.model}...")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        data = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        }

        max_retries = 6
        base_delay = 2  # seconds

        with _groq_http_lock:
            time.sleep(0.12)  # light pacing under free-tier RPM

            for attempt in range(max_retries):
                try:
                    response = requests.post(self.url, headers=headers, data=json.dumps(data), timeout=600)

                    if response.status_code in (400, 401, 403, 404, 413, 422):
                        detail = response.text[:800]
                        try:
                            err = response.json().get("error") or {}
                            if isinstance(err, dict) and err.get("message"):
                                detail = str(err.get("message"))
                        except Exception:
                            pass
                        if response.status_code == 413:
                            log.error(
                                f"Groq API 413 Payload Too Large for model {self.model!r}: {detail}. "
                                "Prompt was pre-clipped; try filter_mode static_only, disable scan_libraries, or a larger-context provider."
                            )
                        else:
                            log.error(
                                f"Groq API error {response.status_code} for model {self.model!r}: {detail}. "
                                "Use a model id from Groq docs (not Ollama names like llama3:8b)."
                            )
                        response.raise_for_status()

                    if response.status_code == 429:
                        delay = base_delay * (2**attempt)
                        ra = response.headers.get("Retry-After")
                        if ra:
                            try:
                                delay = max(delay, float(ra))
                            except ValueError:
                                pass
                        log.warning(f"Rate limit hit (429). Retrying in {delay:.1f}s... (Attempt {attempt + 1}/{max_retries})")
                        time.sleep(delay)
                        continue

                    if response.status_code == 503:
                        delay = base_delay * (2**attempt)
                        log.warning(f"Service Unavailable (503). Retrying in {delay}s... (Attempt {attempt + 1}/{max_retries})")
                        time.sleep(delay)
                        continue

                    response.raise_for_status()
                    result = response.json()

                    if "error" in result:
                        log.error(f"Groq API returned error: {result['error']}")
                        raise requests.exceptions.RequestException(f"Groq API Error: {result['error']}")

                    log.success("Received analysis from Groq.")
                    return result["choices"][0]["message"]["content"]

                except HTTPError as e:
                    if e.response is not None and e.response.status_code in (400, 401, 403, 404, 413, 422):
                        raise
                    if attempt < max_retries - 1:
                        delay = base_delay * (2**attempt)
                        log.warning(f"Groq HTTP error: {e}. Retrying in {delay}s...")
                        time.sleep(delay)
                        continue
                    log.error(f"Failed to communicate with Groq API after {max_retries} attempts: {e}")
                    raise
                except requests.exceptions.RequestException as e:
                    if attempt < max_retries - 1:
                        delay = base_delay * (2**attempt)
                        log.warning(f"Network error: {e}. Retrying in {delay}s...")
                        time.sleep(delay)
                        continue
                    log.error(f"Failed to communicate with Groq API after {max_retries} attempts: {e}")
                    raise

            log.error(f"Groq API failed after {max_retries} attempts (Rate Limit or Service Unavailable).")
            return ""

    def _construct_prompt(self, code_snippet: str, context: Dict[str, Any]) -> str:
        system_prompt = context.get("system_prompt", "")
        vuln_prompt = context.get("vuln_prompt", "")

        formatted_prompt = vuln_prompt.format(
            code_snippet=code_snippet,
            file_path=context.get("file_path", "N/A"),
        )

        return f"{system_prompt}\\n\\n{formatted_prompt}"
