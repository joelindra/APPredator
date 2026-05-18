"""
Lightweight LLM connectivity check for the web UI (short timeouts, tiny payloads).
Uses saved settings from config (call Apply in the UI before testing unsaved edits).
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

import requests

from core.config_loader import Settings
from modules.llm_client.groq import _resolve_groq_model

_TIMEOUT = 18


def _ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)


def _fail(provider: str, msg: str, *, t0: float, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "provider": provider, "message": msg, "latency_ms": _ms(t0), **extra}


def _ok(provider: str, msg: str, *, t0: float, **extra: Any) -> dict[str, Any]:
    return {"ok": True, "provider": provider, "message": msg, "latency_ms": _ms(t0), **extra}


def _openai_style_chat(url: str, api_key: str, model: str, *, provider: str) -> dict[str, Any]:
    t0 = time.perf_counter()
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    data = {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
        "max_tokens": 8,
    }
    try:
        r = requests.post(url, headers=headers, data=json.dumps(data), timeout=_TIMEOUT)
        if r.status_code >= 400:
            detail = r.text[:800]
            try:
                err = r.json().get("error")
                if isinstance(err, dict) and err.get("message"):
                    detail = str(err.get("message"))
                elif isinstance(err, str):
                    detail = err
            except Exception:
                pass
            return _fail(provider, f"HTTP {r.status_code}: {detail}", t0=t0)
        body = r.json()
        if isinstance(body, dict) and body.get("error"):
            return _fail(provider, str(body.get("error")), t0=t0)
        return _ok(provider, "Chat completion accepted; credentials and model id look valid.", t0=t0)
    except requests.RequestException as e:
        return _fail(provider, str(e), t0=t0)


def probe_llm_connection(s: Settings) -> dict[str, Any]:
    prov = (s.llm.provider or "").strip().lower()
    t0 = time.perf_counter()

    if prov == "ollama":
        base = (s.llm.ollama_url or "http://localhost:11434").rstrip("/")
        try:
            r = requests.get(f"{base}/api/tags", timeout=_TIMEOUT)
            r.raise_for_status()
            return _ok(prov, f"Ollama responded at {base}/api/tags.", t0=t0, endpoint=f"{base}/api/tags")
        except requests.RequestException as e:
            return _fail(prov, str(e), t0=t0, endpoint=f"{base}/api/tags")

    if prov == "gemini":
        key = (s.llm.api_key or "").strip()
        if not key:
            return _fail(prov, "llm.api_key is empty (Gemini).", t0=t0)
        model = (s.llm.gemini_model or "gemini-2.0-flash").strip()
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        headers = {"Content-Type": "application/json", "X-goog-api-key": key}
        data = {"contents": [{"parts": [{"text": "Reply with exactly: OK"}]}]}
        try:
            r = requests.post(url, headers=headers, data=json.dumps(data), timeout=_TIMEOUT)
            if r.status_code >= 400:
                return _fail(prov, f"HTTP {r.status_code}: {r.text[:800]}", t0=t0)
            body = r.json()
            if isinstance(body, dict) and body.get("error"):
                return _fail(prov, str(body["error"]), t0=t0)
            return _ok(prov, "Gemini generateContent succeeded.", t0=t0, model=model)
        except requests.RequestException as e:
            return _fail(prov, str(e), t0=t0, model=model)

    if prov == "groq":
        key = (s.llm.groq_api_key or "").strip()
        if not key:
            return _fail(prov, "llm.groq_api_key is empty.", t0=t0)
        model = _resolve_groq_model((s.llm.groq_model or "").strip() or "llama-3.1-8b-instant")
        return _openai_style_chat(
            "https://api.groq.com/openai/v1/chat/completions",
            key,
            model,
            provider=prov,
        )

    if prov == "openai":
        key = (s.llm.openai_api_key or "").strip()
        if not key:
            return _fail(prov, "llm.openai_api_key is empty.", t0=t0)
        model = (s.llm.openai_model or "gpt-4o-mini").strip()
        return _openai_style_chat("https://api.openai.com/v1/chat/completions", key, model, provider=prov)

    if prov == "anthropic":
        key = (s.llm.anthropic_api_key or "").strip()
        if not key:
            return _fail(prov, "llm.anthropic_api_key is empty.", t0=t0)
        model = (s.llm.anthropic_model or "claude-3-5-sonnet-20241022").strip()
        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        data = {"model": model, "max_tokens": 16, "messages": [{"role": "user", "content": "Reply with exactly: OK"}]}
        try:
            r = requests.post("https://api.anthropic.com/v1/messages", headers=headers, data=json.dumps(data), timeout=_TIMEOUT)
            if r.status_code >= 400:
                return _fail(prov, f"HTTP {r.status_code}: {r.text[:800]}", t0=t0)
            return _ok(prov, "Anthropic messages API succeeded.", t0=t0, model=model)
        except requests.RequestException as e:
            return _fail(prov, str(e), t0=t0, model=model)

    if prov == "openrouter":
        key = (s.llm.openrouter_api_key or "").strip()
        if not key:
            return _fail(prov, "llm.openrouter_api_key is empty.", t0=t0)
        model = (s.llm.openrouter_model or "google/gemini-2.0-flash-001").strip()
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/apppredator/apppredator",
            "X-Title": "APPredator",
        }
        data = {
            "model": model,
            "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
            "max_tokens": 8,
        }
        try:
            r = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                data=json.dumps(data),
                timeout=_TIMEOUT,
            )
            if r.status_code >= 400:
                return _fail(prov, f"HTTP {r.status_code}: {r.text[:800]}", t0=t0)
            return _ok(prov, "OpenRouter chat completion succeeded.", t0=t0, model=model)
        except requests.RequestException as e:
            return _fail(prov, str(e), t0=t0, model=model)

    if prov == "deepseek":
        api_key = (s.llm.deepseek_api_key or os.environ.get("DEEPSEEK_API_KEY") or "").strip()
        if not api_key:
            return _fail(prov, "deepseek_api_key is empty (or set DEEPSEEK_API_KEY).", t0=t0)
        model = (s.llm.deepseek_model or "deepseek-chat").strip()
        base = (s.llm.deepseek_base_url or "").strip() or "https://api.deepseek.com"
        url = f"{base.rstrip('/')}/v1/chat/completions"
        return _openai_style_chat(url, api_key, model, provider=prov)

    return _fail(prov or "unknown", f"Unknown or unsupported provider: {prov!r}.", t0=t0)
