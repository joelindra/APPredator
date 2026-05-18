"""
REST endpoints mirroring APPredator CLI config subcommands (YAML via ruamel).
"""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from core.config_loader import load_settings
from core.settings_io import (
    DEFAULT_SETTINGS_PATH,
    load_settings_tree,
    merge_dict_into_tree,
    save_settings_tree,
    tree_to_plain,
)
from modules.decompiler.jadx_handler import normalize_jadx_max_heap_arg

router = APIRouter(prefix="/api/config", tags=["config"])

PROFILE_DIR = Path("config/profiles")


def _save_tree(tree: Any) -> None:
    save_settings_tree(tree)
    load_settings()


@router.get("/show")
def config_show() -> dict[str, Any]:
    s = load_settings()
    return s.model_dump()


@router.get("/provider")
def get_provider() -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    return {"provider": (t.get("llm") or {}).get("provider")}


class ProviderBody(BaseModel):
    provider: str


@router.put("/provider")
def put_provider(body: ProviderBody) -> dict[str, Any]:
    tree = load_settings_tree()
    if not tree:
        tree = {}
    merge_dict_into_tree(tree, {"llm": {"provider": body.provider}})
    _save_tree(tree)
    return {"provider": body.provider}


# Must match keys under `llm:` in config/settings.yaml
_LLM_YAML_LAYOUT: dict[str, dict[str, str]] = {
    "ollama": {"credential_key": "ollama_url", "model_key": "model", "kind": "url", "title": "Ollama"},
    "gemini": {"credential_key": "api_key", "model_key": "gemini_model", "kind": "api_key", "title": "Google Gemini"},
    "groq": {"credential_key": "groq_api_key", "model_key": "groq_model", "kind": "api_key", "title": "Groq"},
    "openai": {"credential_key": "openai_api_key", "model_key": "openai_model", "kind": "api_key", "title": "OpenAI"},
    "anthropic": {"credential_key": "anthropic_api_key", "model_key": "anthropic_model", "kind": "api_key", "title": "Anthropic"},
    "openrouter": {"credential_key": "openrouter_api_key", "model_key": "openrouter_model", "kind": "api_key", "title": "OpenRouter"},
    "deepseek": {"credential_key": "deepseek_api_key", "model_key": "deepseek_model", "kind": "api_key", "title": "DeepSeek"},
}

# Curated presets for the web UI dropdown; any provider id still works via "Other" + free-text save.
_LLM_MODEL_PRESETS: dict[str, list[dict[str, str]]] = {
    "ollama": [
        {"value": "llama3:8b", "label": "Llama 3 8B"},
        {"value": "llama3.1:8b", "label": "Llama 3.1 8B"},
        {"value": "llama3.2:3b", "label": "Llama 3.2 3B"},
        {"value": "mistral", "label": "Mistral 7B"},
        {"value": "mixtral:8x7b", "label": "Mixtral 8x7B"},
        {"value": "codellama:7b", "label": "Code Llama 7B"},
        {"value": "phi3", "label": "Phi-3"},
        {"value": "qwen2.5:7b", "label": "Qwen 2.5 7B"},
    ],
    "gemini": [
        {"value": "gemini-2.0-flash", "label": "Gemini 2.0 Flash"},
        {"value": "gemini-2.5-flash", "label": "Gemini 2.5 Flash"},
        {"value": "gemini-2.5-pro", "label": "Gemini 2.5 Pro"},
        {"value": "gemini-1.5-flash", "label": "Gemini 1.5 Flash"},
        {"value": "gemini-1.5-pro", "label": "Gemini 1.5 Pro"},
    ],
    "groq": [
        {"value": "llama-3.1-8b-instant", "label": "Llama 3.1 8B Instant"},
        {"value": "llama-3.3-70b-versatile", "label": "Llama 3.3 70B Versatile"},
        {"value": "mixtral-8x7b-32768", "label": "Mixtral 8x7B"},
        {"value": "gemma2-9b-it", "label": "Gemma 2 9B IT"},
    ],
    "openai": [
        {"value": "gpt-4o", "label": "GPT-4o"},
        {"value": "gpt-4o-mini", "label": "GPT-4o mini"},
        {"value": "gpt-4-turbo", "label": "GPT-4 Turbo"},
        {"value": "gpt-3.5-turbo", "label": "GPT-3.5 Turbo"},
        {"value": "o1-mini", "label": "o1-mini"},
        {"value": "o1-preview", "label": "o1-preview"},
    ],
    "anthropic": [
        {"value": "claude-sonnet-4-20250514", "label": "Claude Sonnet 4"},
        {"value": "claude-3-5-sonnet-20241022", "label": "Claude 3.5 Sonnet"},
        {"value": "claude-3-opus-20240229", "label": "Claude 3 Opus"},
        {"value": "claude-3-haiku-20240307", "label": "Claude 3 Haiku"},
    ],
    "openrouter": [
        {"value": "google/gemini-2.5-flash", "label": "Google Gemini 2.5 Flash"},
        {"value": "google/gemini-2.5-pro", "label": "Google Gemini 2.5 Pro"},
        {"value": "anthropic/claude-3.5-sonnet", "label": "Anthropic Claude 3.5 Sonnet"},
        {"value": "openai/gpt-4o", "label": "OpenAI GPT-4o"},
        {"value": "meta-llama/llama-3.1-8b-instruct", "label": "Meta Llama 3.1 8B Instruct"},
    ],
    "deepseek": [
        {"value": "deepseek-chat", "label": "DeepSeek Chat"},
        {"value": "deepseek-reasoner", "label": "DeepSeek Reasoner"},
        {"value": "deepseek-v4-flash", "label": "DeepSeek V4 Flash"},
        {"value": "deepseek-v4-pro", "label": "DeepSeek V4 Pro"},
    ],
}


def _mask_api_secret_preview(raw: Any) -> tuple[int, str]:
    """Length + masked string (bullets + last 4 chars) so UI can show sync without exposing full key."""
    s = str(raw).strip() if raw is not None else ""
    if not s:
        return 0, ""
    n = len(s)
    if n <= 8:
        return n, "\u2022" * n
    bullets = min(24, n - 4)
    return n, ("\u2022" * bullets) + s[-4:]


def _llm_layout(provider: str | None) -> dict[str, str] | None:
    if not provider:
        return None
    p = str(provider).strip().lower()
    return _LLM_YAML_LAYOUT.get(p)


def _llm_credential_field(provider: str | None) -> tuple[str, str, str] | None:
    """Returns (yaml_key_under_llm, short label, kind) for backward use; prefer _llm_layout."""
    lay = _llm_layout(provider)
    if not lay:
        return None
    k = lay["credential_key"]
    title = lay["title"]
    kind = lay["kind"]
    if kind == "url":
        return (k, f"{title} — URL", "url")
    return (k, f"{title} — API key", "api_key")


@router.get("/model")
def get_model(provider: Optional[str] = Query(None, description="Override provider for reading model field")) -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    llm = t.get("llm") or {}
    prov = (provider or llm.get("provider") or "").strip()
    pl = prov.lower()
    model = None
    if pl == "ollama":
        model = llm.get("model")
    elif pl == "gemini":
        model = llm.get("gemini_model")
    elif pl == "groq":
        model = llm.get("groq_model")
    elif pl == "openai":
        model = llm.get("openai_model")
    elif pl == "anthropic":
        model = llm.get("anthropic_model")
    elif pl == "openrouter":
        model = llm.get("openrouter_model")
    elif pl == "deepseek":
        model = llm.get("deepseek_model")
    return {"provider": prov or None, "model": model}


@router.get("/llm-model-options")
def get_llm_model_options(
    provider: str = Query(..., description="LLM provider id (ollama, gemini, groq, …)"),
) -> dict[str, Any]:
    """Preset model ids for the configuration UI; users may still save a custom id."""
    p = str(provider or "").strip().lower()
    opts = list(_LLM_MODEL_PRESETS.get(p) or [])
    return {"provider": p, "options": opts}


@router.post("/llm-test")
def post_llm_test() -> dict[str, Any]:
    """One-shot connectivity check using saved settings.yaml (Apply first if you changed the form)."""
    from web.backend.llm_probe import probe_llm_connection

    s = load_settings()
    return probe_llm_connection(s)


@router.get("/llm-credential")
def get_llm_credential(
    provider: Optional[str] = Query(None, description="Which provider's credential field to inspect (defaults to saved provider)"),
) -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    llm = t.get("llm") or {}
    prov = (provider or llm.get("provider") or "").strip() or None
    if not prov:
        return {
            "provider": None,
            "kind": "none",
            "label": None,
            "value": None,
            "configured": False,
            "credential_yaml_key": None,
            "model_yaml_key": None,
            "yaml_hint": None,
            "secret_length": 0,
            "secret_preview": None,
            "settings_path": DEFAULT_SETTINGS_PATH.as_posix(),
        }
    lay = _llm_layout(prov)
    if not lay:
        return {
            "provider": prov,
            "kind": "none",
            "label": None,
            "value": None,
            "configured": False,
            "credential_yaml_key": None,
            "model_yaml_key": None,
            "yaml_hint": None,
            "secret_length": 0,
            "secret_preview": None,
            "settings_path": DEFAULT_SETTINGS_PATH.as_posix(),
        }
    key = lay["credential_key"]
    model_key = lay["model_key"]
    kind = lay["kind"]
    title = lay["title"]
    yaml_hint = f"llm.{key} and llm.{model_key} in {DEFAULT_SETTINGS_PATH.as_posix()}"
    label = f"{title} ({'URL' if kind == 'url' else 'API key'})"
    raw = llm.get(key)
    if kind == "url":
        v = str(raw).strip() if raw else ""
        if not v:
            v = "http://localhost:11434"
        return {
            "provider": prov,
            "kind": "url",
            "label": label,
            "value": v,
            "configured": True,
            "credential_yaml_key": key,
            "model_yaml_key": model_key,
            "yaml_hint": yaml_hint,
            "secret_length": 0,
            "secret_preview": None,
            "settings_path": DEFAULT_SETTINGS_PATH.as_posix(),
        }
    s = str(raw).strip() if raw is not None else ""
    configured = bool(s)
    slen, sprev = (0, "")
    if configured:
        slen, sprev = _mask_api_secret_preview(raw)
    return {
        "provider": prov,
        "kind": "api_key",
        "label": label,
        "value": None,
        "configured": configured,
        "credential_yaml_key": key,
        "model_yaml_key": model_key,
        "yaml_hint": yaml_hint,
        "secret_length": slen,
        "secret_preview": sprev if configured else None,
        "settings_path": DEFAULT_SETTINGS_PATH.as_posix(),
    }


class LlmCredentialPutBody(BaseModel):
    """Write URL or API key for the given provider's YAML field (may differ from saved llm.provider until you save provider)."""

    provider: Optional[str] = None
    value: Optional[str] = None
    clear: bool = False


@router.put("/llm-credential")
def put_llm_credential(body: LlmCredentialPutBody) -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    prov = (body.provider or (t.get("llm") or {}).get("provider") or "").strip()
    if not prov:
        raise HTTPException(400, "Set provider first or pass provider in request body")
    spec = _llm_credential_field(prov.lower())
    if not spec:
        raise HTTPException(400, f"No credential field for provider: {prov}")
    key, _, kind = spec
    tree = load_settings_tree()
    if body.clear:
        if kind == "url":
            raise HTTPException(400, "Ollama URL cannot be cleared; set a non-empty URL")
        merge_dict_into_tree(tree, {"llm": {key: ""}})
        _save_tree(tree)
        return {"ok": True, "configured": False}
    if body.value is None or not str(body.value).strip():
        raise HTTPException(400, "Provide a non-empty value or set clear: true")
    val = str(body.value).strip()
    if kind == "url" and not val:
        val = "http://localhost:11434"
    merge_dict_into_tree(tree, {"llm": {key: val}})
    _save_tree(tree)
    return {"ok": True, "configured": True}


class ModelBody(BaseModel):
    model: str


@router.put("/model")
def put_model(body: ModelBody) -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    prov = (t.get("llm") or {}).get("provider")
    if not prov:
        raise HTTPException(400, "Set provider first")
    key = {
        "ollama": "model",
        "gemini": "gemini_model",
        "groq": "groq_model",
        "openai": "openai_model",
        "anthropic": "anthropic_model",
        "openrouter": "openrouter_model",
        "deepseek": "deepseek_model",
    }.get(prov)
    if not key:
        raise HTTPException(400, f"Unknown provider: {prov}")
    tree = load_settings_tree()
    merge_dict_into_tree(tree, {"llm": {key: body.model}})
    _save_tree(tree)
    return {"model": body.model}


class RulesBody(BaseModel):
    rules: list[str]
    enable: bool = True


@router.post("/rules")
def post_rules(body: RulesBody) -> dict[str, Any]:
    tree = load_settings_tree()
    if not tree:
        tree = {}
    rules = dict(tree.get("rules") or {})
    for r in body.rules:
        rules[r.strip()] = body.enable
    merge_dict_into_tree(tree, {"rules": rules})
    _save_tree(tree)
    return {"ok": True}


@router.get("/rules/enabled")
def rules_enabled() -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    rules = t.get("rules") or {}
    enabled = [k for k, v in rules.items() if v]
    return {"enabled": enabled}


class ToggleBody(BaseModel):
    enable: Optional[bool] = None


@router.get("/attack-surface")
def get_attack_surface() -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    cur = (t.get("analysis") or {}).get("generate_attack_surface_map", False)
    return {"generate_attack_surface_map": cur}


@router.put("/attack-surface")
def put_attack_surface(body: ToggleBody) -> dict[str, Any]:
    if body.enable is None:
        t = tree_to_plain(load_settings_tree())
        cur = (t.get("analysis") or {}).get("generate_attack_surface_map", False)
        return {"generate_attack_surface_map": cur}
    tree = load_settings_tree()
    merge_dict_into_tree(tree, {"analysis": {"generate_attack_surface_map": bool(body.enable)}})
    _save_tree(tree)
    return {"generate_attack_surface_map": body.enable}


@router.get("/context-injection")
def get_context_injection() -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    cur = (t.get("analysis") or {}).get("use_cross_reference_context", True)
    return {"use_cross_reference_context": cur}


@router.put("/context-injection")
def put_context_injection(body: ToggleBody) -> dict[str, Any]:
    if body.enable is None:
        t = tree_to_plain(load_settings_tree())
        cur = (t.get("analysis") or {}).get("use_cross_reference_context", True)
        return {"use_cross_reference_context": cur}
    tree = load_settings_tree()
    merge_dict_into_tree(tree, {"analysis": {"use_cross_reference_context": bool(body.enable)}})
    _save_tree(tree)
    return {"use_cross_reference_context": body.enable}


@router.get("/generate-exploit")
def get_generate_exploit() -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    cur = (t.get("analysis") or {}).get("generate_exploit", False)
    return {"generate_exploit": bool(cur)}


@router.put("/generate-exploit")
def put_generate_exploit(body: ToggleBody) -> dict[str, Any]:
    if body.enable is None:
        t = tree_to_plain(load_settings_tree())
        cur = (t.get("analysis") or {}).get("generate_exploit", False)
        return {"generate_exploit": bool(cur)}
    tree = load_settings_tree()
    merge_dict_into_tree(tree, {"analysis": {"generate_exploit": bool(body.enable)}})
    _save_tree(tree)
    return {"generate_exploit": body.enable}


@router.get("/scan-libraries")
def get_scan_libraries() -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    cur = (t.get("analysis") or {}).get("scan_libraries", False)
    return {"scan_libraries": bool(cur)}


@router.put("/scan-libraries")
def put_scan_libraries(body: ToggleBody) -> dict[str, Any]:
    if body.enable is None:
        t = tree_to_plain(load_settings_tree())
        cur = (t.get("analysis") or {}).get("scan_libraries", False)
        return {"scan_libraries": bool(cur)}
    tree = load_settings_tree()
    merge_dict_into_tree(tree, {"analysis": {"scan_libraries": bool(body.enable)}})
    _save_tree(tree)
    return {"scan_libraries": body.enable}


class DeepSeekAdvancedBody(BaseModel):
    """Partial update for DeepSeek-specific keys under `llm:` (see core.config_loader.LLMSettings)."""

    deepseek_base_url: Optional[str] = None
    deepseek_reasoning_effort: Optional[str] = None
    deepseek_thinking_enabled: Optional[bool] = None


@router.get("/llm-deepseek-advanced")
def get_llm_deepseek_advanced() -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    llm = t.get("llm") or {}
    return {
        "deepseek_base_url": llm.get("deepseek_base_url"),
        "deepseek_reasoning_effort": llm.get("deepseek_reasoning_effort"),
        "deepseek_thinking_enabled": llm.get("deepseek_thinking_enabled"),
    }


@router.put("/llm-deepseek-advanced")
def put_llm_deepseek_advanced(body: DeepSeekAdvancedBody) -> dict[str, Any]:
    tree = load_settings_tree()
    raw = body.model_dump(exclude_unset=True)
    llm_patch: dict[str, Any] = {}
    if "deepseek_base_url" in raw:
        v = raw["deepseek_base_url"]
        llm_patch["deepseek_base_url"] = (str(v).strip() if v is not None else "") or None
    if "deepseek_reasoning_effort" in raw:
        v = raw["deepseek_reasoning_effort"]
        llm_patch["deepseek_reasoning_effort"] = (str(v).strip() if v is not None else "") or None
    if "deepseek_thinking_enabled" in raw:
        llm_patch["deepseek_thinking_enabled"] = raw["deepseek_thinking_enabled"]
    if llm_patch:
        merge_dict_into_tree(tree, {"llm": llm_patch})
        _save_tree(tree)
    return get_llm_deepseek_advanced()


class FilterModeBody(BaseModel):
    mode: str


@router.get("/filter-mode")
def get_filter_mode() -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    cur = (t.get("analysis") or {}).get("filter_mode", "llm_only")
    return {"filter_mode": cur}


@router.put("/filter-mode")
def put_filter_mode(body: FilterModeBody) -> dict[str, Any]:
    valid = {"static_only", "llm_only", "hybrid"}
    if body.mode not in valid:
        raise HTTPException(400, f"mode must be one of {valid}")
    tree = load_settings_tree()
    merge_dict_into_tree(tree, {"analysis": {"filter_mode": body.mode}})
    _save_tree(tree)
    return {"filter_mode": body.mode}


@router.get("/decompiler-mode")
def get_decompiler_mode() -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    cur = (t.get("analysis") or {}).get("decompiler_mode", "apktool")
    return {"decompiler_mode": cur}


class DecompilerModeBody(BaseModel):
    mode: str


@router.put("/decompiler-mode")
def put_decompiler_mode(body: DecompilerModeBody) -> dict[str, Any]:
    valid = {"apktool", "jadx", "hybrid"}
    if body.mode not in valid:
        raise HTTPException(400, f"mode must be one of {valid}")
    tree = load_settings_tree()
    merge_dict_into_tree(tree, {"analysis": {"decompiler_mode": body.mode}})
    _save_tree(tree)
    return {"decompiler_mode": body.mode}


class ToolPathBody(BaseModel):
    """Absolute or PATH-resolvable path to apktool / jadx (e.g. Windows .bat). Empty clears stored path."""

    path: Optional[str] = None


@router.get("/apktool-path")
def get_apktool_path() -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    p = (t.get("apktool") or {}).get("path")
    return {"path": (p or "") if isinstance(p, str) else ""}


@router.put("/apktool-path")
def put_apktool_path(body: ToolPathBody) -> dict[str, Any]:
    val = (body.path or "").strip()
    tree = load_settings_tree()
    merge_dict_into_tree(tree, {"apktool": {"path": val}})
    _save_tree(tree)
    return {"path": val}


@router.get("/jadx-path")
def get_jadx_path() -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    p = (t.get("jadx") or {}).get("path")
    return {"path": (p or "") if isinstance(p, str) else ""}


@router.put("/jadx-path")
def put_jadx_path(body: ToolPathBody) -> dict[str, Any]:
    val = (body.path or "").strip()
    tree = load_settings_tree()
    merge_dict_into_tree(tree, {"jadx": {"path": val}})
    _save_tree(tree)
    return {"path": val}


class JadxMaxHeapBody(BaseModel):
    """JVM -Xmx for JADX (e.g. 4096m, 8g). Empty string clears stored default."""

    max_heap: Optional[str] = None


@router.get("/jadx-max-heap")
def get_jadx_max_heap() -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    p = (t.get("jadx") or {}).get("max_heap")
    return {"max_heap": (p or "") if isinstance(p, str) else ""}


@router.put("/jadx-max-heap")
def put_jadx_max_heap(body: JadxMaxHeapBody) -> dict[str, Any]:
    raw = body.max_heap
    if raw is None or not str(raw).strip():
        val = ""
    else:
        try:
            val = normalize_jadx_max_heap_arg(raw)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
    tree = load_settings_tree()
    merge_dict_into_tree(tree, {"jadx": {"max_heap": val}})
    _save_tree(tree)
    return {"max_heap": val}


@router.get("/ubersigner-jar-path")
def get_ubersigner_jar_path() -> dict[str, Any]:
    t = tree_to_plain(load_settings_tree())
    u = t.get("ubersigner") or {}
    p = u.get("jar_path") if isinstance(u, dict) else None
    return {"path": (p or "") if isinstance(p, str) else ""}


@router.put("/ubersigner-jar-path")
def put_ubersigner_jar_path(body: ToolPathBody) -> dict[str, Any]:
    val = (body.path or "").strip()
    tree = load_settings_tree()
    merge_dict_into_tree(tree, {"ubersigner": {"jar_path": val}})
    _save_tree(tree)
    return {"path": val}


@router.get("/profiles")
def list_profiles() -> dict[str, Any]:
    if not PROFILE_DIR.is_dir():
        return {"profiles": []}
    names = sorted([p.stem for p in PROFILE_DIR.glob("*.yaml")])
    return {"profiles": names}


class ProfileCreateBody(BaseModel):
    name: str
    copy_from: Optional[str] = None


@router.post("/profiles")
def create_profile(body: ProfileCreateBody) -> dict[str, Any]:
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    dest = PROFILE_DIR / f"{body.name}.yaml"
    if dest.exists():
        raise HTTPException(400, "Profile already exists")
    if body.copy_from:
        src = PROFILE_DIR / f"{body.copy_from}.yaml"
        if not src.is_file():
            raise HTTPException(400, "copy_from profile not found")
        shutil.copy(src, dest)
    else:
        shutil.copy(DEFAULT_SETTINGS_PATH, dest)
    return {"name": body.name, "path": str(dest)}


@router.post("/profiles/{name}/switch")
def switch_profile(name: str) -> dict[str, Any]:
    src = PROFILE_DIR / f"{name}.yaml"
    if not src.is_file():
        raise HTTPException(404, "Profile not found")
    shutil.copy(src, DEFAULT_SETTINGS_PATH)
    return {"active": name}


@router.delete("/profiles/{name}")
def delete_profile(name: str) -> dict[str, Any]:
    p = PROFILE_DIR / f"{name}.yaml"
    if not p.is_file():
        raise HTTPException(404, "Profile not found")
    p.unlink()
    return {"deleted": name}
