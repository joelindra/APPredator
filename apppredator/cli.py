from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

from apppredator.bootstrap import configure_runtime

configure_runtime()

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.columns import Columns
from rich.align import Align
from rich.style import Style
from rich.theme import Theme
from rich.live import Live
from rich.spinner import Spinner
from rich import box

from core.config_loader import load_settings
from core import log
from core.logger import setup_logger
from core.scan_runner import ScanFlags, run_scan
from core.settings_io import load_settings_tree, merge_dict_into_tree, save_settings_tree, tree_to_plain

# ── Hacker Theme ─────────────────────────────────────────────────────────────

HACKER_THEME = Theme({
    "primary":      "bold bright_green",
    "secondary":    "bright_cyan",
    "accent":       "bold bright_yellow",
    "danger":       "bold bright_red",
    "muted":        "dim green",
    "dim_cyan":     "dim cyan",
    "success":      "bold green",
    "warning":      "bold yellow",
    "error":        "bold red on black",
    "info":         "cyan",
    "header":       "bold bright_green on black",
    "label":        "bold cyan",
    "value":        "bright_white",
})

console = Console(theme=HACKER_THEME)

# ── ASCII Banner ──────────────────────────────────────────────────────────────

BANNER = r"""
 █████╗ ██████╗ ██████╗ ██████╗ ███████╗██████╗  █████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
███████║██████╔╝██████╔╝██████╔╝█████╗  ██║  ██║███████║   ██║   ██║   ██║██████╔╝
██╔══██║██╔═══╝ ██╔═══╝ ██╔══██╗██╔══╝  ██║  ██║██╔══██║   ██║   ██║   ██║██╔══██╗
██║  ██║██║     ██║     ██║  ██║███████╗██████╔╝██║  ██║   ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
"""

TAGLINE = "[ LLM-Assisted Static Analysis for Android Packages  ·  APK / XAPK ]"
AUTHOR  = "Created by Joel Indra  ·  joelindra.cc  ·  hadesxploit.com"

def _print_banner() -> None:
    console.print()
    console.print(Align.center(Text(BANNER, style="bold bright_green")))
    console.print(Align.center(Text(TAGLINE, style="bold cyan")))
    console.print(Align.center(Text(AUTHOR,  style="dim green")))
    console.print()


def _divider(label: str = "") -> None:
    if label:
        console.print(Rule(f"[bold cyan] {label} [/]", style="green", characters="─"))
    else:
        console.print(Rule(style="dim green", characters="─"))


# ── Typer App ─────────────────────────────────────────────────────────────────

app = typer.Typer(
    epilog=(
        "Quick start: apppredator dashboard | "
        "apppredator analyze --help | apppredator settings --help | apppredator rules print\n\n"
        "Created By Joel Indra · joelindra.cc · hadesxploit.com"
    ),
    rich_markup_mode=None,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _print_rule_ids() -> None:
    from core.config_loader import RulesSettings

    _divider("DETECTION RULES")
    table = Table(
        show_header=True,
        header_style="bold bright_green",
        box=box.SIMPLE_HEAVY,
        border_style="green",
        min_width=50,
    )
    table.add_column("  #", style="dim cyan", justify="right", width=4)
    table.add_column("Rule Identifier", style="bright_green")

    for idx, rule in enumerate(RulesSettings.model_fields, start=1):
        table.add_row(f"{idx:02d}", f"[bold green]▸[/] {rule}")

    console.print()
    console.print(Align.center(table))
    console.print()


def print_rules_callback(value: bool):
    if value:
        _print_rule_ids()
        raise typer.Exit()


# ── Root Command ──────────────────────────────────────────────────────────────

@app.callback(invoke_without_command=True)
def _cli_root(
    ctx: typer.Context,
    verbose: bool      = typer.Option(False, "--verbose",      "-v", help="Emit verbose diagnostics to the log."),
    output: str        = typer.Option(None,  "--output",       "-o", help="Where to write the JSON report for the next analyze run."),
    no_decompile: bool = typer.Option(False, "--no-decompile",       help="Skip decompilation (faster, less context for rules)."),
    rules: str         = typer.Option(None,  "--rules",        "-r", help="Comma-separated list of detection rules to enable."),
    profile: str       = typer.Option(None,  "--profile",      "-p", help="Named YAML profile under config/profiles/."),
    print_rules: bool  = typer.Option(
        False, "--print-rules", "--list-rules",
        help="Print built-in detection rule ids and exit.",
        callback=print_rules_callback,
        is_eager=True,
    ),
):
    """APPredator: LLM-assisted static analysis for Android packages (APK / XAPK)."""
    if ctx.invoked_subcommand is None and not print_rules:
        _print_banner()
        _print_help_panel()
        raise typer.Exit(0)
    setup_logger(verbose)
    ctx.meta["output"]       = output
    ctx.meta["no_decompile"] = no_decompile
    ctx.meta["rules"]        = rules
    ctx.meta["profile"]      = profile


def _print_help_panel() -> None:
    """Pretty help overview shown when running `apppredator` with no args."""
    _divider("COMMANDS")

    table = Table(
        show_header=False,
        box=box.SIMPLE,
        border_style="dim green",
        min_width=72,
        padding=(0, 2),
    )
    table.add_column("Command",  style="bold bright_cyan", no_wrap=True, width=28)
    table.add_column("Description", style="bright_white")

    rows = [
        ("analyze  <APK_PATH>",     "Run static-analysis pipeline on an APK / XAPK"),
        ("dashboard",               "Start the FastAPI + Vite developer web UI"),
        ("web",                     "Start the developer web UI (alias for dashboard)"),
        ("settings setup",          "Interactive wizard for LLM provider config"),
        ("settings llm-provider",   "Show or set the active LLM provider"),
        ("settings llm-model",      "Show or set the active model name"),
        ("settings detection-rules","List / toggle detection rules"),
        ("settings dump",           "Dump merged settings as JSON"),
        ("settings verify",         "Validate config/settings.yaml"),
        ("settings surface-map",    "Toggle attack-surface-map generation"),
        ("settings xref-context",   "Toggle call-graph context injection"),
        ("settings analysis-filter","Show or set static/llm/hybrid mode"),
        ("settings decompiler",     "Show or set decompiler backend"),
        ("settings profiles new",   "Create a named YAML profile"),
        ("settings profiles list",  "List available profiles"),
        ("settings profiles use",   "Activate a saved profile"),
        ("settings profiles remove","Delete a profile"),
        ("rules print",             "Print all built-in rule identifiers"),
    ]
    for cmd, desc in rows:
        table.add_row(f"[bold bright_green]▸[/] {cmd}", desc)

    console.print()
    console.print(Align.center(table))

    console.print()
    footer = Panel(
        Text.from_markup(
            "[dim cyan]Flags available on every run:[/]\n"
            "  [bold bright_green]-v[/]  verbose     "
            "  [bold bright_green]-o[/]  output path     "
            "  [bold bright_green]-r[/]  rule list     "
            "  [bold bright_green]-p[/]  profile"
        ),
        border_style="dim green",
        padding=(0, 2),
    )
    console.print(Align.center(footer))
    console.print()


# ── analyze / scan ────────────────────────────────────────────────────────────

def _run_analyze(ctx: typer.Context, apk_path: str | None, generate_exploit: bool, scan_libraries: bool) -> None:
    if not apk_path or not str(apk_path).strip():
        console.print()
        console.print(Panel(
            Text.from_markup(
                "[bold red]✗ Missing APK path.[/]\n\n"
                "[bold cyan]Usage:[/]\n"
                "  [bright_green]apppredator analyze[/] [dim]\\[OPTIONS][/] [bright_white]<path-to.apk>[/]\n\n"
                "[bold cyan]Examples:[/]\n"
                "  apppredator analyze [bright_white]./builds/myapp.apk[/]\n"
                "  apppredator analyze -o report.json [bright_white].\\samples\\demo.apk[/]\n\n"
                "[dim]Full reference: apppredator analyze --help[/]"
            ),
            title="[bold red]⚠ ERROR[/]",
            border_style="red",
            padding=(1, 3),
        ))
        console.print()
        raise typer.Exit(2)

    output      = ctx.meta["output"]
    no_decompile = ctx.meta["no_decompile"]
    rules       = ctx.meta["rules"]
    profile     = ctx.meta["profile"]

    _print_banner()
    _divider("INITIATING SCAN")

    # ── Scan details panel ────────────────────────────────────────────────────
    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column("Key",   style="bold cyan",    no_wrap=True)
    info_table.add_column("Value", style="bright_white")

    info_table.add_row("[bold green]▸[/] Target",          str(apk_path))
    info_table.add_row("[bold green]▸[/] Output",          str(output) if output else "[dim]stdout[/]")
    info_table.add_row("[bold green]▸[/] Profile",         str(profile) if profile else "[dim]default[/]")
    info_table.add_row("[bold green]▸[/] Rules",           str(rules)   if rules   else "[dim]all enabled[/]")
    info_table.add_row("[bold green]▸[/] Decompile",       "[red]SKIPPED[/]" if no_decompile else "[green]YES[/]")
    info_table.add_row("[bold green]▸[/] Gen Exploit",     "[green]YES[/]"   if generate_exploit else "[dim]no[/]")
    info_table.add_row("[bold green]▸[/] Scan Libraries",  "[green]YES[/]"   if scan_libraries   else "[dim]no[/]")

    console.print(Panel(info_table, title="[bold bright_cyan]⚙ SCAN CONFIGURATION[/]", border_style="cyan", padding=(1, 2)))
    console.print()

    log.info("Starting APPredator analysis...")
    flags = ScanFlags(
        output=output,
        no_decompile=no_decompile,
        rules=rules,
        profile=profile,
        generate_exploit=generate_exploit,
        scan_libraries=scan_libraries,
    )
    result = run_scan(apk_path, flags, settings_overrides=None)

    console.print()
    if result.success:
        console.print(Panel(
            Align.center(Text("✓  SCAN COMPLETED SUCCESSFULLY", style="bold bright_green")),
            border_style="green",
            padding=(1, 4),
        ))
    else:
        console.print(Panel(
            Text.from_markup(f"[bold red]✗ Analysis failed:[/]\n  [red]{result.error}[/]"),
            title="[bold red]SCAN FAILED[/]",
            border_style="red",
            padding=(1, 2),
        ))
        log.error(f"Analysis failed: {result.error}")
    console.print()


@app.command("analyze")
def analyze(
    ctx: typer.Context,
    apk_path: str | None = typer.Argument(None, metavar="APK_PATH", help="Filesystem path to the .apk or .xapk package."),
    generate_exploit: bool = typer.Option(False, "--generate-exploit", help="Emit PoC scripts for supported findings."),
    scan_libraries: bool   = typer.Option(False, "--scan-libraries",   help="Include third-party packages in scope."),
):
    """Run the static analysis pipeline on one Android package."""
    _run_analyze(ctx, apk_path, generate_exploit, scan_libraries)


@app.command("scan", deprecated=True, hidden=True)
def scan_legacy(
    ctx: typer.Context,
    apk_path: str | None   = typer.Argument(None, metavar="APK_PATH"),
    generate_exploit: bool = typer.Option(False, "--generate-exploit"),
    scan_libraries: bool   = typer.Option(False, "--scan-libraries"),
):
    """Deprecated alias for ``analyze``."""
    _run_analyze(ctx, apk_path, generate_exploit, scan_libraries)


# ── settings sub-app ──────────────────────────────────────────────────────────

settings_app = typer.Typer(help="Inspect and edit persisted YAML (config/settings.yaml).")
app.add_typer(settings_app, name="settings")


def _setting_changed(key: str, value: str) -> None:
    console.print(Panel(
        Text.from_markup(f"[bold cyan]{key}[/]  →  [bold bright_green]{value}[/]"),
        title="[bold green]✓ SETTING UPDATED[/]",
        border_style="green",
        padding=(0, 3),
    ))


def _setting_show(key: str, value: str) -> None:
    console.print(Panel(
        Text.from_markup(f"[bold cyan]{key}[/]  →  [bold bright_white]{value}[/]"),
        title="[bold cyan]ℹ CURRENT VALUE[/]",
        border_style="cyan",
        padding=(0, 3),
    ))


@settings_app.command("llm-provider")
def llm_provider(
    provider: str | None = typer.Argument(None, help="Provider id (ollama, gemini, groq, …). Omit to print active value."),
):
    """Show or set the active LLM provider."""
    tree = load_settings_tree() or {}
    if provider is None:
        t   = tree_to_plain(tree)
        val = (t.get("llm") or {}).get("provider") or "[dim]not set[/]"
        _setting_show("LLM Provider", val)
        return
    merge_dict_into_tree(tree, {"llm": {"provider": provider}})
    save_settings_tree(tree)
    _setting_changed("LLM Provider", provider)


@settings_app.command("llm-model")
def llm_model(
    model: str | None = typer.Argument(None, help="Model id for the current provider. Omit to print active value."),
):
    """Show or set the model name for the active provider."""
    tree     = load_settings_tree() or {}
    t        = tree_to_plain(tree)
    provider = (t.get("llm") or {}).get("provider")

    _model_keys = {
        "ollama":     "model",
        "gemini":     "gemini_model",
        "groq":       "groq_model",
        "openai":     "openai_model",
        "anthropic":  "anthropic_model",
        "openrouter": "openrouter_model",
        "deepseek":   "deepseek_model",
    }

    if model is None:
        if not provider:
            console.print("[warning]LLM provider is not set. Run: apppredator settings llm-provider <provider>[/]")
        else:
            key           = _model_keys.get(provider)
            current_model = (t.get("llm") or {}).get(key) if key else None
            _setting_show(f"LLM Model  [{provider}]", current_model or "[dim]not set[/]")
        return

    if not provider:
        console.print(Panel(
            "[bold yellow]⚠  Set a provider first:[/]\n  apppredator settings llm-provider <provider>",
            border_style="yellow", padding=(0, 2),
        ))
        raise typer.Exit()

    key = _model_keys.get(provider)
    if not key:
        console.print(f"[error] Unknown provider: {provider}[/]")
        raise typer.Exit()

    merge_dict_into_tree(tree, {"llm": {key: model}})
    save_settings_tree(tree)
    _setting_changed(f"LLM Model  [{provider}]", model)


@settings_app.command("detection-rules")
def detection_rules(
    rules_arg: str | None = typer.Argument(None, help="Comma-separated rule ids."),
    enable:  bool = typer.Option(False, "--enable"),
    disable: bool = typer.Option(False, "--disable"),
):
    """List enabled detection rules, or toggle specific ids on/off."""
    tree      = load_settings_tree() or {}
    t         = tree_to_plain(tree)
    rules_map = dict(t.get("rules") or {})

    if rules_arg is None:
        _divider("ENABLED DETECTION RULES")
        table = Table(show_header=False, box=box.SIMPLE, border_style="dim green", padding=(0, 2))
        table.add_column("Rule", style="bright_green")
        table.add_column("Status", style="bold green")
        for rule, is_on in rules_map.items():
            if is_on:
                table.add_row(f"[bold green]▸[/] {rule}", "● ON")
        console.print()
        console.print(Align.center(table))
        console.print()
        return

    rules_to_change = [r.strip() for r in rules_arg.split(",")]
    for rule in rules_to_change:
        if enable:
            rules_map[rule] = True
            console.print(f"[success]  ✓ Enabled :[/]  [bright_cyan]{rule}[/]")
        elif disable:
            rules_map[rule] = False
            console.print(f"[danger]  ✗ Disabled:[/]  [bright_cyan]{rule}[/]")

    merge_dict_into_tree(tree, {"rules": rules_map})
    save_settings_tree(tree)
    console.print()
    console.print("[success]Detection rules updated.[/]")


@settings_app.command("dump")
def dump_settings():
    """Print the merged settings object as JSON (useful for debugging)."""
    try:
        settings = load_settings()
        _divider("SETTINGS DUMP")
        console.print_json(settings.model_dump_json(indent=2))
    except Exception as e:
        console.print(f"[error] Could not load settings: {e}[/]")


@settings_app.command("verify")
def verify_settings():
    """Validate config/settings.yaml against the internal schema."""
    try:
        load_settings()
        console.print(Panel(
            Align.center(Text("✓  config/settings.yaml is VALID", style="bold bright_green")),
            border_style="green", padding=(0, 4),
        ))
    except Exception as e:
        console.print(Panel(
            Text.from_markup(f"[bold red]✗ Settings file is INVALID:[/]\n\n  [red]{e}[/]"),
            title="[bold red]VALIDATION ERROR[/]",
            border_style="red", padding=(1, 2),
        ))


def _toggle_setting(tree_path: dict, label: str, current: bool, new_val: bool | None) -> None:
    """Generic toggle helper used by surface-map and xref-context."""
    tree = load_settings_tree() or {}
    t    = tree_to_plain(tree)

    if new_val is None:
        state = "[bold green]ENABLED[/]" if current else "[bold red]DISABLED[/]"
        console.print(Panel(
            Text.from_markup(f"[bold cyan]{label}[/]  →  {state}"),
            title="[bold cyan]ℹ CURRENT STATE[/]",
            border_style="cyan", padding=(0, 3),
        ))
        return

    merge_dict_into_tree(tree, tree_path)
    save_settings_tree(tree)
    state = "[bold green]ENABLED[/]" if new_val else "[bold red]DISABLED[/]"
    _setting_changed(label, "enabled" if new_val else "disabled")


@settings_app.command("surface-map")
def surface_map(
    enable:  bool = typer.Option(False, "--enable"),
    disable: bool = typer.Option(False, "--disable"),
):
    """Toggle automatic generation of the high-level attack-surface map."""
    tree = load_settings_tree() or {}
    t    = tree_to_plain(tree)
    cur  = (t.get("analysis") or {}).get("generate_attack_surface_map", False)

    if not enable and not disable:
        _toggle_setting({}, "Attack-Surface Map", cur, None)
        return
    new_val = True if enable else False
    merge_dict_into_tree(tree, {"analysis": {"generate_attack_surface_map": new_val}})
    save_settings_tree(tree)
    _setting_changed("Attack-Surface Map", "enabled" if new_val else "disabled")


@settings_app.command("xref-context")
def xref_context(
    enable:  bool = typer.Option(False, "--enable"),
    disable: bool = typer.Option(False, "--disable"),
):
    """Toggle cross-reference (call-graph) context injection for the LLM."""
    tree = load_settings_tree() or {}
    t    = tree_to_plain(tree)
    cur  = (t.get("analysis") or {}).get("use_cross_reference_context", True)

    if not enable and not disable:
        _toggle_setting({}, "Cross-Reference Context", cur, None)
        return
    new_val = True if enable else False
    merge_dict_into_tree(tree, {"analysis": {"use_cross_reference_context": new_val}})
    save_settings_tree(tree)
    _setting_changed("Cross-Reference Context", "enabled" if new_val else "disabled")


@settings_app.command("analysis-filter")
def analysis_filter(
    mode: str | None = typer.Argument(None, help="One of: static_only, llm_only, hybrid."),
):
    """Show or set how static heuristics and the LLM are combined."""
    valid_modes = ["static_only", "llm_only", "hybrid"]
    tree = load_settings_tree() or {}
    t    = tree_to_plain(tree)

    if mode is None:
        current = (t.get("analysis") or {}).get("filter_mode", "llm_only")
        _setting_show("Analysis Filter", current)
        return

    if mode not in valid_modes:
        console.print(Panel(
            Text.from_markup(
                f"[bold red]✗ Invalid mode:[/] [bright_white]{mode}[/]\n\n"
                f"[dim]Valid options:[/] [bright_cyan]{', '.join(valid_modes)}[/]"
            ),
            title="[bold red]ERROR[/]", border_style="red", padding=(0, 2),
        ))
        raise typer.Exit()

    merge_dict_into_tree(tree, {"analysis": {"filter_mode": mode}})
    save_settings_tree(tree)
    _setting_changed("Analysis Filter", mode)


@settings_app.command("decompiler")
def decompiler(
    mode: str | None = typer.Argument(None, help="One of: apktool, jadx, hybrid."),
):
    """Show or set which decompiler back-end backs the pipeline."""
    valid_modes = ["apktool", "jadx", "hybrid"]
    tree = load_settings_tree() or {}
    t    = tree_to_plain(tree)

    if mode is None:
        current = (t.get("analysis") or {}).get("decompiler_mode", "apktool")
        _setting_show("Decompiler Mode", current)
        return

    if mode not in valid_modes:
        console.print(Panel(
            Text.from_markup(
                f"[bold red]✗ Invalid mode:[/] [bright_white]{mode}[/]\n\n"
                f"[dim]Valid options:[/] [bright_cyan]{', '.join(valid_modes)}[/]"
            ),
            title="[bold red]ERROR[/]", border_style="red", padding=(0, 2),
        ))
        raise typer.Exit()

    merge_dict_into_tree(tree, {"analysis": {"decompiler_mode": mode}})
    save_settings_tree(tree)
    _setting_changed("Decompiler Mode", mode)


# ── Interactive Setup ─────────────────────────────────────────────────────────

def run_interactive_setup() -> None:
    _print_banner()
    _divider("INTERACTIVE LLM SETUP")
    console.print()

    providers = ["ollama", "gemini", "groq", "openai", "anthropic", "openrouter", "deepseek"]

    table = Table(show_header=False, box=box.SIMPLE, border_style="dim green", padding=(0, 2), min_width=40)
    table.add_column("", style="dim cyan", width=4)
    table.add_column("Provider", style="bright_cyan")
    for i, p in enumerate(providers, start=1):
        table.add_row(f"[dim]{i}[/]", p)
    console.print(Align.center(table))
    console.print()

    provider = typer.prompt("  LLM provider")

    if provider == "ollama":
        model      = typer.prompt("  Ollama model name")
        ollama_url = typer.prompt("  Ollama base URL")
        settings   = {"llm": {"provider": provider, "model": model, "ollama_url": ollama_url}}
    elif provider == "gemini":
        gemini_model = typer.prompt("  Gemini model name")
        api_key      = typer.prompt("  Gemini API key", hide_input=True)
        settings     = {"llm": {"provider": provider, "gemini_model": gemini_model, "api_key": api_key}}
    elif provider == "groq":
        groq_model   = typer.prompt("  Groq model name")
        groq_api_key = typer.prompt("  Groq API key", hide_input=True)
        settings     = {"llm": {"provider": provider, "groq_model": groq_model, "groq_api_key": groq_api_key}}
    elif provider == "openai":
        openai_model   = typer.prompt("  OpenAI model name")
        openai_api_key = typer.prompt("  OpenAI API key", hide_input=True)
        settings       = {"llm": {"provider": provider, "openai_model": openai_model, "openai_api_key": openai_api_key}}
    elif provider == "anthropic":
        anthropic_model   = typer.prompt("  Anthropic model name")
        anthropic_api_key = typer.prompt("  Anthropic API key", hide_input=True)
        settings          = {"llm": {"provider": provider, "anthropic_model": anthropic_model, "anthropic_api_key": anthropic_api_key}}
    elif provider == "openrouter":
        openrouter_model   = typer.prompt("  OpenRouter model name")
        openrouter_api_key = typer.prompt("  OpenRouter API key", hide_input=True)
        settings           = {"llm": {"provider": provider, "openrouter_model": openrouter_model, "openrouter_api_key": openrouter_api_key}}
    elif provider == "deepseek":
        deepseek_model   = typer.prompt("  DeepSeek model name", default="deepseek-v4-pro")
        deepseek_api_key = typer.prompt("  DeepSeek API key", hide_input=True)
        settings         = {"llm": {"provider": provider, "deepseek_model": deepseek_model, "deepseek_api_key": deepseek_api_key}}
    else:
        console.print(Panel("[bold red]✗ Unsupported provider.[/]", border_style="red", padding=(0, 2)))
        raise typer.Exit()

    tree = load_settings_tree() or {}
    merge_dict_into_tree(tree, settings)
    save_settings_tree(tree)
    console.print()
    console.print(Panel(
        Align.center(Text("✓  Saved to config/settings.yaml", style="bold bright_green")),
        border_style="green", padding=(0, 4),
    ))
    console.print()


@settings_app.command("setup")
def setup_interactive():
    """Launch the interactive terminal wizard for core LLM fields."""
    run_interactive_setup()


# ── Profiles ──────────────────────────────────────────────────────────────────

profiles_app = typer.Typer(help="Manage named YAML profiles under config/profiles/.")
settings_app.add_typer(profiles_app, name="profiles")


@profiles_app.callback(invoke_without_command=True)
def profiles_callback(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        profiles_list()


@profiles_app.command("new")
def profiles_new(name: str):
    """Create a profile: runs interactive setup, then stores result as <name>.yaml."""
    profile_dir  = "config/profiles"
    os.makedirs(profile_dir, exist_ok=True)
    profile_path = os.path.join(profile_dir, f"{name}.yaml")

    if os.path.exists(profile_path):
        console.print(Panel(
            f"[bold yellow]⚠  Profile [bright_white]'{name}'[/] already exists.[/]",
            border_style="yellow", padding=(0, 2),
        ))
        raise typer.Exit()

    console.print(f"\n[info]Creating profile: [bold]{name}[/][/]\n")
    run_interactive_setup()
    os.rename("config/settings.yaml", profile_path)
    console.print(Panel(
        Align.center(Text(f"✓  Profile '{name}' saved", style="bold bright_green")),
        border_style="green", padding=(0, 4),
    ))


@profiles_app.command("list")
def profiles_list():
    """Print every profile name on disk."""
    profile_dir = "config/profiles"
    if not os.path.exists(profile_dir):
        console.print("[warning]No profiles directory yet.[/]")
        raise typer.Exit()

    profiles = [f.replace(".yaml", "") for f in os.listdir(profile_dir) if f.endswith(".yaml")]
    if not profiles:
        console.print("[warning]No profiles found.[/]")
        raise typer.Exit()

    _divider("AVAILABLE PROFILES")
    table = Table(show_header=False, box=box.SIMPLE, border_style="dim green", padding=(0, 2), min_width=36)
    table.add_column("Profile", style="bright_cyan")
    for p in sorted(profiles):
        table.add_row(f"[bold green]▸[/] {p}")
    console.print()
    console.print(Align.center(table))
    console.print()


@profiles_app.command("use")
def profiles_use(name: str):
    """Copy the chosen profile over config/settings.yaml (becomes the active preset)."""
    profile_path = os.path.join("config/profiles", f"{name}.yaml")
    if not os.path.exists(profile_path):
        console.print(Panel(
            f"[bold red]✗  Profile [bright_white]'{name}'[/] not found.[/]",
            border_style="red", padding=(0, 2),
        ))
        raise typer.Exit()
    shutil.copy(profile_path, "config/settings.yaml")
    _setting_changed("Active Profile", name)


@profiles_app.command("remove")
def profiles_remove(name: str):
    """Delete a profile file from config/profiles/."""
    profile_path = os.path.join("config/profiles", f"{name}.yaml")
    if not os.path.exists(profile_path):
        console.print(Panel(
            f"[bold red]✗  Profile [bright_white]'{name}'[/] not found.[/]",
            border_style="red", padding=(0, 2),
        ))
        raise typer.Exit()
    os.remove(profile_path)
    console.print(Panel(
        Align.center(Text(f"✓  Profile '{name}' removed", style="bold bright_green")),
        border_style="green", padding=(0, 4),
    ))


# ── Dashboard ─────────────────────────────────────────────────────────────────

def _print_dashboard_instructions(root: Path, api_port: str) -> None:
    _print_banner()
    _divider("WEB DASHBOARD SETUP")

    steps = [
        ("1", "Open a shell in the repository root"),
        ("2", "Install Python package:       [bold bright_green]pip install -e .[/]"),
        ("3", "Install root Node deps:        [bold bright_green]npm install[/]"),
        ("4", "Install UI deps:               [bold bright_green]npm run install:web[/]"),
        ("5", "Start API + Vite:              [bold bright_green]npm run dev[/]   (shortcut: apppredator dashboard)"),
    ]

    table = Table(show_header=False, box=None, padding=(0, 2), min_width=70)
    table.add_column("Step", style="bold cyan", width=4)
    table.add_column("Action")
    for step, action in steps:
        table.add_row(step, Text.from_markup(action))

    console.print()
    console.print(Panel(table, title="[bold bright_cyan]⚙ SETUP STEPS[/]", border_style="cyan", padding=(1, 2)))

    meta_table = Table(show_header=False, box=None, padding=(0, 2))
    meta_table.add_column("Key",   style="bold cyan")
    meta_table.add_column("Value", style="bright_white")
    meta_table.add_row("API base URL",    f"http://127.0.0.1:{api_port}  [dim](override: APPREDATOR_API_PORT)[/]")
    meta_table.add_row("Frontend URL",    "http://localhost:5173  [dim](proxies /api to API)[/]")
    meta_table.add_row("API only",        "[bright_green]npm run api[/]")
    meta_table.add_row("Production UI",   "[bright_green]npm run build[/]  →  serve with uvicorn")
    meta_table.add_row("Repository root", str(root))

    console.print(Panel(meta_table, title="[bold bright_cyan]ℹ INFO[/]", border_style="dim cyan", padding=(1, 2)))
    console.print()


def _run_npm_dev(root: Path) -> None:
    npm = shutil.which("npm") or shutil.which("npm.cmd")
    if not npm:
        console.print(Panel(
            Text.from_markup(
                "[bold red]✗ npm not found on PATH.[/]\n\n"
                "Install [bold]Node.js LTS[/], then run:\n"
                "  [bright_green]npm install && npm run install:web[/]"
            ),
            title="[bold red]DEPENDENCY ERROR[/]",
            border_style="red", padding=(1, 2),
        ))
        raise typer.Exit(1)

    log.info(f"Launching npm run dev in {root} ...")
    try:
        code = subprocess.run([npm, "run", "dev"], cwd=str(root), check=False).returncode
    except KeyboardInterrupt:
        raise typer.Exit(0) from None
    raise typer.Exit(code if code not in (None, 0) else 0)


@app.command("dashboard")
def dashboard(
    instructions_only: bool = typer.Option(False, "--instructions", "-i", help="Print setup instructions only."),
    dev: bool = typer.Option(False, "--dev", "-d", help="Run in live-reloading developer mode (requires Node.js/npm)."),
):
    """Start the FastAPI + React Web UI."""
    from apppredator.paths import project_root
    import webbrowser
    import threading
    import time

    root     = project_root()
    api_port = "8765" if platform.system() == "Windows" else "8080"
    api_port = os.environ.get("APPREDATOR_API_PORT", api_port)

    if instructions_only:
        _print_dashboard_instructions(root, api_port)
        return

    _print_banner()

    dist_dir = root / "web" / "frontend" / "dist"

    if dev:
        console.print(Panel(
            Text.from_markup(
                f"[bold green]>[/] API:      [bright_white]http://127.0.0.1:{api_port}[/]\n"
                f"[bold green]>[/] Frontend: [bright_white]http://localhost:5173[/]  [dim](follow Vite output)[/]\n\n"
                f"[dim]Press Ctrl+C to stop.   Instructions: apppredator dashboard --instructions\n"
                f"API hot-reload opt-in: export APPREDATOR_API_RELOAD=1[/]"
            ),
            title="[bold bright_cyan]LAUNCHING DEVELOPER STACK[/]",
            border_style="cyan", padding=(1, 2),
        ))
        console.print()
        _run_npm_dev(root)
    else:
        # Production Mode (Direct Python Uvicorn Runner)
        console.print(Panel(
            Text.from_markup(
                f"[bold green]>[/] Mode:      [bold bright_green]Local Production (Self-Hosted)[/]\n"
                f"[bold green]>[/] Web UI:    [bold bright_white]http://127.0.0.1:{api_port}/ui/[/]\n"
                f"[bold green]>[/] Docs/API:  [bright_white]http://127.0.0.1:{api_port}/docs[/]\n\n"
                f"[dim]Launching server locally. Press Ctrl+C to stop.[/]"
            ),
            title="[bold bright_cyan]LAUNCHING APPREDATOR WEB UI[/]",
            border_style="green", padding=(1, 2),
        ))
        console.print()

        if not dist_dir.is_dir():
            console.print(Panel(
                Text.from_markup(
                    "[bold yellow]Production UI Assets Not Found![/]\n\n"
                    f"Directory [bright_white]web/frontend/dist[/] does not exist.\n"
                    "The backend will run, but the Web UI under [bright_white]/ui/[/] will return 404.\n\n"
                    "[bold cyan]How to resolve:[/]\n"
                    "  1. Compile assets:  [bright_green]npm install && npm run build[/]\n"
                    "  2. Or run dev mode: [bright_green]apppredator web --dev[/]\n"
                    "  3. Or run via:      [bright_green]docker compose up[/]"
                ),
                title="[bold yellow]WARNING[/]",
                border_style="yellow", padding=(1, 2),
            ))
            console.print()

        # Open web browser after a short delay
        ui_url = f"http://127.0.0.1:{api_port}/ui/"
        def _open_browser():
            time.sleep(1.5)
            try:
                webbrowser.open_new_tab(ui_url)
            except Exception:
                pass
        threading.Thread(target=_open_browser, daemon=True).start()

        import uvicorn
        try:
            # Set the environment variable for uvicorn port if needed
            os.environ["APPREDATOR_API_PORT"] = api_port
            uvicorn.run("web.backend.main:app", host="127.0.0.1", port=int(api_port), reload=False, log_level="info")
        except KeyboardInterrupt:
            console.print("\n[info]Stopping APPredator Web Server...[/]")
            raise typer.Exit(0)
        except Exception as e:
            console.print(f"[error]Failed to start server: {e}[/]")
            raise typer.Exit(1)


@app.command("web", hidden=False)
def web_legacy(
    instructions_only: bool = typer.Option(False, "--instructions", "-i", help="Print setup instructions only."),
    dev: bool = typer.Option(False, "--dev", "-d", help="Run in live-reloading developer mode (requires Node.js/npm)."),
):
    """Start the FastAPI + React Web UI."""
    dashboard(instructions_only, dev)


# ── Rules sub-app ─────────────────────────────────────────────────────────────

rules_app = typer.Typer(help="Utilities for the built-in detection rule catalog.")
app.add_typer(rules_app, name="rules")


@rules_app.command("print")
def rules_print():
    """Print every built-in detection rule id."""
    _print_rule_ids()


@app.command("list-rules", deprecated=True, hidden=True)
def list_rules_legacy():
    """Deprecated; prefer: apppredator rules print"""
    _print_rule_ids()


# ── Entrypoint ────────────────────────────────────────────────────────────────

def main() -> None:
    """Console entrypoint (see pyproject.toml [project.scripts])."""
    app()


if __name__ == "__main__":
    main()