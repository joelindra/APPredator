import os
import sys
import logging
from typing import Dict, Any
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Constants
CONFIG_REL_PATH = "config/settings.yaml"
INPUT_PREFIX = "INPUT_"


def load_settings(config_path: str) -> Dict[str, Any]:
    """Loads the YAML configuration file securely."""
    if not os.path.exists(config_path):
        logger.warning(
            f"Configuration file not found at {config_path}. Starting with empty settings."
        )
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML configuration: {e}")
        sys.exit(1)
    except OSError as e:
        logger.error(f"Error reading configuration file: {e}")
        sys.exit(1)


def save_settings(config_path: str, settings: Dict[str, Any]) -> None:
    """Saves the settings dictionary to the YAML file."""
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(config_path), exist_ok=True)

        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(settings, f, default_flow_style=False)
        logger.info(f"Configuration successfully saved to {config_path}")
    except OSError as e:
        logger.error(f"Failed to save configuration: {e}")
        sys.exit(1)


def apply_llm_settings(settings: Dict[str, Any]) -> None:
    """Injects CI/CD environment variables into the settings."""
    # GitHub Actions inputs are usually passed as INPUT_NAME (uppercase).
    # We check both underscore and dash formats to be safe.
    provider = os.environ.get(f"{INPUT_PREFIX}PROVIDER") or os.environ.get(
        f"{INPUT_PREFIX}PROVIDER".replace("_", "-")
    )
    model = os.environ.get(f"{INPUT_PREFIX}MODEL") or os.environ.get(
        f"{INPUT_PREFIX}MODEL".replace("_", "-")
    )

    # Critical: API Key might be passed as INPUT_API_KEY or INPUT_API-KEY
    api_key = os.environ.get(f"{INPUT_PREFIX}API_KEY") or os.environ.get(
        f"{INPUT_PREFIX}API-KEY"
    )

    # Debug Logging (Sanitized)
    logger.info(
        f"Environment check - Provider found: {bool(provider)}, API Key found: {bool(api_key)}"
    )

    if provider:
        # Ensure 'llm' section exists
        if "llm" not in settings:
            settings["llm"] = {}

        settings["llm"]["provider"] = provider
        logger.info(f"LLM Provider set to: {provider}")

        # Model Configuration Mapping
        # Maps provider names to their specific model configuration keys
        model_config_map = {
            "ollama": "model",
            "gemini": "gemini_model",
            "groq": "groq_model",
            "openai": "openai_model",
            "anthropic": "anthropic_model",
            "openrouter": "openrouter_model",
            "deepseek": "deepseek_model",
        }

        # API Key Configuration Mapping
        api_key_map = {
            "gemini": "api_key",
            "groq": "groq_api_key",
            "openai": "openai_api_key",
            "anthropic": "anthropic_api_key",
            "openrouter": "openrouter_api_key",
            "deepseek": "deepseek_api_key",
        }

        # Update Model
        if model:
            key = model_config_map.get(provider)
            if key:
                settings["llm"][key] = model
                logger.info(f"Model set to: {model} for provider {provider}")
            else:
                logger.warning(
                    f"Unknown provider '{provider}' for model configuration."
                )

        # Update API Key
        if api_key:
            key = api_key_map.get(provider)
            if key:
                settings["llm"][key] = api_key
                logger.info("API Key injected successfully.")
            elif provider != "ollama":  # Ollama typically doesn't use API key
                logger.error(f"CRITICAL: No API key found for provider '{provider}'.")
                logger.error(
                    "Please check your GitHub Secrets and workflow configuration."
                )
                logger.error(
                    "Expected environment variables: INPUT_API_KEY or INPUT_API-KEY"
                )
                sys.exit(1)


def apply_rule_settings(settings: Dict[str, Any]) -> None:
    """Parses and applies rule settings from environment variables."""
    rules_input = os.environ.get(f"{INPUT_PREFIX}RULES")

    if not rules_input:
        return

    logger.info(f"Processing rules input: {rules_input}")

    if "rules" not in settings:
        settings["rules"] = {}

    # Rules format: "rule_name:true, other_rule:false"
    try:
        rules_list = [r.strip() for r in rules_input.split(",")]

        # Get valid rule keys from the loaded settings
        valid_rules = set(settings.get("rules", {}).keys())

        for rule_entry in rules_list:
            if ":" not in rule_entry:
                logger.warning(
                    f"Invalid rule format ignored: {rule_entry}. Expected 'name:boolean'"
                )
                continue

            name, value = rule_entry.split(":", 1)
            name = name.strip()
            value = value.strip().lower()

            # Validation: Check if rule exists based on default settings
            if name not in valid_rules:
                logger.warning(
                    f"Unknown rule ignored: '{name}'. Did you mean one of: {list(valid_rules)[:5]}...?"
                )
                continue

            if value in ("true", "1", "yes"):
                settings["rules"][name] = True
                logger.info(f"Rule '{name}' ENABLED via input.")
            elif value in ("false", "0", "no"):
                settings["rules"][name] = False
                logger.info(f"Rule '{name}' DISABLED via input.")
            else:
                logger.warning(f"Invalid boolean value for rule '{name}': {value}")

    except Exception as e:
        logger.error(f"Failed to parse specific rules: {e}")


def merge_custom_config(default_settings: Dict[str, Any]) -> Dict[str, Any]:
    """Merges a custom configuration file if provided."""
    # The workspace path inside the container usually maps to /github/workspace
    # We need to find if the user provided a relative path
    workspace = os.environ.get("GITHUB_WORKSPACE", "/github/workspace")
    config_path_input = os.environ.get(f"{INPUT_PREFIX}CONFIG_PATH") or os.environ.get(
        f"{INPUT_PREFIX}CONFIG-PATH"
    )

    if not config_path_input:
        return default_settings

    # Resolve absolute path
    if config_path_input.startswith("/"):
        full_path = config_path_input
    else:
        full_path = os.path.join(workspace, config_path_input)

    logger.info(f"Attempting to load custom config from: {full_path}")

    custom_settings = load_settings(full_path)

    if not custom_settings:
        logger.warning("Custom config was empty or NOT FOUND. Using defaults only.")
        return default_settings

    # Recursive merge is ideal, but for now a top-level update + specific section update is "good enough"
    # for our flat structure. Ideally we use a deep merge library, but we want to stick to stdlib + yaml.

    # Simple strategy: Update defaults with custom.
    # Note: dictionary.update() is shallow. We need to be careful about nested dicts like 'llm' and 'rules'.
    # A true professional system would implement deep merge.

    def deep_update(source, overrides):
        for key, value in overrides.items():
            if isinstance(value, dict) and value:
                returned = deep_update(source.get(key, {}), value)
                source[key] = returned
            else:
                source[key] = overrides[key]
        return source

    merged = deep_update(default_settings, custom_settings)
    logger.info("Custom configuration merged successfully.")
    return merged


def main():
    """Main entry point for CI configuration."""
    logger.info("Starting APPredator CI Configurator...")

    # Resolve paths relative to this script: scripts/ci/configurator.py
    # Application root is two levels up: ../../
    base_dir = os.path.dirname(os.path.abspath(__file__))
    app_root = os.path.dirname(os.path.dirname(base_dir))
    config_path = os.path.join(app_root, CONFIG_REL_PATH)

    logger.info(f"Loading configuration from: {config_path}")

    # 1. Load Base Defaults
    settings = load_settings(config_path)

    # 2. Merge Custom Config (if any) - This overrides defaults
    settings = merge_custom_config(settings)

    # 3. Apply Environment Variable Overrides (Action Inputs) - These have highest precedence
    apply_llm_settings(settings)
    apply_rule_settings(settings)

    # 4. Save Final Config
    save_settings(config_path, settings)


if __name__ == "__main__":
    main()
