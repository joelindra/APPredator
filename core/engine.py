from .config_loader import Settings
from core import log
from modules.decompiler.apktool_handler import ApktoolHandler
from modules.decompiler.jadx_handler import JadxHandler
from modules.static_analyzer.code_filter import CodeFilter
from modules.llm_client.ollama import OllamaClient
from modules.llm_client.gemini import GeminiClient
from modules.llm_client.groq import GroqClient
from modules.llm_client.openai import OpenAIClient
from modules.llm_client.anthropic import AnthropicClient
from modules.llm_client.openrouter import OpenRouterClient
from modules.llm_client.deepseek import DeepSeekClient
from core.call_graph import CallGraphBuilder
from core.manifest_parser import ManifestParser
from core.baseline_store import extract_application_id
from core.cache_store import CacheStore, sha256_file, sha256_text
from core.finding_utils import canonical_finding_key, enrich_result_common, finding_priority_score
from core.scan_history import diff_with_previous
import os
import yaml
import concurrent.futures
import zipfile
import shutil
import json
import subprocess
import tempfile
from typing import Any, Callable, Optional

class Engine:
    def __init__(self, settings: Settings, on_partial_results: Optional[Callable[[list[dict[str, Any]]], None]] = None):
        self.settings = settings
        self.llm_client = self._setup_llm_client()
        self.summaries = {}
        self.masvs_mapping = self._load_masvs_mapping()
        self._on_partial_results = on_partial_results
        
        self.apk_name = "target_app" # Default fallback
        self.vulnerability_findings = []  
        self.cache = CacheStore()
        self.exploit_validation: list[dict[str, Any]] = []
        
        # Load Call Graph Builder if enabled

    def _load_masvs_mapping(self):
        try:
            with open("config/knowledge_base/masvs_mapping.json", "r") as f:
                import json
                return json.load(f)
        except Exception as e:
            log.warning(f"Could not load MASVS mapping: {e}")
            return {}

    def _enrich_result(self, rule_name: str, result_dict: dict) -> dict:
        """Enriches the LLM result with static MASVS knowledge."""
        if rule_name in self.masvs_mapping:
            masvs_info = self.masvs_mapping[rule_name]
            result_dict["masvs_reference"] = {
                "id": masvs_info["masvs_id"],
                "description": masvs_info["description"],
                "link": masvs_info["reference"]
            }
        return result_dict

    def _llm_cached(self, *, code: str, context: dict[str, Any]) -> str:
        prompt_fingerprint = "|".join(
            [
                str(context.get("system_prompt") or ""),
                str(context.get("vuln_prompt") or ""),
                str(context.get("file_path") or ""),
                str(self.settings.llm.provider),
                str(getattr(self.llm_client, "model", "")),
            ]
        )
        key = sha256_text(code + "\n" + prompt_fingerprint)
        cached = self.cache.llm_get(key)
        if cached is not None:
            return cached
        out = self.llm_client.analyze_code(code, context)
        self.cache.llm_put(key, out or "")
        return out or ""

    def _dedup_results(self, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        deduped: dict[str, dict[str, Any]] = {}
        dup_counts: dict[str, int] = {}
        for item in results:
            res = item.get("result") if isinstance(item.get("result"), dict) else {}
            key = canonical_finding_key(
                file_path=str(item.get("file") or ""),
                vulnerability=str(item.get("vulnerability") or ""),
                status=str(item.get("status") or ""),
                evidence=str(res.get("evidence") or res.get("description") or ""),
            )
            score = finding_priority_score(res)
            if key not in deduped:
                deduped[key] = dict(item)
                deduped[key]["dedup_key"] = key
                deduped[key]["duplicate_count"] = 1
                dup_counts[key] = score
            else:
                deduped[key]["duplicate_count"] = int(deduped[key].get("duplicate_count", 1)) + 1
                if score > dup_counts[key]:
                    prev_count = deduped[key]["duplicate_count"]
                    deduped[key] = dict(item)
                    deduped[key]["dedup_key"] = key
                    deduped[key]["duplicate_count"] = prev_count
                    dup_counts[key] = score
        return list(deduped.values())

    def _validate_exploit(self, script_path: str) -> dict[str, Any]:
        ext = os.path.splitext(script_path)[1].lower()
        if ext not in (".py", ".sh"):
            return {"status": "theoretical", "reason": "Auto-validation supports only .py/.sh"}
        try:
            if ext == ".py":
                cmd = ["python", script_path]
            else:
                cmd = ["sh", script_path]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=8,
                cwd=tempfile.gettempdir(),
                env={"PATH": os.environ.get("PATH", "")},
            )
            if proc.returncode == 0:
                return {"status": "reproducible", "reason": "Executed successfully in sandbox runner."}
            return {"status": "failed_validation", "reason": (proc.stderr or proc.stdout or "")[:300]}
        except Exception as e:
            return {"status": "failed_validation", "reason": str(e)[:300]}

    def _emit_partial_results(self, chunk: list[dict[str, Any]]) -> None:
        cb = self._on_partial_results
        if not cb or not chunk:
            return
        try:
            cb(chunk)
        except Exception as e:
            log.debug(f"partial result sink failed: {e}")

    def _setup_llm_client(self):
        if self.settings.llm.provider == "ollama":
            return OllamaClient(model=self.settings.llm.model, url=self.settings.llm.ollama_url)
        elif self.settings.llm.provider == "gemini":
            return GeminiClient(model=self.settings.llm.gemini_model, api_key=self.settings.llm.api_key)
        elif self.settings.llm.provider == "groq":
            return GroqClient(model=self.settings.llm.groq_model, api_key=self.settings.llm.groq_api_key)
        elif self.settings.llm.provider == "openai":
            return OpenAIClient(model=self.settings.llm.openai_model, api_key=self.settings.llm.openai_api_key)
        elif self.settings.llm.provider == "anthropic":
            return AnthropicClient(model=self.settings.llm.anthropic_model, api_key=self.settings.llm.anthropic_api_key)
        elif self.settings.llm.provider == "openrouter":
            return OpenRouterClient(model=self.settings.llm.openrouter_model, api_key=self.settings.llm.openrouter_api_key)
        elif self.settings.llm.provider == "deepseek":
            api_key = self.settings.llm.deepseek_api_key or os.environ.get("DEEPSEEK_API_KEY")
            if not api_key:
                raise ValueError("deepseek_api_key is required (or set DEEPSEEK_API_KEY)")
            model = self.settings.llm.deepseek_model or "deepseek-chat"
            base = (self.settings.llm.deepseek_base_url or "").strip() or "https://api.deepseek.com"
            effort = self.settings.llm.deepseek_reasoning_effort
            if effort is None or str(effort).strip() == "":
                effort = "high"
            thinking = self.settings.llm.deepseek_thinking_enabled
            if thinking is None:
                thinking = True
            return DeepSeekClient(
                model=model,
                api_key=api_key,
                base_url=base,
                reasoning_effort=str(effort).strip(),
                thinking_enabled=bool(thinking),
            )
        else:
            raise ValueError(f"Unsupported LLM provider: {self.settings.llm.provider}")

    def get_status(self, result: dict) -> str:
        """Determines status from the structured JSON result."""
        if result.get("is_vulnerable"):
            return "Vulnerable"
        return "Not Vulnerable"

    def _find_manifest_path(self, start_path: str) -> str:
        """Traverses up the directory tree to find AndroidManifest.xml."""
        current_dir = os.path.dirname(os.path.abspath(start_path))
        while current_dir != "/" and current_dir != "":
            manifest = os.path.join(current_dir, "AndroidManifest.xml")
            if os.path.exists(manifest):
                return manifest
            parent = os.path.dirname(current_dir)
            if parent == current_dir: break
            current_dir = parent
        return ""

    def _get_class_name(self, file_path: str) -> str:
        """Derives class name from file path for Manifest matching."""
        parts = file_path.replace("\\", "/").split("/")
        filename = parts[-1]
        name, _ = os.path.splitext(filename)
        
        # Try to reconstruct package from path (simple heuristic)
        # Stop at common root markers
        package_parts = [name]
        for part in reversed(parts[:-1]):
            if part in ["smali", "java", "src", "main", "decompiled"]:
                break
            package_parts.insert(0, part)
        
        return ".".join(package_parts)

    def _build_global_context(self) -> str:
        """Summarizes all findings into a global context string."""
        if not self.vulnerability_findings:
            return "No previous findings."
        
        summary = "Summary of Vulnerabilities found in other components:\n"
        for finding in self.vulnerability_findings:
            summary += f"- File: {os.path.basename(finding['file_path'])}\n"
            summary += f"  - Vulnerability: {finding['rule_name']}\n"
            summary += f"  - Description: {finding['vuln_description'][:200]}...\n"
        return summary

    def _generate_chained_exploits(self):
        """Iterates through findings and generates exploits using global context."""
        global_context = self._build_global_context()
        log.info("Generating Chained Exploits with Global Context...")
        
        for finding in self.vulnerability_findings:
            self._generate_poc(
                finding["file_path"],
                finding["code_snippet"],
                finding["vuln_description"],
                finding["rule_name"],
                global_context
            )

    def _is_relevant_file(self, file_path: str, package_name: str) -> bool:
        """
        Determines if a file is relevant for analysis based on package scope and blocklist.
        """
        # Blocklist (Libraries to ignore)
        blocklist = [
            "android/", "androidx/", "com/google/", "kotlin/", 
            "okhttp3/", "retrofit2/", "io/reactivex/", "dagger/",
            "b/b/p/", "b/j/a/" # Obfuscated common libs often seen
        ]
        
        # Normalize path
        normalized_path = file_path.replace("\\", "/")
        
        # [FIX] Logic Reordered: Check Whitelist (Package Name) FIRST
        # This prevents apps like 'com.google.myapp' from being blocked by 'com/google/' in blocklist.
        
        # 1. Check Whitelist (Package Name)
        if package_name and "." in package_name:
            package_path = package_name.replace(".", "/")
            if package_path in normalized_path:
                return True
        
        # [V1.1.7 Library Hunter]
        if self.settings.analysis.scan_libraries:
            # If Library Hunter is active, we WANT to see files in the blocklist.
            # We specifically look FOR them.
            # However, we still might want to filter out 'standard java/kotlin' runtime stuff if it's too noisy,
            # but for now, let's just bypass the blocklist check if this mode is on.
            pass 
        else:
            # Standard Mode: Block libraries
            for blocked in blocklist:
                if blocked in normalized_path:
                    # Double Check: Is it actually the app's package?
                    # Sometimes apps use package names that look like libraries? (Rare)
                    return False
            
        # If no package name extracted and not blocked, allow it.
        return True

    def _generate_poc(self, file_path: str, code_snippet: str, vuln_description: str, rule_name: str, global_context: str = ""):
        """Generates a PoC script for a confirmed vulnerability."""
        try:
            # [NEW] Manifest Context Injection
            manifest_context = "Manifest not found or Context Injection disabled."
            if self.settings.analysis.use_cross_reference_context: # Reuse context flag or always on? User asked for accuracy.
                manifest_path = self._find_manifest_path(file_path)
                if manifest_path:
                    parser = ManifestParser(manifest_path)
                    class_name = self._get_class_name(file_path)
                    details = parser.get_component_details(class_name)
                    if details and details.get("context_str"):
                        manifest_context = details["context_str"]
                        log.info(f"Injecting Manifest Context for {class_name}")

            # [NEW] Hardcoded Secrets "Auto-Fill"
            # We use a temporary CodeFilter instance to reuse its regex logic, or the main one if available.
            # Since CodeFilter need decompiled_dir, we can pass a dummy one if we just use extract_secrets(content).
            detected_secrets_str = "None detected."
            try:
                # Assuming CodeFilter is imported. We can use a lightweight instance or static method if refactored.
                # But extract_secrets is an instance method.
                # Let's instantiate it with a dummy path since we only process the snippet string here.
                temp_filter = CodeFilter(decompiled_dir="/tmp", mode="java") 
                secrets = temp_filter.extract_secrets(code_snippet)
                if secrets:
                    detected_secrets_str = ""
                    for s in secrets:
                        detected_secrets_str += f"- {s['type']}: \"{s['value']}\"\n"
                    log.info(f"Injecting {len(secrets)} detected secrets into prompt.")
            except Exception as e:
                log.warning(f"Secret extraction failed: {e}")

            # [LOGIC GUARD] Skip exploit generation if "Hardcoded Secrets" is the issue but Regex found nothing.
            if rule_name == "Hardcoded Secrets" and detected_secrets_str == "None detected.":
                log.warning(f"Skipping exploit generation for {os.path.basename(file_path)}: Vulnerability is 'Hardcoded Secrets' but no actual secrets extracted by Regex.")
                return "" # Return empty string to signal skip

            with open("config/prompts/exploit_prompt.txt", "r", encoding="utf-8") as f:
                prompt_template = f.read()
            
            prompt = prompt_template.replace("{vulnerability_description}", vuln_description)
            prompt = prompt.replace("{file_path}", file_path)
            prompt = prompt.replace("{file_path}", file_path)
            prompt = prompt.replace("{manifest_context}", manifest_context) # Inject Manifest
            prompt = prompt.replace("{detected_secrets}", detected_secrets_str) # Inject Secrets
            prompt = prompt.replace("{global_context}", global_context) # [V1.1.3] Inject Global Context
            prompt = prompt.replace("{code_snippet}", code_snippet[:8000]) 

            
            log.info(f"Generating PoC for {rule_name} in {os.path.basename(file_path)}...")
            
            # The 'prompt' variable is now fully constructed with all placeholders replaced.
            # We pass this as the 'system_prompt' (or 'vuln_prompt') to the LLM client.
            # We pass "" as the code_snippet to analyze_code because we already injected it into the prompt.
            
            context_wrapper = {
                "system_prompt": "You are a Red Team Exploit Developer.",
                "vuln_prompt": prompt, 
                "file_path": file_path
            }
            
            # Note: analyze_code in some clients might try to formatting vuln_prompt if code_snippet is provided.
            # Since we pass prompt (which has no braces left ideally) and empty code_snippet, it should be safe.
            # However, prompt likely contains code with braces.
            # To be safe against client-side formatting, we can pass the whole prompt as system_prompt
            # and empty vuln_prompt, or rely on client implementation.
            # Most clients: f"{system_prompt}\n\n{vuln_prompt}" (no format called if code_snippet is empty or if client checks).
            
            # Let's try passing the full prompt as system_prompt to avoid any client-side formatting magic on '{...}' inside code.
            
            context_wrapper_safe = {
                "system_prompt": prompt,
                "vuln_prompt": "",
                "file_path": file_path
            }
            
            poc_content = self._llm_cached(code="", context=context_wrapper_safe)
            
            if not poc_content:
                log.warning("PoC generation returned empty.")
                return

            # [FIX] Strip markdown code fences that LLMs often wrap output with.
            # e.g. ```bash\n...\n``` or ```python\n...\n```
            # This ensures the saved file is directly executable without manual editing.
            import re as _re
            # Strategy 1: Extract content inside a fenced block if present
            _fence_match = _re.search(r'^```[a-zA-Z]*\s*\n(.*?)\n```\s*$', poc_content.strip(), _re.DOTALL)
            if _fence_match:
                poc_content = _fence_match.group(1).strip()
                log.debug("Stripped markdown code fence from PoC content.")
            else:
                # Strategy 2: Strip leading/trailing fence markers if partial
                poc_content = _re.sub(r'^```[a-zA-Z]*\s*\n?', '', poc_content.strip())
                poc_content = _re.sub(r'\n?```\s*$', '', poc_content.strip())
                poc_content = poc_content.strip()

            # Determine extension based on cleaned content
            ext = ".txt"
            if "Java.perform" in poc_content or "Java.use" in poc_content or "console.log" in poc_content:
                ext = ".js"
            elif "#!/usr/bin/env python" in poc_content or ("import " in poc_content and "def " in poc_content):
                ext = ".py"
            elif "import " in poc_content or "def " in poc_content:
                ext = ".py" 
            elif "<html" in poc_content.lower() or "<script" in poc_content.lower() or "<!doctype" in poc_content.lower():
                ext = ".html"
            elif "#!/bin/bash" in poc_content or "#!/bin/sh" in poc_content or "adb shell" in poc_content:
                ext = ".sh"
            
            # Use the pre-calculated exploit directory from 'run' if available, otherwise fallback
            if hasattr(self, 'final_exploit_dir') and self.final_exploit_dir:
                 exploit_dir = self.final_exploit_dir
            else:
                 # Fallback (shouldn't happen in normal flow)
                 clean_name = self.apk_name
                 if clean_name.lower().endswith(".apk"):
                     clean_name = clean_name[:-4]
                 exploit_dir = f"output/{clean_name}_exploits"

            os.makedirs(exploit_dir, exist_ok=True)
            
            filename = f"{rule_name}_{os.path.basename(file_path)}{ext}"
            save_path = os.path.join(exploit_dir, filename)
            
            with open(save_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(poc_content)
            
            # [FIX] Auto chmod +x for shell scripts so they are immediately runnable
            if ext == ".sh":
                import stat as _stat
                current_mode = os.stat(save_path).st_mode
                os.chmod(save_path, current_mode | _stat.S_IXUSR | _stat.S_IXGRP | _stat.S_IXOTH)
                log.debug(f"chmod +x applied to {filename}")
                
            validation = self._validate_exploit(save_path)
            self.exploit_validation.append(
                {
                    "rule_name": rule_name,
                    "file_path": file_path,
                    "script_path": save_path,
                    "validation_status": validation["status"],
                    "validation_reason": validation["reason"],
                }
            )
            log.success(f"PoC saved to {save_path}")

        except Exception as e:
            log.error(f"Failed to generate PoC: {e}")

    def _extract_json_str(self, text: str) -> str:
        """Extracts the first valid JSON object string by counting braces."""
        text = text.strip()
        start_idx = text.find('{')
        if start_idx == -1:
            return ""
        
        balance = 0
        for i in range(start_idx, len(text)):
            char = text[i]
            if char == '{':
                balance += 1
            elif char == '}':
                balance -= 1
                if balance == 0:
                    return text[start_idx:i+1]
        return ""

    def _parse_llm_response(self, response: str) -> dict:
        """Parses the LLM response string into a dictionary, handling potential formatting issues."""
        import json
        import re
        import ast

        # Strategy 0: Clean Markdown Code Blocks
        # Many LLMs wrap JSON in ```json ... ```
        # We find the first block enclosed in backticks if present
        markdown_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
        if markdown_match:
             cleaned_response = markdown_match.group(1)
        else:
             # Fallback: regex replace if it's just tags without proper closure or mixed content
             cleaned_response = re.sub(r'^```[a-zA-Z]*\s*', '', response.strip())
             cleaned_response = re.sub(r'\s*```$', '', cleaned_response).strip()

        # Strategy 1: Extract JSON using Brace Counting (Most Robust)
        json_candidate = self._extract_json_str(cleaned_response)
        
        if not json_candidate:
            # Fallback for when brace counting fails (e.g. malformed)
            match = re.search(r'\{.*\}', cleaned_response, re.DOTALL)
            if match:
                json_candidate = match.group(0)
            else:
                json_candidate = cleaned_response

        # List of candidate strings to try parsing
        candidates = [json_candidate, cleaned_response, response]
        
        for candidate in candidates:
            if not candidate: continue
            try:
                # strict=False allows control characters like newlines in strings
                return json.loads(candidate, strict=False)
            except json.JSONDecodeError:
                # Sub-strategy: Fix common JSON issues (trailing commas)
                try:
                    fixed_json = re.sub(r',\s*([\]\}])', r'\1', candidate)
                    return json.loads(fixed_json, strict=False)
                except:
                    pass
                
                # Sub-strategy: Python AST Fallback (Single quotes, etc.)
                try:
                    return ast.literal_eval(candidate)
                except:
                    pass

        log.warning(f"Failed to parse LLM response as JSON. Raw: {response[:100]}...")
        return {
                "is_vulnerable": False,
                "severity": "Info",
                "confidence": "Low",
                "evidence": "",
                "description": "Failed to parse LLM response. Please review raw output.",
                "attack_scenario": "N/A (Parsing Failed)",
                "attacker_priority": "N/A",
                "recommendation": "Check raw LLM output for details.",
                "false_positive_analysis": "Parsing failed."
            }

    def analyze_file(self, file_path, rules_to_run: list = None):
        results = []
        with open(file_path, "r", encoding="utf-8") as f:
            code_snippet = f.read()
            
        # Context Injection via Call Graph
        external_context = ""
        if self.call_graph_builder and self.settings.analysis.use_cross_reference_context:
            dependencies = self.call_graph_builder.get_dependencies(file_path)
            if dependencies:
                external_context = "\n\n### EXTERNAL CONTEXT (Dependencies)\n"
                external_context += "The following are summaries of classes called by this file. Use this to verify inputs/outputs and reduce false positives.\n"
                
                # Smart Filtering: Check if the dependency is actually referenced in the code
                # Heuristic: The class name (without package) should likely appear in the smali code
                relevant_summaries = []
                for dep_path in dependencies:
                    dep_class_name = os.path.basename(dep_path).replace(".smali", "")
                    # Simple check: is the class name mentioned?
                    if dep_class_name in code_snippet:
                        if dep_path in self.summaries:
                            relevant_summaries.append(f"- Class {dep_class_name}: {self.summaries[dep_path]}")
                
                if relevant_summaries:
                    external_context += "\n".join(relevant_summaries)
                else:
                    external_context = "" # Reset if no relevant context found
        
        # Combine snippets for the prompt
        full_code_context = code_snippet + external_context

        # [V1.1.7 Library Hunter - Exclusive Mode]
        # Logic: If this is a 3rd party library file, we run ONLY the specialized audit prompt.
        # This saves tokens by not running the 20+ standard rules on generic library code.
        
        is_library_file = False
        library_prefixes = [
            "android/", "androidx/", "com/google/", "kotlin/", 
            "okhttp3/", "retrofit2/", "io/reactivex/", "dagger/",
            "b/b/p/", "b/j/a/"
        ]
        normalized_path = file_path.replace("\\", "/")
        
        for prefix in library_prefixes:
            if prefix in normalized_path:
                is_library_file = True
                break
        
        if self.settings.analysis.scan_libraries and is_library_file:
             log.info(f"Library Scan Triggered for: {os.path.basename(file_path)}")
             prompt_path = "config/prompts/vuln_rules/library_vulnerability.yaml"
             if os.path.exists(prompt_path):
                 with open(prompt_path, "r") as f:
                     prompt_data = yaml.safe_load(f)
                 
                 # [V1.1.7 Optimization] Hybrid Filter
                 # Check regex pattern before calling LLM
                 if self.settings.analysis.filter_mode != "llm_only":
                     pattern = prompt_data.get("detection_pattern")
                     if pattern:
                         import re
                         if not re.search(pattern, full_code_context, re.IGNORECASE | re.DOTALL):
                             log.debug(f"Skipping library file {os.path.basename(file_path)}: No suspicious pattern found.")
                             return results

                 # Prepare Context
                 system_prompt = self._load_system_prompt()
                 
                 context = {
                    "system_prompt": system_prompt,
                    "vuln_prompt": prompt_data["prompt"],
                    "file_path": file_path
                 }
                 
                 # Run Analysis
                 try:
                     raw_result = self._llm_cached(code=full_code_context, context=context)
                     parsed_result = self._parse_llm_response(raw_result)
                     status = self.get_status(parsed_result)
                 
                     if status == "Vulnerable":
                         parsed_result = self._enrich_result("library_vulnerability", parsed_result)
                         parsed_result = enrich_result_common(
                             file_path=file_path,
                             vulnerability="library_vulnerability",
                             result=parsed_result,
                         )
                         if self.settings.analysis.generate_exploit:
                              self.vulnerability_findings.append({
                                  "file_path": file_path,
                                  "code_snippet": full_code_context,
                                  "vuln_description": parsed_result.get("description", ""),
                                  "rule_name": "library_vulnerability"
                              })

                         results.append({
                            "file": file_path,
                            "vulnerability": "Library Hunter",
                            "status": status,
                            "result": parsed_result
                         })
                         self._emit_partial_results([results[-1]])
                 except Exception as e:
                     log.error(f"Library Scan failed for {file_path}: {e}")
             
             # [CRITICAL OPTIMIZATION] Early Return!
             # We assume standard logic rules (like 'Intent Spoofing' in App Logic) are less relevant 
             # for granular library internals, or are covered by the general 'Library Audit' prompt.
             return results

        for rule_name, enabled in self.settings.rules.dict().items():
            if enabled and rule_name not in ["webview_deeplink", "intent_spoofing", "exported_components", "deeplink_hijack"]:
                if rules_to_run and rule_name not in rules_to_run:
                    continue
                prompt_path = f"config/prompts/vuln_rules/{rule_name}.yaml"
                with open(prompt_path, "r") as f:
                    prompt_data = yaml.safe_load(f)
                
                
                # --- MASVS CONTEXT INJECTION (LITE RAG) ---
                system_prompt = self._load_system_prompt()
                
                
                # Check if this rule maps to a MASVS ID
                if rule_name in self.masvs_mapping:
                    masvs_info_data = self.masvs_mapping[rule_name]
                    masvs_id = masvs_info_data.get("masvs_id", "Unknown")
                    masvs_desc = masvs_info_data.get("description", "No description available.")
                    
                    # Append guidance to the system prompt
                    system_prompt += f"\n\n### OWASP MASVS GUIDANCE\n"
                    system_prompt += f"This analysis relates to **{masvs_id}**.\n"
                    system_prompt += f"Standard: \"{masvs_desc}\"\n"
                    system_prompt += f"Ensure your verification aligns strictly with this standard."

                # --- DYNAMIC PROMPT ADAPTATION (Language Agnostic) ---
                vuln_prompt = prompt_data["prompt"]
                if file_path.endswith(".java"):
                    # Improve prompt context by switching terminology
                    # "Analyze this smali code..." -> "Analyze this java code..."
                    # ```smali -> ```java
                    vuln_prompt = vuln_prompt.replace("smali", "java")
                    vuln_prompt = vuln_prompt.replace("Smali", "Java")

                context = {
                    "system_prompt": system_prompt,
                    "vuln_prompt": vuln_prompt,
                    "file_path": file_path
                }
                
                # Pass the ENRICHED context
                raw_result = self._llm_cached(code=full_code_context, context=context)
                parsed_result = self._parse_llm_response(raw_result)
                status = self.get_status(parsed_result)
                
                # Enrich with MASVS
                if status == "Vulnerable":
                    parsed_result = self._enrich_result(rule_name, parsed_result)
                    parsed_result = enrich_result_common(
                        file_path=file_path,
                        vulnerability=prompt_data["name"],
                        result=parsed_result,
                    )
                    
                    # Instead of generating PoC immediately, we store the finding.
                    if self.settings.analysis.generate_exploit:
                         self.vulnerability_findings.append({
                             "file_path": file_path,
                             "code_snippet": full_code_context,
                             "vuln_description": parsed_result.get("description", ""),
                             "rule_name": rule_name
                         })

                results.append({
                    "file": file_path,
                    "vulnerability": prompt_data["name"],
                    "status": status,
                    "result": parsed_result # Store the full structured object
                })
                self._emit_partial_results([results[-1]])
        return results

    def analyze_manifest(self, manifest_path, rules_to_run: list = None):
        results = []
        with open(manifest_path, "r", encoding="utf-8") as f:
            code_snippet = f.read()

        manifest_rules = ["webview_deeplink", "intent_spoofing", "exported_components", "deeplink_hijack", "strandhogg"]
        for rule_name in manifest_rules:
            if getattr(self.settings.rules, rule_name):
                if rules_to_run and rule_name not in rules_to_run:
                    continue
                prompt_path = f"config/prompts/vuln_rules/{rule_name}.yaml"
                with open(prompt_path, "r") as f:
                    prompt_data = yaml.safe_load(f)

                context = {
                    "system_prompt": self._load_system_prompt(),
                    "vuln_prompt": prompt_data["prompt"],
                    "file_path": manifest_path
                }

                raw_result = self._llm_cached(code=code_snippet, context=context)
                parsed_result = self._parse_llm_response(raw_result)
                status = self.get_status(parsed_result)
                
                # Enrich with MASVS
                if status == "Vulnerable":
                    parsed_result = self._enrich_result(rule_name, parsed_result)
                    parsed_result = enrich_result_common(
                        file_path=manifest_path,
                        vulnerability=prompt_data["name"],
                        result=parsed_result,
                    )
                    
                    if self.settings.analysis.generate_exploit:
                         self.vulnerability_findings.append({
                             "file_path": manifest_path,
                             "code_snippet": code_snippet,
                             "vuln_description": parsed_result.get("description", ""),
                             "rule_name": rule_name
                         })

                results.append({
                    "file": manifest_path,
                    "vulnerability": prompt_data["name"],
                    "status": status,
                    "result": parsed_result 
                })
                self._emit_partial_results([results[-1]])
        return results

    def analyze_strings_xml(self, decompiled_dir: str, rules_to_run: list = None):
        """Scans res/values/strings.xml for hardcoded secrets."""
        results = []
        rule_name = "hardcoded_secrets_xml"
        
        if not getattr(self.settings.rules, rule_name):
            return []

        if rules_to_run and rule_name not in rules_to_run:
            return []

        # Find strings.xml
        strings_path = None
        for root, _, files in os.walk(decompiled_dir):
            if "strings.xml" in files:
                # Prioritize res/values/strings.xml
                potential = os.path.join(root, "strings.xml")
                if "values" in root.split(os.sep): 
                     strings_path = potential
                     break
                # Fallback to any strings.xml if not in valus (unlikely but possible)
                if not strings_path:
                    strings_path = potential

        if not strings_path:
            log.warning("strings.xml not found in decompiled output.")
            return []

        log.info(f"Analyzing {strings_path} for Hardcoded Secrets...")
        
        with open(strings_path, "r", encoding="utf-8") as f:
            code_snippet = f.read()

        prompt_path = f"config/prompts/vuln_rules/{rule_name}.yaml"
        with open(prompt_path, "r") as f:
            prompt_data = yaml.safe_load(f)

        context = {
            "system_prompt": self._load_system_prompt(),
            "vuln_prompt": prompt_data["prompt"],
            "file_path": strings_path
        }

        raw_result = self._llm_cached(code=code_snippet, context=context)
        parsed_result = self._parse_llm_response(raw_result)
        status = self.get_status(parsed_result)
        
        if status == "Vulnerable":
            parsed_result = enrich_result_common(
                file_path=strings_path,
                vulnerability=prompt_data["name"],
                result=parsed_result,
            )
            # [V1.1.3] DEFERRED GENERATION
            if self.settings.analysis.generate_exploit:
                    self.vulnerability_findings.append({
                        "file_path": strings_path,
                        "code_snippet": code_snippet,
                        "vuln_description": parsed_result.get("description", ""),
                        "rule_name": rule_name
                    })

        results.append({
            "file": strings_path,
            "vulnerability": prompt_data["name"],
            "status": status,
            "result": parsed_result 
        })
        self._emit_partial_results([results[-1]])
        return results

    def summarize_chunks(self, decompiled_dir: str, file_list: list = None):
        log.info("Starting code summarization...")
        summaries = {}
        summarize_prompt = self._load_summarize_prompt()

        files_to_process = []
        if file_list:
             files_to_process = file_list
        else:
            for root, _, files in os.walk(decompiled_dir):
                for file in files:
                    if file.endswith(".smali"):
                        files_to_process.append(os.path.join(root, file))

        for file_path in files_to_process:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            # Simple chunking by class
            chunks = content.split(".class ")
            for chunk in chunks:
                if not chunk.strip():
                    continue
                
                full_chunk = ".class " + chunk
                
                context = {
                    "system_prompt": "",
                    "vuln_prompt": summarize_prompt,
                    "file_path": file_path
                }
                
                summary = self._llm_cached(code=full_chunk, context=context)
                summaries[file_path] = summary
                log.debug(f"Summary for {file_path}: {summary}")

        log.success("Code summarization complete.")
        return summaries

    def identify_risky_chunks(self, summaries: dict):
        log.info("Identifying risky code chunks...")
        risky_files = []
        identify_risk_prompt = self._load_identify_risk_prompt()

        for file_path, summary in summaries.items():
            context = {
                "system_prompt": "",
                "vuln_prompt": identify_risk_prompt,
                "file_path": file_path
            }
            
            response = self._llm_cached(code=summary, context=context)
            
            if "yes" in response.lower():
                risky_files.append(file_path)
                log.debug(f"Identified risky file: {file_path}")

        log.success(f"Identified {len(risky_files)} risky files.")
        return risky_files

    def summarize_app(self, manifest_path: str, summaries: dict):
        log.info("Summarizing application capabilities...")
        
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = f.read()
            
        summaries_text = "\n".join(f"- {file_path}: {summary}" for file_path, summary in summaries.items())
        
        prompt = self._load_app_summary_prompt().format(manifest=manifest, summaries=summaries_text)
        # Escape curly braces to prevent double formatting issues in analyze_code
        prompt = prompt.replace("{", "{{").replace("}", "}}")
        
        context = {
            "system_prompt": "",
            "vuln_prompt": prompt,
            "file_path": manifest_path
        }
        
        app_summary = self._llm_cached(code="", context=context)
        log.success("Application capabilities summarized.")
        return app_summary

    def generate_attack_surface_map(self, manifest_path: str, summaries: dict):
        log.info("Generating attack surface map...")
        
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = f.read()
            
        summaries_text = "\n".join(f"- {file_path}: {summary}" for file_path, summary in summaries.items())
        
        prompt = self._load_attack_surface_prompt().format(manifest=manifest, summaries=summaries_text)
        # Escape curly braces to prevent double formatting issues in analyze_code
        prompt = prompt.replace("{", "{{").replace("}", "}}")
        
        context = {
            "system_prompt": "",
            "vuln_prompt": prompt,
            "file_path": manifest_path
        }
        
        attack_surface_map = self._llm_cached(code="", context=context)
        log.success("Attack surface map generated.")
        return attack_surface_map

    def _find_smali_fallback(self, java_path: str, output_dir: str) -> str:
        """Helper to find corresponding smali file for a java file."""
        # Java: output/src_jadx/com/example/MainActivity.java
        # Smali: output/smali/com/example/MainActivity.smali
        # This is a heuristic translation
        try:
             # Remove prefix up to package
             rel_path = java_path.split("sources/")[-1] 
             if not rel_path: return None
             
             smali_path = os.path.join(output_dir, "smali", rel_path.replace(".java", ".smali"))
             if os.path.exists(smali_path):
                 return smali_path
        except:
             pass
        return None

    def run(self, apk_path: str, output_file: str = None, no_decompile: bool = False, rules: str = None):
        log.info(f"Starting analysis of {apk_path}...")
        
        rules_to_run = rules.split(',') if rules else None
        
        # [V1.1.4] XAPK Auto-Extraction Support
        if apk_path.lower().endswith(".xapk"):
             log.info(f"Detected XAPK file: {apk_path}. Attempting to extract...")
             xapk_name = os.path.basename(apk_path)
             temp_extract_dir = f"output/temp_xapk_{xapk_name}"
             os.makedirs(temp_extract_dir, exist_ok=True)
             
             try:
                 with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                     zip_ref.extractall(temp_extract_dir)
                 
                 # Find the largest .apk file (heuristically the base/main APK)
                 largest_apk = None
                 max_size = 0
                 
                 for root, dirs, files in os.walk(temp_extract_dir):
                     for file in files:
                         if file.lower().endswith(".apk"):
                             full_path = os.path.join(root, file)
                             size = os.path.getsize(full_path)
                             if size > max_size:
                                 max_size = size
                                 largest_apk = full_path
                 
                 if largest_apk:
                     log.success(f"Extracted XAPK and selected main APK: {largest_apk}")
                     apk_path = largest_apk # Override valid APK path
                 else:
                     log.error("Could not find any .apk file inside the XAPK archive.")
                     return # Abort
                     
             except zipfile.BadZipFile:
                 log.error(f"Failed to extract XAPK: {apk_path} is not a valid zip file.")
                 return
             except Exception as e:
                 log.error(f"Error handling XAPK: {e}")
                 return

        self.apk_name = os.path.basename(apk_path) # Store for later use
        apk_name = self.apk_name
        output_dir = f"output/{apk_name}_decompiled"
        
        # [Moved from end] Calculate unique output file/dir options EARLY
        if output_file is None:
            base_filename = f"{os.path.basename(apk_path)}_results.json"
            base_exploit_dir_name = f"{os.path.basename(apk_path).replace('.apk', '')}_exploits"
            
            # Initial candidates
            candidate_file = f"output/{base_filename}"
            candidate_exploit_dir = f"output/{base_exploit_dir_name}"
            
            # Versioning loop
            scan_count = 1
            while os.path.exists(candidate_file):
                 # Create suffix _scan1, _scan2...
                 candidate_file = f"output/{base_filename.replace('.json', '')}_scan{scan_count}.json"
                 candidate_exploit_dir = f"output/{base_exploit_dir_name}_scan{scan_count}"
                 scan_count += 1
            
            self.final_output_file = candidate_file
            self.final_exploit_dir = candidate_exploit_dir
        else:
            self.final_output_file = output_file
            filename_no_ext = os.path.splitext(os.path.basename(output_file))[0]
            self.final_exploit_dir = f"output/{filename_no_ext}_exploits"
        
        decomp_mode = self.settings.analysis.decompiler_mode
        log.info(f"Decompiler Mode: {decomp_mode}")

        apk_hash = sha256_file(apk_path) if os.path.isfile(apk_path) else "unknown"
        decompile_key = sha256_text(
            "|".join(
                [
                    apk_hash,
                    decomp_mode,
                    str(self.settings.apktool.path or "apktool"),
                    str((self.settings.jadx.path if self.settings.jadx else "") or "jadx"),
                ]
            )
        )
        decomp_cache = self.cache.decompile_get(decompile_key)

        if not no_decompile and not (decomp_cache and os.path.isdir(output_dir)):
            os.makedirs(output_dir, exist_ok=True)
            
            # 1. Always run Apktool (Need Manifest + Resources + Smali Fallback)
            log.info("Running Apktool...")
            decompiler = ApktoolHandler(apktool_path=self.settings.apktool.path or "apktool")
            decompiler.decompile(apk_path, output_dir)
            
            # 2. Run JADX if needed
            if decomp_mode in ["jadx", "hybrid"]:
                log.info("Running JADX...")
                jx = self.settings.jadx
                jadx = JadxHandler(jadx_path=jx.path if jx else None, max_heap=jx.max_heap if jx else None)
                # JADX typically outputs to 'sources' dir inside output_dir when -d is used? 
                # Handler uses -d output_dir. Jadx usually creates 'sources' structure.
                # Let's ensure JadxHandler puts it in output_dir/sources or we handle it.
                # Our handler: cmd = [self.jadx_path, "-d", output_dir, ...]
                # Jadx default behavior: creates 'sources' folder inside output_dir.
                jadx.decompile(apk_path, output_dir)
            self.cache.decompile_put(
                decompile_key,
                {
                    "apk_hash": apk_hash,
                    "output_dir": output_dir,
                    "mode": decomp_mode,
                },
            )
        elif decomp_cache and os.path.isdir(output_dir):
            log.info("Decompiler cache hit: reusing existing decompiled output.")

        # BUILD CALL GRAPH (Only supports Smali for now)
        if self.settings.analysis.use_cross_reference_context:
            self.call_graph_builder = CallGraphBuilder(output_dir)
            self.call_graph_builder.build()
        else:
            self.call_graph_builder = None

        smali_rules_enabled = any(
            enabled and rule_name not in ["webview_deeplink", "intent_spoofing", "exported_components", "deeplink_hijack"]
            for rule_name, enabled in self.settings.rules.dict().items()
        )

        self.summaries = {}
        target_files = [] # Files we will actually scan (either .smali or .java)
        
        if smali_rules_enabled:
            filter_mode = self.settings.analysis.filter_mode
            log.info(f"Using filter mode: {filter_mode}")

            # --- DYNAMIC KEYWORD & REGEX GATHERING ---
            extra_keywords = []
            extra_regex = [] # [V1.2] Regex Support
            for rule_name, enabled in self.settings.rules.dict().items():
                if enabled and rule_name not in ["webview_deeplink", "intent_spoofing", "exported_components", "deeplink_hijack", "strandhogg"]:
                     try:
                        prompt_path = f"config/prompts/vuln_rules/{rule_name}.yaml"
                        with open(prompt_path, "r") as f:
                            rule_data = yaml.safe_load(f)
                            if "keywords" in rule_data and rule_data["keywords"]:
                                extra_keywords.extend(rule_data["keywords"])
                            
                            # [V1.2] Support for 'detection_pattern' (regex) and 'static_analysis' block
                            if "detection_pattern" in rule_data and rule_data["detection_pattern"]:
                                extra_regex.append(rule_data["detection_pattern"])
                            elif "static_analysis" in rule_data:
                                if "patterns" in rule_data["static_analysis"]:
                                    extra_regex.extend(rule_data["static_analysis"]["patterns"])
                                    
                     except Exception as e:
                         log.warning(f"Could not load matching logic from {rule_name}: {e}")
            
            # Deduplicate
            extra_keywords = list(set(extra_keywords))
            extra_regex = list(set(extra_regex))
            
            if extra_keywords:
                log.info(f"Loaded high-value keywords: {len(extra_keywords)}")
            if extra_regex:
                log.info(f"Loaded high-value regex patterns: {len(extra_regex)}")

            # --- SCOPE IDENTIFICATION ---
            # Parse Manifest early to get package name for filtering
            manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
            app_package_name = ""
            if os.path.exists(manifest_path):
                try:
                    parser = ManifestParser(manifest_path)
                    app_package_name = parser.package_name
                    log.info(f"Identified App Package: {app_package_name}")
                except Exception as e:
                    log.warning(f"Failed to parse package name: {e}")

            # --- STRATEGY SELECTION ---
            
            # Set scan roots
            smali_dir = output_dir # Root of decompiled dir, CodeFilter walks this
            # JADX usually creates 'sources' inside output_dir
            java_dir = os.path.join(output_dir, "sources") 
            
            potential_targets = []
            
            # A. STATIC FILTER PHASE
            # A. STATIC FILTER PHASE
            if filter_mode in ["static_only", "hybrid"]:
                use_strict = (filter_mode == "hybrid")
                
                # [V1.1.7 Optimization] Library Hunter Strict Mode
                # If Library Scan is requested, we override standards to be VERY STRICT.
                # We do NOT want generic 'WebView' or 'File' keywords matching 100 library files.
                # We ONLY want 'readObject', 'DexClassLoader', etc.
                if self.settings.analysis.scan_libraries:
                    log.info("Library Hunter Mode: Enforcing STRICT regex targeting to save tokens.")
                    
                    # 1. Load ONLY the library regex
                    strict_lib_regex = []
                    lib_prompt_path = "config/prompts/vuln_rules/library_vulnerability.yaml"
                    if os.path.exists(lib_prompt_path):
                         with open(lib_prompt_path, "r") as f:
                             d = yaml.safe_load(f)
                             if "detection_pattern" in d:
                                 strict_lib_regex.append(d["detection_pattern"])
                    
                    # 2. Run CodeFilter in STRICT MODE (No default keywords)
                    # Support JADX or HYBRID (if Java sources exist)
                    if decomp_mode in ["jadx", "hybrid"] and os.path.exists(java_dir):
                        cf = CodeFilter(java_dir, mode="java", additional_keywords=[], additional_regex=strict_lib_regex, strict_mode=True)
                        potential_targets = cf.find_high_value_targets()
                    # Fallback to Smali (Apktool or missing Java sources)
                    else:
                        cf = CodeFilter(smali_dir, mode="smali", additional_keywords=[], additional_regex=strict_lib_regex, strict_mode=True)
                        potential_targets = cf.find_high_value_targets()
                     
                else:
                    # Standard Mode (Broad)
                    if decomp_mode == "apktool":
                        cf = CodeFilter(smali_dir, mode="smali", additional_keywords=extra_keywords, additional_regex=extra_regex, strict_mode=use_strict)
                        potential_targets = cf.find_high_value_targets()
                        
                    elif decomp_mode == "jadx":
                        if os.path.exists(java_dir):
                            cf = CodeFilter(java_dir, mode="java", additional_keywords=extra_keywords, additional_regex=extra_regex, strict_mode=use_strict)
                            potential_targets = cf.find_high_value_targets()
                        else:
                            log.error("JADX sources not found. Falling back to Smali.")
                            cf = CodeFilter(smali_dir, mode="smali", additional_keywords=extra_keywords, additional_regex=extra_regex, strict_mode=use_strict)
                            potential_targets = cf.find_high_value_targets()

                    elif decomp_mode == "hybrid":
                        # HYBRID DECOMPILER + HYBRID FILTER
                        if os.path.exists(java_dir):
                            cf = CodeFilter(java_dir, mode="java", additional_keywords=extra_keywords, additional_regex=extra_regex, strict_mode=use_strict)
                            java_targets = cf.find_high_value_targets()
                            potential_targets = java_targets
                        else:
                            cf = CodeFilter(smali_dir, mode="smali", additional_keywords=extra_keywords, additional_regex=extra_regex, strict_mode=use_strict)
                            potential_targets = cf.find_high_value_targets()

            # B. LLM_ONLY PHASE (Get everything)
            else: 
                # This is risky/expensive for JADX if huge source tree. 
                # But logic is "summarize everything".
                if decomp_mode == "apktool":
                     # Walk smali
                     for root, _, files in os.walk(smali_dir):
                        for file in files:
                            if file.endswith(".smali"): potential_targets.append(os.path.join(root, file))
                else: 
                     # Walk java
                     if os.path.exists(java_dir):
                        for root, _, files in os.walk(java_dir):
                            for file in files:
                                if file.endswith(".java"): potential_targets.append(os.path.join(root, file))
            
            # --- STRINGS.XML ANALYSIS ---
            strings_results = self.analyze_strings_xml(output_dir, rules_to_run)
            
            # --- SMART FALLBACK & SELECTION ---
            # Now we have 'potential_targets'. 
            # If we are in 'hybrid' DECOMPILER mode, we check content quality.
            
            final_targets_for_summary = []
            
            for target in potential_targets:
                if decomp_mode == "hybrid" and target.endswith(".java"):
                    # Check if valid
                    try:
                        if os.path.getsize(target) < 50: # Empty or just package decl
                             # Fallback
                             fallback = self._find_smali_fallback(target, output_dir)
                             if fallback:
                                 log.info(f"Smart Fallback: Switching {os.path.basename(target)} to Smali due to low quality.")
                                 final_targets_for_summary.append(fallback)
                             else:
                                 final_targets_for_summary.append(target) # Keep it if no fallback
                        else:
                             final_targets_for_summary.append(target)
                    except:
                        final_targets_for_summary.append(target)
                else:
                    final_targets_for_summary.append(target)

            # [V1.1.4] Apply Scope Filtering
            filtered_targets = []
            skipped_count = 0
            for target in final_targets_for_summary:
                if self._is_relevant_file(target, app_package_name):
                    filtered_targets.append(target)
                else:
                    skipped_count += 1
            
            if skipped_count > 0:
                log.info(f"Scope Filter: Ignored {skipped_count} library/irrelevant files.")
            
            final_targets_for_summary = filtered_targets

            
            # --- SUMMARIZATION & RISK ID PHASE ---
            
            if filter_mode == "static_only":
                 target_files = final_targets_for_summary
                 # No summarization logic for pure static, just pass to analyze
                 
            elif filter_mode == "hybrid": 
                # Static found targets -> Summarize them -> Ask LLM
                if final_targets_for_summary:
                    self.summaries = self.summarize_chunks(output_dir, file_list=final_targets_for_summary)
                    target_files = self.identify_risky_chunks(self.summaries)
                else:
                    target_files = []

            else: # llm_only
                # We summarized EVERYTHING (expensive!). 
                self.summaries = self.summarize_chunks(output_dir, file_list=final_targets_for_summary)
                target_files = self.identify_risky_chunks(self.summaries)


        manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
        
        # Always attempt to summarize app (even if only based on Manifest)
        app_summary = self.summarize_app(manifest_path, self.summaries)
        
        attack_surface_map = None
        if self.settings.analysis.generate_attack_surface_map:
            attack_surface_map = self.generate_attack_surface_map(manifest_path, self.summaries)

        # Clear previous findings before scan
        self.vulnerability_findings = []

        # Analyze the manifest file
        all_results = self.analyze_manifest(manifest_path, rules_to_run)

        if smali_rules_enabled and target_files:
            # Append strings.xml results
            try:
                if strings_results:
                    all_results.extend(strings_results)
            except NameError:
                pass # strings_results might not be defined if scope skipped
            # Analyze the identified files
            # Note: analyze_file handles reading the file content logic.
            # Does it handle .java? Yes, strictly text read.
            # But context injection? CallGraph only knows Smali paths. 
            # If passing .java, context injection (get_dependencies) currently fails or returns nothing.
            # We accept this limitation for now (Java analysis has better inherent context).
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                future_to_file = {executor.submit(self.analyze_file, file_path, rules_to_run): file_path for file_path in target_files}
                for future in concurrent.futures.as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        results = future.result()
                        all_results.extend(results)
                    except Exception as exc:
                        log.error(f"{file_path} generated an exception: {exc}")

        all_results = self._dedup_results(all_results)
        app_id = extract_application_id({"app_summary": app_summary, "attack_surface_map": attack_surface_map})
        apk_version = os.path.basename(apk_path)
        diff_summary = diff_with_previous(
            apk_version=apk_version,
            application_id=app_id,
            results=all_results,
        )

        final_report = {
            "app_summary": app_summary,
            "attack_surface_map": attack_surface_map,
            "results": all_results,
            "diff_summary": diff_summary,
            "exploit_validation": self.exploit_validation,
        }

        # [V1.1.3] Generate Chained Exploits (Phase 2)
        if self.settings.analysis.generate_exploit and self.vulnerability_findings:
            self._generate_chained_exploits()

        # Output the report to the pre-calculated path
        with open(self.final_output_file, "w", encoding="utf-8") as f:
            json.dump(final_report, f, indent=2)
        from core.scan_history import record_scan
        record_scan(
            apk_version=apk_version,
            application_id=app_id,
            report_path=self.final_output_file,
            results=all_results,
        )
        self.cache.cleanup()
        self.cache.save()
        log.success(f"Analysis complete. Results saved to {self.final_output_file}")

    def _load_system_prompt(self) -> str:
        with open("config/prompts/system_prompt.txt", "r") as f:
            return f.read()

    def _load_summarize_prompt(self) -> str:
        with open("config/prompts/summarize_prompt.txt", "r") as f:
            return f.read()

    def _load_identify_risk_prompt(self) -> str:
        with open("config/prompts/identify_risk_prompt.txt", "r") as f:
            return f.read()

    def _load_app_summary_prompt(self) -> str:
        with open("config/prompts/app_summary_prompt.txt", "r") as f:
            return f.read()

    def _load_attack_surface_prompt(self) -> str:
        with open("config/prompts/attack_surface_prompt.txt", "r") as f:
            return f.read()
