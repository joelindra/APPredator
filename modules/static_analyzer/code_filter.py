import os
from typing import List
from core import log

class CodeFilter:
    def __init__(self, decompiled_dir: str, mode: str = "smali", additional_keywords: List[str] = None, additional_regex: List[str] = None, strict_mode: bool = False):
        self.decompiled_dir = decompiled_dir
        self.mode = mode
        self.additional_regex = additional_regex if additional_regex else []
        
        self.smali_keywords = [
            "Landroid/webkit/WebView;",
            "Landroid/database/sqlite/SQLiteDatabase;->rawQuery",
            "Landroid/database/sqlite/SQLiteDatabase;->execSQL",
            "Landroid/content/SharedPreferences;",
            "Ljavax/crypto/SecretKey;",
            "Ljavax/crypto/Cipher;",
            "Ljava/security/MessageDigest;",
            "Landroid/webkit/WebSettings;->setJavaScriptEnabled",
            "Landroid/webkit/WebView;->addJavascriptInterface",
            "Landroid/webkit/WebView;->loadUrl",
            "Landroid/webkit/WebView;->loadData",
            "Ljava/net/HttpURLConnection;",
            "Lokhttp3/OkHttpClient;",
            "Landroid/hardware/biometrics/BiometricPrompt;",
            "Ljava/io/File;",
            "Landroid/content/ContentProvider;",
            "Landroid/security/keystore/KeyGenParameterSpec;",
        ]
        
        # Keywords for Java Source Code (JADX)
        self.java_keywords = [
            "android.webkit.WebView",
            "SQLiteDatabase", "rawQuery", "execSQL",
            "SharedPreferences",
            "javax.crypto.SecretKey",
            "javax.crypto.Cipher",
            "java.security.MessageDigest",
            "setJavaScriptEnabled",
            "addJavascriptInterface",
            "loadUrl", "loadData",
            "HttpURLConnection",
            "OkHttpClient",
            "BiometricPrompt",
            "java.io.File",
            "ContentProvider",
            "KeyGenParameterSpec"
        ]
        
        # Merge built-in keywords with any dynamic additional keywords
        if strict_mode:
            # In strict mode (Hybrid), we IGNORE the default hardcoded keywords
            # and rely ONLY on what the Rules provide (keywords or regex).
            base_keywords = []
        else:
            # In legacy mode, we include the default "catch-all" keywords
            base_keywords = self.java_keywords if mode == "java" else self.smali_keywords
            
        self.keywords = base_keywords + (additional_keywords if additional_keywords else [])
        self.extension = ".java" if mode == "java" else ".smali"

        # Compilation of regex for performance
        import re
        self.compiled_patterns = []
        if self.additional_regex:
             for p in self.additional_regex:
                 try:
                     self.compiled_patterns.append(re.compile(p))
                 except re.error as e:
                     log.warning(f"Invalid regex pattern skipped: {p} ({e})")

    def find_high_value_targets(self) -> List[str]:
        high_value_files = []
        log.info(f"Starting keyword/regex search in {self.decompiled_dir} (Mode: {self.mode})...")
        for root, _, files in os.walk(self.decompiled_dir):
            for file in files:
                if file.endswith(self.extension):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()
                        
                        # Check Keywords
                        matched = False
                        if any(keyword in content for keyword in self.keywords):
                            matched = True
                        
                        # Check Regex Patterns (if not already matched)
                        if not matched and self.compiled_patterns:
                            for pattern in self.compiled_patterns:
                                if pattern.search(content):
                                    matched = True
                                    break
                        
                        if matched:
                            high_value_files.append(file_path)
                            log.debug(f"Found high-value target: {file_path}")
                    except Exception as e:
                        log.warning(f"Could not read file {file_path}: {e}")

        log.success(f"Found {len(high_value_files)} high-value target files.")
        return high_value_files

    def extract_secrets(self, content: str) -> List[dict]:
        """
        Scans content for hardcoded secrets using regex patterns.
        Returns a list of detected secrets with metadata.
        """
        import re
        secrets = []
        
        patterns = [
            {
                "name": "Google API Key",
                "regex": r"AIza[0-9A-Za-z-_]{35}"
            },
            {
                "name": "Generic Secret Assignment",
                # Captures: var_name = "secret_value"
                # Case insensitive for variable names like apiKey, API_KEY, password, secretToken
                "regex": r"(?i)(api_key|apikey|secret|token|password|auth_token|access_token|client_secret)\s*=\s*[\"']([^\"']+)[\"']",
                "is_group": True # Indicates the value is in a capture group
            },
            {
                "name": "Bearer Token",
                "regex": r"Bearer\s+[a-zA-Z0-9\-\._~+/]+=*"
            },
            {
                "name": "Private Key (PEM)",
                "regex": r"-----BEGIN (?:RSA )?PRIVATE KEY-----"
            },
            {
                "name": "AWS Access Key ID",
                "regex": r"AKIA[0-9A-Z]{16}"
            },
            {
                "name": "Map/JSON Put",
                # Captures: .put("secret_key", "value")
                "regex": r'\.put\(\s*[\"\']([^\"\']*(?:key|secret|password|token|auth|enc_data)[^\"\']*)[\"\']\s*,\s*[\"\']([^\"\']+)[\"\']\s*\)',
                "is_group": True
            }
        ]
        
        for p in patterns:
            try:
                matches = re.finditer(p["regex"], content)
                for match in matches:
                    value = match.group(0)
                    if p.get("is_group") and len(match.groups()) >= 2:
                        # For assignments, grabbing the value (group 2) and variable name (group 1)
                        # We format it as explicit context: "var_name = value"
                        # Or just return the value? Better to return full context if possible.
                        # Let's return the simplified value for the exploited script.
                        value = match.group(2) # The actual secret string
                        key_name = match.group(1) # The variable name
                        
                        # Filter out common false positives or placeholders
                        if "replace" in value.lower() or "your_" in value.lower() or "dummy" in value.lower():
                            continue
                            
                        secrets.append({
                            "type": p["name"],
                            "key": key_name, 
                            "value": value,
                            "context": match.group(0) # Full match for context
                        })
                    else:
                        # For direct pattern matches (like AIza...)
                        secrets.append({
                            "type": p["name"],
                            "value": value,
                            "context": value
                        })
            except Exception as e:
                log.debug(f"Regex error for {p['name']}: {e}")
                
        # Deduplicate secrets based on value
        unique_secrets = []
        seen_values = set()
        for s in secrets:
            if s["value"] not in seen_values:
                unique_secrets.append(s)
                seen_values.add(s["value"])
                
        return unique_secrets