import requests
import json
from .base import BaseLLMClient
from core import log
from typing import Dict, Any

class OpenRouterClient(BaseLLMClient):
    def __init__(self, model: str, api_key: str):
        self.model = model
        self.api_key = api_key
        self.url = "https://openrouter.ai/api/v1/chat/completions"

    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        prompt = self._construct_prompt(code_snippet, context)
        log.info(f"Sending analysis request to OpenRouter model: {self.model}...")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # Include site URL and name for OpenRouter rankings (Optional but good practice)
        headers["HTTP-Referer"] = "https://github.com/apppredator/apppredator"
        headers["X-Title"] = "APPredator"
        
        data = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }

        max_retries = 3
        base_delay = 2 # seconds
        import time

        for attempt in range(max_retries):
            try:
                response = requests.post(self.url, headers=headers, data=json.dumps(data), timeout=120)
                
                if response.status_code == 429:
                    log.warning(f"Rate limit hit (429). Retrying... (Attempt {attempt + 1})")
                    time.sleep(base_delay * (2 ** attempt))
                    continue
                
                response.raise_for_status()
                result = response.json()
                
                if "error" in result:
                     log.error(f"OpenRouter API returned error: {result['error']}")
                     raise requests.exceptions.RequestException(f"OpenRouter API Error: {result['error']}")

                if 'choices' in result and len(result['choices']) > 0:
                    log.success("Received analysis from OpenRouter.")
                    return result['choices'][0]['message']['content']
                else:
                    return ""

            except requests.exceptions.RequestException as e:
                log.warning(f"Network error: {e}. Retrying...")
                time.sleep(base_delay * (2 ** attempt))
        
        log.error(f"OpenRouter API failed after {max_retries} attempts.")
        return ""

    def _construct_prompt(self, code_snippet: str, context: Dict[str, Any]) -> str:
        system_prompt = context.get("system_prompt", "")
        vuln_prompt = context.get("vuln_prompt", "")

        # Use .replace() instead of .format() to handle code snippets containing {}
        # which would otherwise confuse the string formatter.
        formatted_prompt = vuln_prompt.replace("{code_snippet}", code_snippet)
        formatted_prompt = formatted_prompt.replace("{file_path}", context.get("file_path", "N/A"))

        return f"{system_prompt}\n\n{formatted_prompt}"
