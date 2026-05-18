from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseLLMClient(ABC):
    @abstractmethod
    def analyze_code(self, code_snippet: str, context: Dict[str, Any]) -> str:
        pass
