from abc import ABC, abstractmethod

class Decompiler(ABC):
    @abstractmethod
    def decompile(self, apk_path: str, output_dir: str):
        pass
