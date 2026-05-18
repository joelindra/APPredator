import re
import os
from collections import defaultdict
from core import log

class CallGraphBuilder:
    def __init__(self, decompiled_dir: str):
        self.decompiled_dir = decompiled_dir
        # Map: class_name -> list of (callee_class, callee_method)
        self.call_graph = defaultdict(set)
        # Map: class_name -> file_path
        self.class_to_file = {}
        # Regex patterns
        self.class_pattern = re.compile(r'^\.class\s+(?:public|private|protected|abstract|interface|static|final|synthetic)*\s*L([\w/$]+);')
        self.invoke_pattern = re.compile(r'invoke-\w+\s+\{.*\},\s+L([\w/$]+);->(\w+)\(')

    def build(self):
        log.info("Building call graph from Smali files...")
        count = 0
        for root, _, files in os.walk(self.decompiled_dir):
            for file in files:
                if file.endswith(".smali"):
                    file_path = os.path.join(root, file)
                    self._parse_file(file_path)
                    count += 1
        log.success(f"Call graph built from {count} files.")

    def _parse_file(self, file_path: str):
        current_class = None
        
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                
            for line in lines:
                line = line.strip()
                
                # Find class definition
                if line.startswith(".class"):
                    match = self.class_pattern.search(line)
                    if match:
                        current_class = match.group(1)
                        self.class_to_file[current_class] = file_path
                        continue
                
                # Find method invocations
                if line.startswith("invoke-") and current_class:
                    match = self.invoke_pattern.search(line)
                    if match:
                        callee_class = match.group(1)
                        callee_method = match.group(2)
                        
                        # Optimization: Ignore standard Android/Java calls to reduce noise
                        # Only track calls to classes within the app or libraries included in the apk
                        if not callee_class.startswith("java/") and not callee_class.startswith("android/"):
                            self.call_graph[current_class].add((callee_class, callee_method))
                            
        except Exception as e:
            log.warning(f"Error parsing smali file {file_path}: {e}")

    def get_dependencies(self, file_path: str) -> list:
        """Returns a list of file paths that the given file depends on (calls)."""
        # 1. Find the class name for this file
        target_class = None
        for cls, path in self.class_to_file.items():
            if path == file_path:
                target_class = cls
                break
        
        if not target_class:
            return []

        # 2. Get callees from graph
        callees = self.call_graph.get(target_class, set())
        
        # 3. Resolve callees to file paths
        dependency_files = set()
        for callee_class, _ in callees:
            if callee_class in self.class_to_file:
                # Avoid self-reference
                if callee_class != target_class:
                    dependency_files.add(self.class_to_file[callee_class])
        
        return list(dependency_files)
