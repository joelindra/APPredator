import xml.etree.ElementTree as ET
from typing import List, Dict, Any
from core.logger import log

class ManifestParser:
    def __init__(self, manifest_path: str):
        self.manifest_path = manifest_path
        self.tree = self._load_manifest()

    def _load_manifest(self):
        try:
            return ET.parse(self.manifest_path)
        except ET.ParseError as e:
            log.error(f"Error parsing AndroidManifest.xml: {e}")
            raise
        except FileNotFoundError:
            log.error(f"AndroidManifest.xml not found at: {self.manifest_path}")
            raise

    def get_permissions(self) -> List[str]:
        root = self.tree.getroot()
        permissions = [
            elem.attrib["{http://schemas.android.com/apk/res/android}name"]
            for elem in root.findall("uses-permission")
        ]
        log.info(f"Found {len(permissions)} permissions.")
        return permissions

    def get_activities(self) -> List[str]:
        root = self.tree.getroot()
        activities = [
            elem.attrib["{http://schemas.android.com/apk/res/android}name"]
            for elem in root.findall(".//activity")
        ]
        log.info(f"Found {len(activities)} activities.")
        return activities

    def get_exported_components(self) -> Dict[str, List[str]]:
        root = self.tree.getroot()
        exported = {"activities": [], "services": [], "receivers": []}
        for component_type in exported.keys():
            for elem in root.findall(f".//{component_type}"):
                if elem.attrib.get("{http://schemas.android.com/apk/res/android}exported") == "true":
                    exported[component_type].append(
                        elem.attrib["{http://schemas.android.com/apk/res/android}name"]
                    )
        log.info(f"Found exported components: {exported}")
        return exported
