import xml.etree.ElementTree as ET
import os
from core import log

class ManifestParser:
    def __init__(self, manifest_path: str):
        self.manifest_path = manifest_path
        self.root = self._parse_manifest()
        self.package_name = self.root.get('package') if self.root else ""

    def _parse_manifest(self):
        """Parses the XML file safely."""
        try:
            if not os.path.exists(self.manifest_path):
                log.warning(f"Manifest not found at {self.manifest_path}")
                return None
            tree = ET.parse(self.manifest_path)
            return tree.getroot()
        except Exception as e:
            log.error(f"Failed to parse AndroidManifest.xml: {e}")
            return None

    def get_component_details(self, component_name: str) -> dict:
        """
        Searches for a component (Activity, Receiver, Service, Provider) by name
        and returns its details: Intent Filters, Permissions, Exported status.
        Handles partial names (e.g. '.MainActivity') and full names.
        """
        if not self.root:
            return {}

        # Normalize component name (e.g. "com.example.MainActivity" -> ".MainActivity" suffix check)
        # Or ideally, match exact full name or suffix
        
        target_node = None
        component_types = ['activity', 'activity-alias', 'service', 'receiver', 'provider']
        
        # Traverse application -> component
        application = self.root.find('application')
        if application is None:
            return {}

        current_best_match = None

        for c_type in component_types:
            for node in application.findall(c_type):
                name = node.get('{http://schemas.android.com/apk/res/android}name')
                if not name:
                    continue
                
                # Direct match
                if name == component_name:
                    target_node = node
                    break
                
                # Check for relative name usage in manifest (e.g. name=".MainActivity")
                if name.startswith("."):
                    full_name = self.package_name + name
                    if full_name == component_name:
                        target_node = node
                        break
                
                # Check if the code uses full name but manifest uses relative
                # component_name might be "com.example.app.MainActivity"
                # manifest name might be ".MainActivity"
                if component_name.endswith(name):
                     # Weak match, keep looking for stronger match but store this
                     current_best_match = node

            if target_node:
                break
        
        if not target_node and current_best_match:
            target_node = current_best_match

        if not target_node:
            return {}

        # Extract Details
        exported = target_node.get('{http://schemas.android.com/apk/res/android}exported')
        permission = target_node.get('{http://schemas.android.com/apk/res/android}permission')
        
        intent_filters = []
        for intent_filter in target_node.findall('intent-filter'):
            filter_data = {
                "actions": [],
                "categories": [],
                "data": []
            }
            
            for action in intent_filter.findall('action'):
                filter_data["actions"].append(action.get('{http://schemas.android.com/apk/res/android}name'))
            
            for category in intent_filter.findall('category'):
                filter_data["categories"].append(category.get('{http://schemas.android.com/apk/res/android}name'))
                
            for data in intent_filter.findall('data'):
                scheme = data.get('{http://schemas.android.com/apk/res/android}scheme')
                host = data.get('{http://schemas.android.com/apk/res/android}host')
                path = data.get('{http://schemas.android.com/apk/res/android}path')
                pathPrefix = data.get('{http://schemas.android.com/apk/res/android}pathPrefix')
                mimeType = data.get('{http://schemas.android.com/apk/res/android}mimeType')
                
                data_entry = {}
                if scheme: data_entry["scheme"] = scheme
                if host: data_entry["host"] = host
                if path: data_entry["path"] = path
                if pathPrefix: data_entry["pathPrefix"] = pathPrefix
                if mimeType: data_entry["mimeType"] = mimeType
                
                if data_entry:
                    filter_data["data"].append(data_entry)
            
            intent_filters.append(filter_data)

        # Build Context String
        context_str = f"Component: {component_name}\n"
        context_str += f"Package: {self.package_name}\n"
        context_str += f"Exported: {exported}\n"
        if permission:
            context_str += f"Required Permission: {permission}\n"
        
        if intent_filters:
            context_str += "Intent Filters:\n"
            for idx, f in enumerate(intent_filters):
                context_str += f"  Filter {idx+1}:\n"
                if f['actions']: context_str += f"    Actions: {', '.join(filter(None, f['actions']))}\n"
                if f['categories']: context_str += f"    Categories: {', '.join(filter(None, f['categories']))}\n"
                for d in f['data']:
                    context_str += f"    Data: {d}\n"
        else:
            context_str += "Intent Filters: None (Warning: Exploit might require explicit component targeting)\n"

        return {
            "component_name": component_name,
            "exported": exported,
            "permission": permission,
            "intent_filters": intent_filters,
            "context_str": context_str
        }
