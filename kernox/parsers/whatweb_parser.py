"""kernox.parsers.whatweb_parser - Complete universal parser"""
from __future__ import annotations
import re
from typing import Dict, List, Any


class WhatwebParser:
    """
    Complete WhatWeb parser that handles all output formats correctly.
    
    WhatWeb output format:
        URL [HTTP_STATUS] Plugin1[value], Plugin2[value], Plugin3[value1,value2]
    
    This parser extracts:
    - Target URL and IP
    - HTTP status code
    - ALL plugins with their exact values
    - Proper version extraction
    - Email addresses
    - Country information
    """
    
    def parse(self, raw: str) -> Dict[str, Any]:
        """Parse raw WhatWeb output into structured data"""
        
        # Remove ANSI color codes first
        raw = self._clean_ansi(raw)
        
        result = {
            "url": None,
            "ip": None,
            "status_code": None,
            "status_text": None,
            "plugins": {},           # All plugins: name -> value
            "technologies": [],      # List of plugin names (filtered)
            "versions": [],          # Extracted versions
            "cookies": [],           # Cookie names
            "country": None,
            "title": None,
            "server": None,
            "redirect": None,
            "powered_by": None,
            "emails": [],
            "raw": raw,
        }
        
        # Step 1: Extract target URL and IP from the beginning of the line
        url_match = re.match(r'^(https?://[^\s]+)', raw)
        if url_match:
            result["url"] = url_match.group(1)
            
            # Try to extract IP from URL or from IP plugin
            ip_match = re.search(r'IP\[([^\]]+)\]', raw)
            if ip_match:
                result["ip"] = ip_match.group(1)
            else:
                # Try to extract from URL
                url_ip = re.search(r'(\d{1,3}\.){3}\d{1,3}', result["url"])
                if url_ip:
                    result["ip"] = url_ip.group(0)
        
        # Step 2: Extract HTTP status code
        status_match = re.search(r'\[(\d{3})\s+([^\]]+)\]', raw)
        if status_match:
            result["status_code"] = int(status_match.group(1))
            result["status_text"] = status_match.group(2).strip()
        
        # Step 3: Extract ALL plugins (the core of WhatWeb)
        # Pattern: PluginName[value] or PluginName[value1,value2]
        # Important: Some values contain nested brackets, so we need to be careful
        
        # Method: Find all PluginName[ ... ] patterns where the brackets are balanced
        plugin_pattern = r'([A-Za-z][A-Za-z0-9\-]*)\[([^\]]*(?:\[[^\]]*\][^\]]*)*)\]'
        
        for match in re.finditer(plugin_pattern, raw):
            plugin_name = match.group(1)
            plugin_value = match.group(2).strip()
            
            # Skip if this is part of the URL or status
            if plugin_name in ['http', 'https']:
                continue
            
            # Store the raw value
            result["plugins"][plugin_name] = plugin_value
            
            # Process specific plugins with special handling
            self._process_special_plugin(plugin_name, plugin_value, result)
        
        # Step 4: Extract technologies (all plugin names except metadata)
        metadata_plugins = {'IP', 'Title', 'HTTPServer', 'Cookies', 'Country', 
                           'RedirectLocation', 'X-Powered-By', 'Status', 'URL'}
        
        result["technologies"] = [
            name for name in result["plugins"].keys() 
            if name not in metadata_plugins
        ]
        
        # Step 5: Extract versions from plugin values
        result["versions"] = self._extract_versions(result["plugins"])
        
        # Step 6: Extract emails
        result["emails"] = list(set(re.findall(r'[\w\.\-]+@[\w\.\-]+\.\w+', raw)))
        
        return result
    
    def _process_special_plugin(self, name: str, value: str, result: Dict) -> None:
        """Process plugins that have special meaning"""
        
        if name == 'Title':
            result["title"] = value
            
        elif name == 'HTTPServer':
            result["server"] = value
            
        elif name == 'Cookies':
            # Split by comma, but be careful with spaces
            result["cookies"] = [c.strip() for c in value.split(',') if c.strip()]
            
        elif name == 'Country':
            result["country"] = value
            
        elif name == 'RedirectLocation':
            result["redirect"] = value
            
        elif name == 'X-Powered-By':
            result["powered_by"] = value
            
        elif name == 'IP':
            result["ip"] = value
    
    def _extract_versions(self, plugins: Dict[str, str]) -> List[Dict[str, str]]:
        """Extract version numbers from plugin values"""
        versions = []
        
        # Version patterns
        version_patterns = [
            r'(\d+\.\d+\.\d+(?:-\w+)?)',           # 1.2.3 or 1.2.3-beta
            r'(\d+\.\d+(?:\.\d+)?)',                # 1.2 or 1.2.3
            r'v(\d+(?:\.\d+)+)',                    # v1.2.3
            r'version[:\s]+(\d+(?:\.\d+)+)',        # version: 1.2.3
            r'(\d+(?:\.\d+)+)[-\s]',                # 1.2.3-something
        ]
        
        for plugin_name, plugin_value in plugins.items():
            # Skip metadata plugins
            if plugin_name in ['IP', 'Title', 'Cookies', 'Country', 'RedirectLocation']:
                continue
            
            # Try each pattern
            for pattern in version_patterns:
                matches = re.findall(pattern, plugin_value, re.IGNORECASE)
                for match in matches:
                    # Clean up the version string
                    version = match.strip()
                    if version and len(version) < 30:  # Sanity check
                        versions.append({
                            "tech": plugin_name,
                            "version": version
                        })
                        break  # Found a version, move to next plugin
        
        # Remove duplicates (same tech and version)
        unique = []
        seen = set()
        for v in versions:
            key = f"{v['tech']}|{v['version']}"
            if key not in seen:
                seen.add(key)
                unique.append(v)
        
        return unique
    
    def _clean_ansi(self, text: str) -> str:
        """Remove ANSI escape sequences and clean up"""
        # Remove ANSI codes
        text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
        # Remove carriage returns
        text = text.replace('\r', '')
        # Normalize newlines
        text = text.replace('\n', ' ')
        # Remove extra spaces
        text = re.sub(r'\s+', ' ', text)
        return text.strip()


# The formatter - shows EVERYTHING
