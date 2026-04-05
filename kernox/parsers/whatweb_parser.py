"""kernox.parsers.whatweb_parser - Fixed version"""
from __future__ import annotations
import re


class WhatwebParser:
    # Match plugin patterns like:   Apache[2.2.8]  or  PHP[5,5.2.4...]
    # Format: PLUGINNAME[value] or just [status] like [302 Found]
    PLUGIN_RE = re.compile(r'(?:^|\s)([A-Za-z][A-Za-z\-]*)\[([^\]]+)\]|\[(\d{3}\s+[A-Z]+)\]')
    
    # Match version patterns within brackets
    VERSION_RE = re.compile(r'(\d+(?:\.\d+)+)')
    
    # Email extraction
    EMAIL_RE = re.compile(r'[\w\.\-]+@[\w\.\-]+\.\w+')
    
    # IP extraction
    IP_RE = re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b')
    
    def parse(self, raw: str) -> dict:
        raw = self._clean_ansi(raw)
        
        technologies = {}
        status_code = None
        title = None
        server = None
        cookies = []
        country = None
        redirect = None
        
        # Parse plugin patterns: Name[value]
        for match in self.PLUGIN_RE.finditer(raw):
            if match.group(1):  # Plugin with name
                name = match.group(1)
                value = match.group(2)
                
                # Clean up value (remove extra brackets, truncate)
                value = value.strip()
                if len(value) > 100:
                    value = value[:100]
                
                if name == 'Cookies':
                    cookies = [c.strip() for c in value.split(',')]
                elif name == 'Country':
                    country = value
                elif name == 'RedirectLocation':
                    redirect = value
                elif name == 'HTTPServer':
                    server = value
                elif name == 'Title':
                    title = value
                else:
                    technologies[name] = value
                    
            elif match.group(3):  # Status code like [302 Found]
                status_code = match.group(3)
        
        # Extract versions from technology values
        versions = []
        for tech, value in technologies.items():
            version_matches = self.VERSION_RE.findall(value)
            if version_matches:
                for v in version_matches:
                    versions.append({"tech": tech, "version": v})
            elif value and value != tech:
                # Store as detected without explicit version
                versions.append({"tech": tech, "version": "detected"})
        
        # Extract emails
        emails = list(set(self.EMAIL_RE.findall(raw)))
        
        # Extract IPs
        ips = list(set(self.IP_RE.findall(raw)))
        
        # Build result
        result = {
            "technologies": list(technologies.keys()),
            "versions": versions,
            "status_code": status_code,
            "title": title,
            "server": server,
            "cookies": cookies,
            "country": country,
            "redirect": redirect,
            "emails": emails,
            "ips": ips,
            "raw": raw,
        }
        
        return result
    
    def _clean_ansi(self, text: str) -> str:
        """Remove ANSI escape sequences"""
        return re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)