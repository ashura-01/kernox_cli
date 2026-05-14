"""
kernox.utils.network_ips – Silent IP detection for AI context.
"""

import subprocess
import re
from typing import Dict, Optional


def get_interface_ip(interface: str) -> Optional[str]:
    """Get IPv4 address for a specific network interface."""
    try:
        result = subprocess.run(
            ["ip", "addr", "show", interface],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode != 0:
            return None
        pattern = r'inet\s+(\d+\.\d+\.\d+\.\d+)/\d+'
        match = re.search(pattern, result.stdout)
        return match.group(1) if match else None
    except Exception:
        return None


def get_all_ips() -> Dict[str, Optional[str]]:
    """Get IPs for common network interfaces."""
    interfaces = ["eth0", "wlan0", "tun0", "eth1", "wlan1", "ens33"]
    return {iface: get_interface_ip(iface) for iface in interfaces}


def get_primary_ip() -> Optional[str]:
    """Get the most likely primary IP address."""
    for priority in ["eth0", "wlan0", "tun0", "ens33"]:
        ip = get_interface_ip(priority)
        if ip:
            return ip
    return None


def get_ip_context() -> str:
    """Return IP info as compact string for AI context (no console output)."""
    ips = get_all_ips()
    active = {k: v for k, v in ips.items() if v}
    
    if not active:
        return "No active network interfaces found."
    
    parts = [f"{k}={v}" for k, v in active.items()]
    primary = get_primary_ip()
    
    result = f"Your IPs: {', '.join(parts)}"
    if primary:
        result += f" | Primary: {primary}"
    
    return result