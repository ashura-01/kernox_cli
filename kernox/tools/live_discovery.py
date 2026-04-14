"""
kernox.tools.live_discovery - Smart network host discovery with AI integration.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess as sp
import sys
import time
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm
from rich import box

console = Console()

# Try to import Scapy
try:
    from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, conf as scapy_conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class LiveDiscoveryTool:
    """
    Smart live host discovery with:
    - Automatic sudo handling
    - Multiple discovery methods (ARP, ping sweep, arp-scan)
    - AI integration for OS detection and prioritization
    - MAC vendor lookup
    """

    name = "live_discovery"
    description = "Discover live hosts with IP, MAC, OS, and vendor info"

    def __init__(self, ai_client=None, session_state=None):
        self._ai = ai_client
        self._state = session_state
        self._is_root = os.geteuid() == 0

    def build_command(self, **_) -> str:
        return ""

    def parse(self, output: str) -> Dict:
        return {"raw": output}

    def run_direct(
        self,
        target: str = None,
        timeout: float = 2.0,
        vendor_lookup: bool = True,
        icmp_fallback: bool = True,
        silent: bool = False,
        iface: str = None,
        **kwargs,
    ) -> Dict:
        """
        Discover live hosts on network with smart fallbacks.
        """
        # Auto-detect network if needed
        if not target or target.lower() == "auto":
            target = self._auto_detect_network(iface)
            if not silent:
                console.print(f"[cyan]Auto-detected network: {target}[/cyan]")
        #
        # if not silent:
        #     console.print(f"[cyan]Scanning {target}...[/cyan]")

        devices = []

        # Try methods in order of reliability
        # Method 1: ARP with Scapy (best, needs root)
        if self._is_root and SCAPY_AVAILABLE:
            devices = self._arp_scan_scapy(target, timeout, iface)
            if devices:
                if not silent:
                    console.print(f"[green]✓ ARP scan found {len(devices)} hosts[/green]")

        # Method 2: arp-scan binary (good fallback)
        if not devices:
            devices = self._arp_scan_binary(target, timeout, iface)
            if devices and not silent:
                console.print(f"[green]✓ arp-scan found {len(devices)} hosts[/green]")

        # Method 3: ICMP ping sweep (last resort)
        if icmp_fallback and not devices:
            if not silent:
                console.print("[dim]Trying ICMP ping sweep...[/dim]")
            devices = self._ping_sweep(target, timeout)
            if devices and not silent:
                console.print(f"[green]✓ ICMP sweep found {len(devices)} hosts[/green]")

        if not devices:
            if not silent:
                console.print("[yellow]No live hosts found.[/yellow]")
                if not self._is_root:
                    console.print("[dim]Tip: Run with 'sudo' for better ARP discovery[/dim]")
            return {"hosts": [], "total": 0, "network": target}

        # Enrich each device with OS, vendor, hostname
        if not silent:
            console.print(f"[dim]Enriching {len(devices)} host(s)...[/dim]")

        for device in devices:
            self._enrich_device(device, timeout, vendor_lookup)

        # Filter and sort
        devices = self._filter_hosts(devices, target)
        devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))

        # Display results
        if not silent:
            self._print_results(devices, target)

        # AI analysis - gets IPs and OS info
        ai_response = None
        if self._ai and devices:
            ai_response = self._ai_analyze(devices, target)

        return {
            "hosts": devices,
            "total": len(devices),
            "network": target,
            "ai_suggestion": ai_response,
        }

    # ── Discovery Methods ─────────────────────────────────────────────────────

    def _arp_scan_scapy(self, ip_range: str, timeout: float, iface: str = None) -> List[Dict]:
        """ARP scan using Scapy (requires root)."""
        if not SCAPY_AVAILABLE:
            return []

        try:
            arp = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            kwargs = {"timeout": timeout, "verbose": 0}
            if iface:
                kwargs["iface"] = iface

            answered, _ = srp(packet, **kwargs)

            devices = []
            for _, rcv in answered:
                devices.append({
                    "ip": rcv.psrc,
                    "mac": rcv.hwsrc.upper(),
                    "method": "arp-scapy",
                })
            return devices
        except PermissionError:
            return []
        except Exception:
            return []

    def _arp_scan_binary(self, ip_range: str, timeout: float, iface: str = None) -> List[Dict]:
        """ARP scan using arp-scan binary (works without root if setuid)."""
        cmd = ["arp-scan", ip_range, "--timeout", str(int(timeout))]
        if iface:
            cmd.extend(["--interface", iface])

        try:
            # Try without sudo first
            result = sp.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            if result.returncode != 0 and "permission" in result.stderr.lower():
                # Need sudo - ask once
                if Confirm.ask("[yellow]ARP scan needs sudo. Run with sudo?[/yellow]", default=True):
                    result = sp.run(["sudo"] + cmd, capture_output=True, text=True, timeout=timeout + 5)
                else:
                    return []

            devices = []
            for line in result.stdout.split("\n"):
                parts = line.strip().split("\t")
                if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    devices.append({
                        "ip": parts[0],
                        "mac": parts[1].upper() if len(parts) > 1 else "",
                        "vendor": parts[2] if len(parts) > 2 else "",
                        "method": "arp-scan",
                    })
            return devices
        except FileNotFoundError:
            return []
        except Exception:
            return []

    def _ping_sweep(self, ip_range: str, timeout: float) -> List[Dict]:
        """ICMP ping sweep using system ping (setuid root, works without sudo)."""
        devices = []
        try:
            net = ipaddress.ip_network(ip_range, strict=False)
            ips = [str(ip) for ip in net.hosts()][:254]

            for ip in ips:
                try:
                    result = sp.run(
                        ["ping", "-c", "1", "-W", "1", ip],
                        capture_output=True,
                        timeout=int(timeout) + 1
                    )
                    if result.returncode == 0:
                        devices.append({
                            "ip": ip,
                            "mac": "",
                            "method": "ping",
                        })
                except Exception:
                    continue
        except Exception:
            pass
        return devices

    # ── Enrichment Methods ────────────────────────────────────────────────────

    def _get_ttl(self, ip: str, timeout: float) -> Optional[int]:
        """Get TTL from ICMP response using system ping (reliable)."""
        try:
            result = sp.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True,
                text=True,
                timeout=int(timeout) + 1
            )
            # Parse TTL from output: "ttl=64"
            match = re.search(r"ttl=(\d+)", result.stdout.lower())
            if match:
                return int(match.group(1))
        except Exception:
            pass
        return None

    def _guess_os_from_ttl(self, ttl: Optional[int]) -> Tuple[str, int]:
        """Fingerprint OS from TTL value with confidence."""
        if ttl is None:
            return "Unknown", 0
        if ttl <= 64:
            return "Linux/Unix/macOS", 80
        if ttl <= 128:
            return "Windows", 80
        if ttl <= 255:
            return "Network Device", 60
        return "Unknown", 30

    def _get_vendor(self, mac: str) -> str:
        """Look up vendor from MAC OUI."""
        if not mac or len(mac) < 8:
            return ""

        oui = mac[:8].upper()
        # Simple OUI database (common vendors)
        oui_db = {
            "00:00:0C": "Cisco", "00:14:22": "Dell", "00:1A:A0": "HP",
            "00:1E:C2": "Apple", "00:25:9C": "Samsung", "00:50:56": "VMware",
            "08:00:27": "VirtualBox", "B8:27:EB": "Raspberry Pi", "00:15:5D": "Hyper-V",
            "00:0C:29": "VMware", "00:50:F2": "Microsoft", "00:1B:21": "Sony",
            "00:1A:11": "Google", "00:1E:8F": "Intel", "00:22:68": "Dell",
            "00:23:DF": "Apple", "00:24:36": "IBM", "00:26:2D": "Acer",
        }
        for prefix, vendor in oui_db.items():
            if mac.startswith(prefix):
                return vendor

        # Try online API as fallback
        try:
            import requests
            url = f"https://api.macvendors.com/{mac}"
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                return r.text.strip()[:30]
        except Exception:
            pass
        return ""

    def _enrich_device(self, device: Dict, timeout: float, vendor_lookup: bool) -> None:
        """Add TTL, OS, vendor, and hostname to device."""
        ip = device["ip"]

        # Get TTL and OS
        ttl = self._get_ttl(ip, timeout)
        device["ttl"] = ttl
        os_name, confidence = self._guess_os_from_ttl(ttl)
        device["os"] = os_name
        device["os_confidence"] = confidence

        # Get hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            device["hostname"] = hostname
        except Exception:
            device["hostname"] = ""

        # Get vendor from MAC
        if vendor_lookup and device.get("mac"):
            device["vendor"] = self._get_vendor(device["mac"])
        else:
            device["vendor"] = ""

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _auto_detect_network(self, iface: str = None) -> str:
        """Auto-detect local network range."""
        # Try to get from interface
        if iface:
            try:
                result = sp.run(["ip", "-4", "addr", "show", iface], capture_output=True, text=True)
                match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", result.stdout)
                if match:
                    ip = match.group(1)
                    cidr = match.group(2)
                    parts = ip.split(".")
                    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/{cidr}"
            except Exception:
                pass

        # Get default route interface
        try:
            result = sp.run(["ip", "route", "show", "default"], capture_output=True, text=True)
            match = re.search(r"dev\s+(\S+)", result.stdout)
            if match:
                iface_name = match.group(1)
                addr = sp.run(["ip", "-4", "addr", "show", iface_name], capture_output=True, text=True)
                ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", addr.stdout)
                if ip_match:
                    ip = ip_match.group(1)
                    parts = ip.split(".")
                    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            pass

        return "192.168.1.0/24"

    def _get_gateway(self) -> Optional[str]:
        """Get default gateway IP."""
        try:
            r = sp.run(["ip", "route", "show", "default"], capture_output=True, text=True)
            m = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", r.stdout)
            return m.group(1) if m else None
        except Exception:
            return None

    def _filter_hosts(self, devices: List[Dict], network: str) -> List[Dict]:
        """Remove gateway and broadcast addresses."""
        gateway = self._get_gateway()
        try:
            net = ipaddress.ip_network(network, strict=False)
            broadcast = str(net.broadcast_address)
            network_addr = str(net.network_address)
        except Exception:
            broadcast, network_addr = "", ""

        filtered = []
        for d in devices:
            ip = d["ip"]
            if ip in (gateway, broadcast, network_addr):
                continue
            if ip.startswith(("224.", "239.", "127.")):
                continue
            filtered.append(d)
        return filtered

    def _print_results(self, devices: List[Dict], network: str) -> None:
        """Display results in a clean table."""
        if not devices:
            console.print("[yellow]No live hosts found.[/yellow]")
            return

        table = Table(title=f"Live Hosts on {network}", box=box.HEAVY)
        table.add_column("#", style="cyan", width=4)
        table.add_column("IP", style="green", width=16)
        table.add_column("MAC", style="dim", width=18)
        table.add_column("OS", style="yellow", width=20)
        table.add_column("Vendor", style="white", width=20)
        table.add_column("Hostname", style="blue", width=20)

        for i, d in enumerate(devices, 1):
            table.add_row(
                str(i),
                d["ip"],
                d.get("mac", "?")[:17],
                f"{d.get('os', '?')} ({d.get('os_confidence', 0)}%)",
                d.get("vendor", "?")[:20],
                d.get("hostname", "?")[:20],
            )

        console.print(table)
        console.print(f"\n[green]✓ Found {len(devices)} live host(s)[/green]")

    def _ai_analyze(self, devices: List[Dict], network: str) -> Optional[str]:
        """
        AI analysis with full device info (IP + OS).
        This gives AI both IP and OS for better prioritization.
        """
        if not self._ai or not devices:
            return None

        # Build compact device list for AI
        device_lines = []
        for d in devices[:12]:
            line = f"IP={d['ip']} OS={d.get('os', 'Unknown')}"
            if d.get('open_ports'):
                line += f" ports={d['open_ports']}"
            device_lines.append(line)

        device_str = "\n".join(device_lines)
        if len(devices) > 12:
            device_str += f"\n... +{len(devices) - 12} more"

        prompt = f"""Network: {network}
Total hosts: {len(devices)}

Devices:
{device_str}

Which IPs to prioritize for scanning? Consider OS types and potential vulnerabilities.
Return ONLY: IPs and brief reason (2-3 sentences max)."""

        try:
            if hasattr(self._ai, "chat"):
                response = self._ai.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="Penetration tester. Prioritize targets. Be brief.",
                    max_tokens=200,
                )
            elif callable(self._ai):
                response = self._ai(prompt)
            else:
                return None

            if response:
                console.print(Panel(
                    str(response),
                    title="[cyan]AI — Priority Targets & Strategy[/cyan]",
                    border_style="cyan",
                    box=box.SIMPLE,
                ))
            return str(response) if response else None
        except Exception as e:
            console.print(f"[dim]AI analysis skipped: {e}[/dim]")
            return None


# Standalone test
if __name__ == "__main__":
    tool = LiveDiscoveryTool()
    result = tool.run_direct(silent=False)
    print(f"\nFound: {result['total']} hosts")
    for h in result['hosts']:
        print(f"  {h['ip']} - {h.get('os', '?')} - {h.get('vendor', '')}")
