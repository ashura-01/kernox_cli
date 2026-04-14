"""
kernox.tools.live_discovery - Network host discovery using Scapy.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from typing import Dict, List, Optional

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# Try to import Scapy
try:
    from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class LiveDiscoveryTool:
    """Discover live hosts on network using ARP scan + optional ICMP."""

    name = "live_discovery"
    description = "Discover live hosts on local network (ARP scan)"

    def __init__(self, ai_client=None, session_state=None):
        self._ai = ai_client
        self._state = session_state

    def run_direct(
        self,
        target: str = None,
        timeout: float = 2.0,
        vendor_lookup: bool = True,
        icmp_fallback: bool = True,
        silent: bool = True,
        **kwargs,
    ) -> Dict:
        """
        Discover live hosts on network.

        Args:
            target: CIDR network (e.g., 192.168.1.0/24) or None for auto-detect
            timeout: ARP and ICMP timeout in seconds
            vendor_lookup: Query macvendors.com API for vendor names
            icmp_fallback: Also try ICMP ping for cross-subnet discovery
            silent: Suppress all terminal output
        """
        if not SCAPY_AVAILABLE:
            return self._fallback_no_scapy(target, silent)

        # Get network range
        if not target or target.lower() == "auto":
            target = self._detect_local_range()
            if not silent:
                console.print(f"[cyan]Auto-detected network: {target}[/cyan]")

        if not silent:
            console.print(f"[cyan]Scanning {target}...[/cyan]")

        # Step 1: ARP scan (primary - finds everything on local subnet)
        devices = self._arp_scan(target, timeout)

        # Step 2: ICMP fallback (for cross-subnet or if ARP found nothing)
        if icmp_fallback and not devices:
            if not silent:
                console.print("[dim]ARP found nothing, trying ICMP sweep...[/dim]")
            devices = self._icmp_sweep(target, timeout)

        if not devices:
            if not silent:
                console.print("[yellow]No live hosts found.[/yellow]")
            return {"hosts": [], "total": 0, "network": target}

        # Step 3: Enrich each device (TTL, OS, vendor)
        if not silent:
            console.print(f"[dim]Enriching {len(devices)} host(s)...[/dim]")

        for device in devices:
            self._enrich_device(device, timeout, vendor_lookup)

        # Step 4: Filter out gateway and broadcast
        devices = self._filter_hosts(devices, target)

        # Step 5: Sort by IP
        devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))

        # Step 6: Display results (if not silent)
        if not silent:
            self._print_results(devices, target)

        # Step 7: AI analysis (only IPs)
        ai_response = None
        if self._ai and devices:
            ai_response = self._ai_analyze([d["ip"] for d in devices], target)

        return {
            "hosts": devices,
            "total": len(devices),
            "network": target,
            "ai_suggestion": ai_response,
        }

    # ── Core scanning ─────────────────────────────────────────────────────────

    def _arp_scan(self, ip_range: str, timeout: float) -> List[Dict]:
        """ARP scan using Scapy."""
        try:
            ipaddress.ip_network(ip_range, strict=False)
        except ValueError:
            return []

        # Create ARP request packet
        arp_req = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp_req

        # Send and receive
        try:
            answered, _ = srp(packet, timeout=timeout, verbose=0)
        except Exception:
            return []

        devices = []
        for _, rcv in answered:
            devices.append({
                "ip": rcv.psrc,
                "mac": rcv.hwsrc.upper(),
                "method": "arp",
            })
        return devices

    def _icmp_sweep(self, ip_range: str, timeout: float) -> List[Dict]:
        """ICMP ping sweep using Scapy."""
        try:
            net = ipaddress.ip_network(ip_range, strict=False)
            ips = [str(ip) for ip in net.hosts()][:254]
        except Exception:
            return []

        devices = []
        for ip in ips:
            try:
                pkt = IP(dst=ip) / ICMP()
                reply = sr1(pkt, timeout=timeout, verbose=0)
                if reply:
                    devices.append({
                        "ip": ip,
                        "mac": "",
                        "method": "icmp",
                    })
            except Exception:
                continue
        return devices

    # ── Enrichment ────────────────────────────────────────────────────────────

    def _get_ttl(self, ip: str, timeout: float) -> Optional[int]:
        """Get TTL from ICMP response."""
        try:
            pkt = IP(dst=ip) / ICMP()
            reply = sr1(pkt, timeout=timeout, verbose=0)
            if reply:
                return reply.ttl
        except Exception:
            pass
        return None

    def _guess_os_from_ttl(self, ttl: Optional[int]) -> str:
        """Fingerprint OS from TTL value."""
        if ttl is None:
            return "Unknown"
        if ttl <= 64:
            return "Linux/Unix/macOS"
        if ttl <= 128:
            return "Windows"
        if ttl <= 255:
            return "Network Device"
        return "Unknown"

    def _get_vendor(self, mac: str) -> str:
        """Look up vendor from macvendors.com API."""
        if not mac or mac == "":
            return "N/A"
        try:
            import requests
            url = f"https://api.macvendors.com/{mac}"
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                return r.text.strip()
            if r.status_code == 404:
                return "Unknown vendor"
        except ImportError:
            return "requests not installed"
        except Exception:
            pass
        return "Lookup failed"

    def _enrich_device(self, device: Dict, timeout: float, vendor_lookup: bool) -> None:
        """Add TTL, OS, and vendor to device dict."""
        ip = device["ip"]
        mac = device.get("mac", "")

        # Get TTL and guess OS
        ttl = self._get_ttl(ip, timeout)
        os_guess = self._guess_os_from_ttl(ttl)

        device["ttl"] = ttl
        device["os"] = os_guess

        # Vendor lookup (with rate limiting for API)
        if vendor_lookup and mac:
            device["vendor"] = self._get_vendor(mac)
            time.sleep(0.5)  # Be polite to free API (1 req/sec)
        else:
            device["vendor"] = "Disabled"

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _detect_local_range(self) -> str:
        """Auto-detect local subnet."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.rsplit(".", 1)
            return f"{parts[0]}.0/24"
        except Exception:
            return "192.168.1.0/24"

    def _get_gateway(self) -> Optional[str]:
        """Get default gateway IP."""
        try:
            import subprocess as sp
            r = sp.run(["ip", "route", "show", "default"], capture_output=True, text=True)
            import re
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
        table.add_column("OS (TTL)", style="yellow", width=20)
        table.add_column("Vendor", style="white", width=25)

        for i, d in enumerate(devices, 1):
            table.add_row(
                str(i),
                d["ip"],
                d.get("mac", "?")[:17],
                f"{d.get('os', '?')} ({d.get('ttl', '?')})",
                d.get("vendor", "?")[:25],
            )

        console.print(table)
        console.print(f"\n[green]✓ Found {len(devices)} live host(s)[/green]")

    def _ai_analyze(self, ips: List[str], network: str) -> Optional[str]:
        """Single AI call - only gets IPs."""
        if not self._ai or not ips:
            return None

        ip_str = ", ".join(ips[:15])
        if len(ips) > 15:
            ip_str += f" (+{len(ips)-15} more)"

        prompt = f"Network: {network}\nIPs: {ip_str}\nWhich IPs to prioritize for scanning?"

        try:
            response = self._ai.chat(
                messages=[{"role": "user", "content": prompt}],
                system="Brief. Return only IPs and one sentence why.",
                max_tokens=100,
            )
            if response:
                console.print(Panel(
                    response,
                    title="[cyan]AI — Priority Targets[/cyan]",
                    border_style="cyan",
                    box=box.SIMPLE,
                ))
            return response
        except Exception:
            return None

    def _fallback_no_scapy(self, target: str, silent: bool) -> Dict:
        """Fallback when Scapy is not installed."""
        if not silent:
            console.print("[red]Scapy not installed. Run: pip install scapy[/red]")
        return {"hosts": [], "total": 0, "network": target or "unknown", "error": "scapy missing"}


if __name__ == "__main__":
    tool = LiveDiscoveryTool()
    result = tool.run_direct(silent=False)
    print(f"\nFound: {result['total']} hosts")
    if result.get('ai_suggestion'):
        print(f"\nAI: {result['ai_suggestion']}")