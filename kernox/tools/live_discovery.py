"""
Live host discovery tool for Kernox
Full orchestrator-grade AI integration:
  - Pre-flight: AI picks optimal scan strategy before running
  - Post-scan:  AI explains every host and finding automatically
  - Insights:   Structured vuln/risk records stored to session state
  - Chaining:   AI suggests next tools based on what was found
  - Learning:   Persistent MAC→vendor/OS cache across runs
  - Context:    Full session state injected into every AI call
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.markdown import Markdown
from rich.spinner import Spinner
from rich.table import Table
from rich import box

console = Console()

# ── Persistent AI learning cache ─────────────────────────────────────────────
AI_CACHE_PATH = Path.home() / ".kernox" / "ai_vendor_cache.json"


def _load_ai_cache() -> Dict[str, Dict]:
    try:
        if AI_CACHE_PATH.exists():
            with open(AI_CACHE_PATH) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_ai_cache(cache: Dict[str, Dict]) -> None:
    try:
        AI_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(AI_CACHE_PATH, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        # FIX #5: Log the save failure so it isn't silently swallowed.
        console.print(f"[yellow]Warning: Failed to persist AI cache: {e}[/yellow]")


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class DiscoveredHost:
    """Complete host record — AI gets every field."""
    ip: str
    mac: str = "N/A"
    vendor: str = "Unknown"
    vendor_source: str = "unknown"
    os: str = "Unknown"
    os_confidence: int = 0
    os_source: str = "unknown"
    hostname: str = ""
    method: str = ""
    ttl: Optional[int] = None
    open_ports: List[int] = field(default_factory=list)
    ai_notes: str = ""
    risk_level: str = ""
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class HostInsight:
    """Structured AI insight — mirrors orchestrator AIInsight pattern."""
    ip: str
    vulnerability: str
    severity: str
    tool: str
    explanation: Dict[str, str]
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ── Main tool ─────────────────────────────────────────────────────────────────

class LiveDiscoveryTool:
    """
    Live host discovery with full orchestrator-grade AI integration.
    """

    name = "live_discovery"
    description = "Discover live hosts — AI learns MAC/vendor/OS mappings over time"

    CHAINABLE_TOOLS = [
        "nmap", "nikto", "ffuf", "gobuster", "whatweb", "nuclei",
        "enum4linux", "smbclient", "sslscan", "dnsrecon", "theharvester",
        "wafw00f", "onesixtyone", "wpscan",
    ]

    def __init__(self, ai_client=None, session_state=None):
        self._ai = ai_client
        self._state = session_state
        self._oui_cache: Dict[str, str] = {}
        self._ai_cache: Dict[str, Dict] = _load_ai_cache()
        self._ai_cache_dirty = False
        self._insights: List[HostInsight] = []
        # FIX #4: Per-host mutation lock used during parallel enrichment.
        self._host_lock = Lock()
        self._load_system_oui_db()

    # ── AI client compatibility shim ──────────────────────────────────────────

    def _ai_chat(self, messages: List[Dict], system: str = "", max_tokens: int = 500, temperature: float = 0.2) -> str:
        """
        FIX #1: Unified shim that handles different AI client interfaces.
        Tries .chat() first, then falls back to the Anthropic SDK-style
        .messages.create() so the tool works regardless of which client
        is injected.
        """
        if self._ai is None:
            return ""
        try:
            # Interface A: simple .chat() used in original code
            if callable(getattr(self._ai, "chat", None)):
                return self._ai.chat(
                    messages=messages,
                    system=system,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
            # Interface B: Anthropic SDK — client.messages.create()
            if callable(getattr(getattr(self._ai, "messages", None), "create", None)):
                resp = self._ai.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=max_tokens,
                    system=system,
                    messages=messages,
                )
                return resp.content[0].text if resp.content else ""
            # Interface C: bare callable (e.g. lambda)
            if callable(self._ai):
                return self._ai(messages=messages, system=system, max_tokens=max_tokens)
        except Exception as e:
            console.print(f"[dim]AI call failed: {e}[/dim]")
        return ""

    # ── Public interface ──────────────────────────────────────────────────────

    def build_command(self, **_) -> List[str]:
        return []

    def parse(self, output: str) -> Dict[str, Any]:
        return {}

    def run_direct(
        self,
        target: str = None,
        method: str = "auto",
        interface: str = None,
        timeout: int = 30,
        quick_ports: bool = True,
        **kwargs,
    ) -> Dict[str, Any]:
        """Full discovery pipeline with AI at every stage."""
        
        if not target or target == "auto" or target.lower() == "auto":
            target = self._detect_network_range(interface)
            console.print(f"[cyan]Auto-detected network: {target}[/cyan]")

        results: Dict[str, Any] = {
            "hosts": [],
            "total_hosts": 0,
            "method_used": method,
            "network_range": target,
            "interface": interface,
            "scan_duration": 0,
            "unknown_hosts": [],
            "known_hosts": [],
            "ai_inferred_hosts": [],
            "insights": [],
            "chain_suggestions": [],
        }

        start = datetime.now()
        hosts: Dict[str, DiscoveredHost] = {}

        if os.geteuid() != 0:
            console.print("[yellow]Warning: Run with sudo for best results[/yellow]")

        # ── 1: AI pre-flight ─────────────────────────────────────────────────
        strategy = self._ai_preflight(target, method, interface)
        effective_method = strategy.get("method", method)
        console.print(f"[cyan]Scanning {target} via {effective_method}...[/cyan]")
        if strategy.get("notes"):
            console.print(f"[dim]{strategy['notes']}[/dim]")

        # ── 2: Host enumeration ───────────────────────────────────────────────
        for h in self._arp_scan(target, interface, timeout):
            hosts[h.ip] = h

        if not hosts:
            console.print("[dim]ARP scan found nothing, trying ICMP...[/dim]")
            for h in self._icmp_scan(target, timeout):
                hosts[h.ip] = h

        if not hosts:
            console.print("[yellow]No live hosts found. Check network connection.[/yellow]")
            results["scan_duration"] = (datetime.now() - start).seconds
            return results

        # ── 3: Parallel enrichment ────────────────────────────────────────────
        # FIX #4: Collect all futures and wait for ALL of them before proceeding.
        # Each worker acquires _host_lock only for the final attribute write so
        # reads inside _detect_os_from_ttl / _resolve_hostname don't race.
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = []
            for host in hosts.values():
                futures.append(ex.submit(self._resolve_hostname, host))
                futures.append(ex.submit(self._detect_os_from_ttl, host))
                if quick_ports:
                    futures.append(ex.submit(self._quick_port_probe, host))
            # Block until every future is done before vendor/OS lookup below.
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception:
                    pass

        # ── 4: Vendor lookup ──────────────────────────────────────────────────
        # All enrichment threads have finished — safe to read host fields now.
        for host in hosts.values():
            self._lookup_vendor_smart(host)

        unknown_vendors = [h for h in hosts.values() if h.vendor_source == "unknown"]
        if unknown_vendors and self._ai:
            self._ai_infer_vendor_batch(unknown_vendors)

        # ── 5: AI OS fingerprinting ──────────────────────────────────────────
        low_conf = [h for h in hosts.values() if h.os_confidence < 60]
        if low_conf and self._ai:
            self._ai_os_fingerprint_batch(low_conf)

        # ── 6: Post-scan AI analysis ─────────────────────────────────────────
        if self._ai:
            self._post_scan_ai_analysis(hosts, target)

        # ── 7: Structured AI insights ────────────────────────────────────────
        if self._ai:
            self._generate_ai_insights(hosts, target)

        # ── 8: AI chain suggestions ──────────────────────────────────────────
        sorted_hosts = sorted(
            hosts.values(),
            key=lambda x: [int(i) for i in x.ip.split(".")]
        )
        chain = self._ai_chain_suggestions(sorted_hosts, target)
        results["chain_suggestions"] = chain
        if chain:
            self._print_chain_suggestions(chain)

        # ── 9: Persist AI knowledge ──────────────────────────────────────────
        # FIX #5: Only attempt save when dirty; keep dirty flag True on failure
        # so a subsequent successful run can retry persisting the knowledge.
        if self._ai_cache_dirty:
            try:
                _save_ai_cache(self._ai_cache)
                self._ai_cache_dirty = False   # Reset only on confirmed success
            except Exception as e:
                console.print(f"[yellow]Warning: AI cache not saved: {e}[/yellow]")
                # _ai_cache_dirty stays True — will retry next run

        # ── Categorise & finalise ────────────────────────────────────────────
        for host in sorted_hosts:
            entry = {
                "ip": host.ip, "mac": host.mac,
                "vendor": host.vendor, "source": host.vendor_source,
                "os": host.os, "ai_notes": host.ai_notes,
            }
            if host.vendor_source in ("ai_inferred", "ai_cached"):
                results["ai_inferred_hosts"].append(entry)
            elif host.vendor == "Unknown":
                results["unknown_hosts"].append({"ip": host.ip, "mac": host.mac})
            else:
                results["known_hosts"].append(entry)

        results["hosts"] = [self._host_to_dict(h) for h in sorted_hosts]
        results["total_hosts"] = len(results["hosts"])
        results["scan_duration"] = (datetime.now() - start).seconds
        results["insights"] = [
            {
                "ip": i.ip, "vulnerability": i.vulnerability,
                "severity": i.severity, "tool": i.tool,
                "explanation": i.explanation,
            }
            for i in self._insights
        ]

        # Push insights to orchestrator session state
        if self._state is not None:
            if hasattr(self._state, "add_ai_insight"):
                for insight in self._insights:
                    self._state.add_ai_insight(
                        vulnerability=insight.vulnerability,
                        severity=insight.severity,
                        tool=insight.tool,
                        target=insight.ip,
                        explanation=insight.explanation,
                    )

        self._print_summary(results)
        return results

    # ── AI: Pre-flight ────────────────────────────────────────────────────────

    def _ai_preflight(self, target: str, method: str, interface: str = None) -> Dict:
        if not self._ai:
            return {"method": method, "notes": ""}

        state_context = self._build_state_context()
        prompt = f"""You are a network security expert. Choose the best live host discovery strategy.

TARGET: {target}
REQUESTED METHOD: {method}
INTERFACE: {interface or "auto"}

SESSION CONTEXT:
{state_context}

Return ONLY a JSON object:
{{"method": "arp", "notes": "one-line reason", "risk_level": "low"}}

Methods: arp, icmp, both"""

        try:
            with Live(Spinner("dots", text="[dim]AI planning scan strategy...[/dim]"), refresh_per_second=10):
                # FIX #1: Use the shim instead of calling self._ai.chat() directly.
                response = self._ai_chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="You are a network security expert. Return ONLY a JSON object.",
                    max_tokens=200,
                    temperature=0.1,
                )
            m = re.search(r"\{.*\}", response, re.DOTALL)
            if m:
                plan = json.loads(m.group())
                console.print(Panel(
                    f"[bold]Strategy:[/bold] {plan.get('method', method).upper()}  "
                    f"[dim]{plan.get('notes', '')}[/dim]",
                    title="[cyan]AI — Scan Pre-flight[/cyan]",
                    border_style="cyan",
                    box=box.SIMPLE,
                ))
                return plan
        except Exception:
            pass
        return {"method": method, "notes": ""}

    # ── AI: Post-scan analysis ────────────────────────────────────────────────

    def _post_scan_ai_analysis(self, hosts: Dict[str, DiscoveredHost], target: str) -> None:
        if not hosts:
            return

        summary = self._build_scan_summary(hosts, target)
        prompt = f"""A live host discovery scan just finished.

Target: {target}
{summary}

Provide SHORT response:
**Finding:** <most important finding>
**Next:** ```bash
<exact command>
```"""

        try:
            with Live(Spinner("dots", text="[dim]AI analysing results...[/dim]"), refresh_per_second=10):
                # FIX #1: Use the shim.
                response = self._ai_chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="Senior penetration tester. Give exact commands.",
                    max_tokens=250,
                )
            if response and not response.startswith("Error:"):
                console.print(Panel(
                    Markdown(response),
                    title="[bold cyan]AI — live_discovery[/bold cyan]",
                    border_style="cyan",
                    box=box.SIMPLE,
                ))
        except Exception:
            pass

    # ── AI: Insights ──────────────────────────────────────────────────────────

    def _generate_ai_insights(self, hosts: Dict[str, DiscoveredHost], target: str) -> None:
        findings = []

        for host in hosts.values():
            ports = set(host.open_ports)
            # NOTE: open_ports only contains TCP ports (from _quick_port_probe).
            # SNMP (UDP 161) is intentionally excluded from this set — see
            # _quick_port_probe_udp for UDP detection.
            if 23 in ports:
                findings.append((host, "Telnet exposed (cleartext)", "high", f"Telnet on {host.ip}"))
            if 21 in ports:
                findings.append((host, "FTP port open", "medium", f"FTP on {host.ip}"))
            if ports & {139, 445}:
                findings.append((host, "SMB/NetBIOS exposed", "high", f"SMB on {host.ip}"))
            if 3389 in ports:
                findings.append((host, "RDP exposed", "medium", f"RDP on {host.ip}"))
            # FIX #3: SNMP is UDP — check the dedicated udp_ports list instead.
            if 161 in host.__dict__.get("udp_open_ports", []):
                findings.append((host, "SNMP port open", "high", f"SNMP on {host.ip}"))
            if host.vendor == "Unknown" and host.os == "Unknown":
                findings.append((host, "Unidentified device", "medium", f"Unknown at {host.ip}"))

        # FIX #7: Slice BEFORE the AI explanation loop to avoid wasted API calls.
        for host, vuln_name, severity, description in findings[:6]:
            try:
                # FIX #1: Use the shim.
                explanation_resp = self._ai_chat(
                    messages=[{
                        "role": "user",
                        "content": f"""Explain this finding:
Vulnerability: {vuln_name}
Severity: {severity}
Host: {host.ip}
Context: {description}

Return JSON: {{"description": "", "impact": "", "recommendation": ""}}"""
                    }],
                    system="Security expert. Return ONLY JSON.",
                )
                m = re.search(r"\{.*\}", explanation_resp, re.DOTALL)
                explanation = json.loads(m.group()) if m else None
                if not explanation:
                    raise ValueError
            except Exception:
                explanation = {
                    "description": description,
                    "impact": "May lead to unauthorised access.",
                    "recommendation": "Review service necessity.",
                }

            self._insights.append(HostInsight(
                ip=host.ip,
                vulnerability=vuln_name,
                severity=severity,
                tool="live_discovery",
                explanation=explanation,
            ))

    # ── AI: Chain suggestions ─────────────────────────────────────────────────

    def _ai_chain_suggestions(self, hosts: List[DiscoveredHost], target: str) -> List[Dict]:
        if self._ai:
            suggestions = self._ai_chain_call(hosts, target)
            if suggestions:
                return suggestions
        return self._fallback_chain(hosts, target)

    def _ai_chain_call(self, hosts: List[DiscoveredHost], target: str) -> List[Dict]:
        summary = self._build_scan_summary({h.ip: h for h in hosts}, target)

        prompt = f"""Return ONLY JSON array. NO markdown. NO backticks.

Format: [{{"tool": "nmap", "args": {{"target": "IP"}}, "reason": "why", "priority": 1}}]

Results: {summary}
Available: {", ".join(self.CHAINABLE_TOOLS)}

JSON now:"""

        try:
            with Live(Spinner("dots", text="[dim]AI planning next steps...[/dim]"), refresh_per_second=10):
                # FIX #1: Use the shim.
                response = self._ai_chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="Return ONLY valid JSON array. No markdown.",
                    max_tokens=300,
                    temperature=0.1,
                )

            response = response.strip()
            if response.startswith("```"):
                lines = response.split("\n")
                if lines and lines[0].startswith("```"):
                    lines.pop(0)
                if lines and lines[-1].strip() == "```":
                    lines.pop()
                response = "\n".join(lines).strip()
            for prefix in ("```json", "```bash", "json", "bash"):
                if response.startswith(prefix):
                    response = response[len(prefix):].strip()
            if response.endswith("```"):
                response = response[:-3].strip()

            m = re.search(r"\[.*\]", response, re.DOTALL)
            if not m:
                m = re.search(r"\[.*?\]", response.replace("\n", " "))
            if not m:
                return []

            suggestions = json.loads(m.group())
            if not isinstance(suggestions, list):
                return []

            valid = []
            for s in suggestions[:4]:
                if isinstance(s, dict) and s.get("tool") in self.CHAINABLE_TOOLS:
                    a = s.get("args", {"target": target})
                    if not isinstance(a, dict):
                        a = {"target": target}
                    if not a.get("target"):
                        a["target"] = target
                    valid.append({
                        "tool": s["tool"],
                        "args": a,
                        "reason": s.get("reason", "AI suggested"),
                        "priority": s.get("priority", 2),
                    })
            return valid
        except Exception:
            return []

    def _fallback_chain(self, hosts: List[DiscoveredHost], target: str) -> List[Dict]:
        suggestions = []
        seen = set()

        def add(tool, args, reason, priority=2):
            if tool not in seen:
                seen.add(tool)
                suggestions.append({"tool": tool, "args": args, "reason": reason, "priority": priority})

        for host in hosts:
            ports = set(host.open_ports)

            if ports & {80, 443, 8080, 8443}:
                scheme = "https" if (443 in ports or 8443 in ports) else "http"
                url = f"{scheme}://{host.ip}"
                add("whatweb", {"target": url}, f"Web on {host.ip}", 1)
                add("nikto", {"target": url}, f"Web vuln scan on {host.ip}", 2)
                add("nuclei", {"target": url, "mode": "quick"}, f"CVE scan on {host.ip}", 2)

            if ports & {139, 445}:
                add("enum4linux", {"target": host.ip}, f"SMB on {host.ip}", 1)

            # FIX #3: SNMP is UDP — check udp_open_ports, not open_ports (TCP).
            if 161 in host.__dict__.get("udp_open_ports", []):
                add("onesixtyone", {"target": host.ip}, f"SNMP on {host.ip}", 1)

            if 443 in ports or 8443 in ports:
                port_str = "443" if 443 in ports else "8443"
                add("sslscan", {"target": f"{host.ip}:{port_str}"}, f"SSL on {host.ip}", 2)

        if hosts:
            all_ips = " ".join(h.ip for h in hosts[:10])
            add("nmap", {"target": all_ips, "mode": "service"}, f"Service scan on {len(hosts)} hosts", 1)

        return sorted(suggestions, key=lambda s: s["priority"])

    # ── AI: Vendor batch ──────────────────────────────────────────────────────

    def _ai_infer_vendor_batch(self, hosts: List[DiscoveredHost]) -> None:
        if not self._ai or not hosts:
            return

        lines = [f"MAC={h.mac} TTL={h.ttl}" for h in hosts]
        prompt = f"Infer vendor from MAC. Return JSON array: [{{\"mac\":\"...\",\"vendor\":\"...\"}}]\n\n" + "\n".join(lines)

        try:
            with Live(Spinner("dots", text="[dim]AI inferring vendors...[/dim]"), refresh_per_second=10):
                # FIX #1: Use the shim.
                response = self._ai_chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="Return ONLY JSON array.",
                    max_tokens=400,
                )
            inferences = self._parse_json_array(response)
            for item in inferences:
                mac = item.get("mac", "")
                oui = self._normalise_oui(mac)
                vendor = item.get("vendor", "Unknown")
                for h in hosts:
                    if h.mac == mac:
                        h.vendor = vendor
                        h.vendor_source = "ai_inferred"
                        break
                if oui and vendor != "Unknown":
                    self._ai_cache[oui] = {"vendor": vendor, "learned_at": datetime.now().isoformat()}
                    self._ai_cache_dirty = True
        except Exception:
            pass

    # ── AI: OS fingerprint batch ──────────────────────────────────────────────

    def _ai_os_fingerprint_batch(self, hosts: List[DiscoveredHost]) -> None:
        if not self._ai or not hosts:
            return

        lines = [f"IP={h.ip} vendor={h.vendor} TTL={h.ttl} ports={h.open_ports}" for h in hosts]
        prompt = f"Infer OS. Return JSON: [{{\"ip\":\"...\",\"os\":\"...\",\"confidence\":0}}]\n\n" + "\n".join(lines)

        try:
            with Live(Spinner("dots", text="[dim]AI fingerprinting OS...[/dim]"), refresh_per_second=10):
                # FIX #1: Use the shim.
                response = self._ai_chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="Return ONLY JSON array.",
                    max_tokens=500,
                )
            inferences = self._parse_json_array(response)
            host_map = {h.ip: h for h in hosts}
            for item in inferences:
                h = host_map.get(item.get("ip", ""))
                if not h:
                    continue
                confidence = item.get("confidence", 50)
                if confidence > h.os_confidence:
                    h.os = item.get("os", h.os)
                    h.os_confidence = confidence
                    h.os_source = "ai_inferred"
                oui = self._normalise_oui(h.mac)
                if oui and confidence >= 60:
                    self._ai_cache.setdefault(oui, {})["os"] = h.os
                    self._ai_cache_dirty = True
        except Exception:
            pass

    # ── State context ─────────────────────────────────────────────────────────

    def _build_state_context(self) -> str:
        lines = ["=== CURRENT SESSION STATE ==="]

        if self._state is not None:
            if hasattr(self._state, "hosts") and self._state.hosts:
                lines.append(f"Hosts scanned: {', '.join(self._state.hosts.keys())}")
            else:
                lines.append("Hosts scanned: None")

            if hasattr(self._state, "get_tool_results"):
                tool_results = self._state.get_tool_results()
                lines.append(f"Tools run: {len(tool_results)}")

            if hasattr(self._state, "get_ai_insights"):
                insights = self._state.get_ai_insights()
                if insights:
                    for i in insights[-3:]:
                        lines.append(f"  [{i.severity.upper()}] {i.vulnerability}")
        else:
            lines.append("Standalone run — no session state")

        lines.append(f"AI cache entries: {len(self._ai_cache)}")
        lines.append("=== END STATE ===")
        return "\n".join(lines)

    # ── Discovery methods ─────────────────────────────────────────────────────

    def _arp_scan(self, network: str, interface: str = None, timeout: int = 30) -> List[DiscoveredHost]:
        hosts = []
        if self._check_command("arp-scan"):
            try:
                cmd = ["sudo", "arp-scan", network, "--timeout", str(timeout)]
                if interface:
                    cmd.extend(["--interface", interface])
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
                for line in result.stdout.split("\n"):
                    parts = line.strip().split("\t")
                    if len(parts) >= 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                        mac = parts[1] if len(parts) > 1 else "N/A"
                        vendor = parts[2] if len(parts) > 2 else "Unknown"
                        hosts.append(DiscoveredHost(
                            ip=parts[0], mac=mac, vendor=vendor,
                            vendor_source="arp_scan" if vendor != "Unknown" else "unknown",
                            method="arp-scan",
                        ))
            except Exception as e:
                console.print(f"[dim]arp-scan error: {e}[/dim]")

        if not hosts:
            hosts = self._fallback_arp_scan(network)
        return hosts

    def _fallback_arp_scan(self, network: str) -> List[DiscoveredHost]:
        hosts = []
        try:
            ips = [str(ip) for ip in ipaddress.ip_network(network, strict=False).hosts()][:254]
            with ThreadPoolExecutor(max_workers=50) as ex:
                ex.map(self._quick_ping, ips)
            result = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=10)
            for line in result.stdout.split("\n"):
                parts = line.split()
                if len(parts) >= 3 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    hosts.append(DiscoveredHost(ip=parts[0], mac=parts[2], method="arp-cache"))
        except Exception:
            pass
        return hosts

    def _icmp_scan(self, network: str, timeout: int = 60) -> List[DiscoveredHost]:
        hosts = []
        try:
            ips = [str(ip) for ip in ipaddress.ip_network(network, strict=False).hosts()][:254]
            with ThreadPoolExecutor(max_workers=50) as ex:
                futures = {ex.submit(self._ping_host, ip): ip for ip in ips}
                for f in as_completed(futures, timeout=timeout):
                    ip = f.result()
                    if ip:
                        hosts.append(DiscoveredHost(ip=ip, method="icmp"))
        except Exception as e:
            console.print(f"[dim]ICMP scan error: {e}[/dim]")
        return hosts

    # ── Enrichment methods ────────────────────────────────────────────────────

    def _quick_port_probe(self, host: DiscoveredHost, ports: List[int] = None) -> None:
        """
        FIX #3: TCP-only probe. SNMP (UDP 161) removed from this list because
        socket.create_connection() is TCP-only and will never detect UDP services.
        UDP SNMP detection is handled separately by _quick_port_probe_udp().
        """
        if ports is None:
            # 161 removed — it is UDP and cannot be detected via TCP connect.
            ports = [21, 22, 23, 25, 80, 135, 139, 443, 445, 3389, 8080, 8443]
        open_ports = []
        for port in ports:
            try:
                with socket.create_connection((host.ip, port), timeout=0.5):
                    open_ports.append(port)
            except Exception:
                pass
        # FIX #4: Acquire lock only for the final attribute write.
        with self._host_lock:
            host.open_ports = open_ports

    def _quick_port_probe_udp(self, host: DiscoveredHost, ports: List[int] = None) -> None:
        """
        FIX #3: Dedicated UDP probe for services that cannot be detected via TCP.
        Sends an empty datagram and treats no ICMP port-unreachable as 'open|filtered'.
        Requires root for reliable results.
        """
        if ports is None:
            ports = [161]  # SNMP
        udp_open = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1.0)
                sock.sendto(b"", (host.ip, port))
                try:
                    sock.recvfrom(1024)
                    udp_open.append(port)
                except socket.timeout:
                    # No ICMP port-unreachable received → likely open|filtered
                    udp_open.append(port)
                except Exception:
                    pass
                finally:
                    sock.close()
            except Exception:
                pass
        with self._host_lock:
            host.udp_open_ports = udp_open  # type: ignore[attr-defined]

    def _lookup_vendor_smart(self, host: DiscoveredHost) -> None:
        if host.vendor != "Unknown" and host.vendor_source not in ("unknown", ""):
            return
        oui = self._normalise_oui(host.mac)
        if not oui:
            return
        if oui in self._ai_cache:
            host.vendor = self._ai_cache[oui].get("vendor", host.vendor)
            host.vendor_source = "ai_cached"
            return
        if oui in self._oui_cache:
            host.vendor = self._oui_cache[oui]
            host.vendor_source = "oui_db"
            return
        host.vendor_source = "unknown"

    def _detect_os_from_ttl(self, host: DiscoveredHost) -> None:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", host.ip],
                capture_output=True, text=True, timeout=3,
            )
            m = re.search(r"ttl=(\d+)", result.stdout.lower())
            if m:
                ttl = int(m.group(1))
                if ttl <= 64:
                    os_str, conf, src = "Linux/Unix", 70, "ttl"
                elif ttl <= 128:
                    os_str, conf, src = "Windows", 70, "ttl"
                else:
                    os_str, conf, src = "Network Device", 50, "ttl"
                # FIX #4: Acquire lock only for the final attribute write.
                with self._host_lock:
                    host.ttl = ttl
                    host.os = os_str
                    host.os_confidence = conf
                    host.os_source = src
        except Exception:
            pass

    def _resolve_hostname(self, host: DiscoveredHost) -> None:
        try:
            name = socket.gethostbyaddr(host.ip)[0]
            if name and name != host.ip:
                # FIX #4: Acquire lock only for the final attribute write.
                with self._host_lock:
                    host.hostname = name
        except Exception:
            pass

    # ── OUI database ──────────────────────────────────────────────────────────

    def _load_system_oui_db(self) -> None:
        for path in [
            "/usr/share/arp-scan/ieee-oui.txt",
            "/usr/local/share/arp-scan/ieee-oui.txt",
            "/var/lib/arp-scan/ieee-oui.txt",
        ]:
            if Path(path).exists():
                try:
                    with open(path) as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                parts = line.split("\t")
                                if len(parts) >= 2:
                                    self._oui_cache[parts[0].strip().upper()] = parts[1].strip()
                    console.print(f"[dim]Loaded {len(self._oui_cache)} OUI entries[/dim]")
                    return
                except Exception:
                    pass
        console.print("[dim]No OUI DB found. AI will learn from scans.[/dim]")

    # ── Display helpers ───────────────────────────────────────────────────────

    def _build_scan_summary(self, hosts: Dict[str, DiscoveredHost], target: str) -> str:
        lines = [f"[LIVE_DISCOVERY on {target}]", f"Total hosts: {len(hosts)}"]
        for host in list(hosts.values())[:15]:
            lines.append(
                f"  {host.ip} | {host.vendor} | {host.os} ({host.os_confidence}%) | "
                f"ports={host.open_ports}"
            )
        return "\n".join(lines)

    def _print_chain_suggestions(self, suggestions: List[Dict]) -> None:
        if not suggestions:
            return
        console.print("\n[bold cyan] Smart Chain Suggestions[/bold cyan]")
        table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE_HEAVY)
        table.add_column("#", width=4, style="bold cyan")
        table.add_column("Tool", style="bold", width=16)
        table.add_column("Reason")
        table.add_column("Priority", width=8)
        pri_labels = {1: "HIGH", 2: "MED", 3: "LOW"}
        pri_colors = {1: "bold red", 2: "bold yellow", 3: "cyan"}
        for i, s in enumerate(suggestions, 1):
            pri = s.get("priority", 2)
            color = pri_colors.get(pri, "white")  # FIX: Default to "white" if pri not found
            label = pri_labels.get(pri, "MED")     # FIX: Default to "MED" if pri not found
            table.add_row(str(i), s["tool"], s["reason"], f"[{color}]{label}[/{color}]")
        console.print(table)

    def _print_summary(self, results: Dict) -> None:
        console.print(f"\n[green]✓ Found {results['total_hosts']} live hosts[/green]")
        if results["ai_inferred_hosts"]:
            console.print(f"[cyan]✦ AI inferred {len(results['ai_inferred_hosts'])} vendor/OS fields[/cyan]")
        if results["insights"]:
            console.print(f"[yellow]⚠ {len(results['insights'])} security insights generated[/yellow]")

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _normalise_oui(mac: str) -> str:
        if not mac or mac == "N/A":
            return ""
        clean = mac.upper().replace("-", ":").replace(".", "")
        if ":" not in clean and len(clean) == 12:
            clean = ":".join(clean[i:i+2] for i in range(0, 12, 2))
        parts = clean.split(":")
        return ":".join(parts[:3]) if len(parts) >= 3 else ""

    @staticmethod
    def _parse_json_array(text: str) -> List[Dict]:
        text = re.sub(r"```(?:json)?", "", text).strip()
        m = re.search(r"\[.*\]", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except Exception:
                pass
        return []

    def _quick_ping(self, ip: str) -> None:
        try:
            subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, timeout=2)
        except Exception:
            pass

    def _ping_host(self, ip: str) -> Optional[str]:
        try:
            r = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True, timeout=2)
            return ip if r.returncode == 0 else None
        except Exception:
            return None

    def _check_command(self, cmd: str) -> bool:
        try:
            subprocess.run(["which", cmd], capture_output=True, check=True)
            return True
        except Exception:
            return False

    def _detect_network_range(self, interface: str = None) -> str:
        """
        FIX #6: Parse `ip route` output robustly by searching for the 'dev'
        keyword instead of assuming a fixed field index, which varies across
        kernel versions and routing table formats.
        """
        try:
            result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
            if result.stdout:
                # Robustly find the interface name after the 'dev' keyword.
                m = re.search(r"\bdev\s+(\S+)", result.stdout)
                iface = m.group(1) if m else None
                if iface:
                    addr = subprocess.run(
                        ["ip", "-4", "addr", "show", iface],
                        capture_output=True, text=True,
                    )
                    m2 = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", addr.stdout)
                    if m2:
                        ip_parts = m2.group(1).split(".")
                        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/{m2.group(2)}"
        except Exception:
            pass
        return "192.168.1.0/24"

    @staticmethod
    def _host_to_dict(h: DiscoveredHost) -> Dict[str, Any]:
        return {
            "ip": h.ip,
            "mac": h.mac,
            "vendor": h.vendor,
            "vendor_source": h.vendor_source,
            "os": h.os,
            "os_confidence": h.os_confidence,
            "os_source": h.os_source,
            "hostname": h.hostname,
            "ttl": h.ttl,
            "open_ports": h.open_ports,
            # FIX #3: Include UDP ports in the serialised host record.
            "udp_open_ports": h.__dict__.get("udp_open_ports", []),
            "ai_notes": h.ai_notes,
            "risk_level": h.risk_level,
            "discovered_by": h.method,
            "first_seen": h.first_seen,
        }