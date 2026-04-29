"""Chat detection and handling — AI decides chat vs action."""

import re

_TARGET_RE = re.compile(
    r"(\d{1,3}\.){3}\d{1,3}|https?://|\b\w+\.(com|net|org|io|dev)\b",
    re.IGNORECASE,
)

# Command patterns - when user wants to RUN tools
COMMAND_PATTERNS = re.compile(
    r'^(run|execute|scan|enumerate|bruteforce|crack|exploit|attack|test|check)\s|'
    r'^(nmap|nikto|gobuster|ffuf|dirb|wfuzz|hydra|sqlmap|msfconsole|searchsploit|'
    r'enum4linux|smbclient|whois|dig|nslookup|wpscan|whatweb|theharvester|'
    r'aircrack|reaver|kismet|bettercap|arp-scan|netdiscover|masscan)\s',
    re.IGNORECASE
)

# Question patterns - when user wants to CHAT/ASK
QUESTION_PATTERNS = re.compile(
    r'^(what|how|why|can you|could you|would you|please|tell me|show me|'
    r'explain|help me|teach me|learn|is there|do you|know about|'
    r'give me an example|write a|give me|create a|generate a)\s',
    re.IGNORECASE
)


def is_chat(text: str) -> bool:
    """
    Detect if user wants to chat vs run a command.
    Returns True for chat, False for command execution.
    """
    t = text.lower().strip()

    # Has target IP/domain -> definitely a command
    if _TARGET_RE.search(t):
        return False

    # Starts with command verb or tool name -> command
    if COMMAND_PATTERNS.match(t):
        return False

    # Starts with question pattern -> chat
    if QUESTION_PATTERNS.match(t):
        return True

    # Ends with question mark -> chat
    if t.endswith('?'):
        return True

    # Single word or short commands (e.g., "nmap", "sqlmap")
    if len(t.split()) == 1 and len(t) < 20:
        return False

    # Check for command-like structure (verb + noun without question)
    words = t.split()
    if len(words) >= 2:
        # If first word is a verb and no question markers -> command
        action_verbs = ['scan', 'run', 'execute', 'test', 'check', 'enumerate', 'crack']
        if words[0] in action_verbs:
            return False

    # Default to command (safe assumption)
    return False


class ChatHandler:
    def __init__(self, ai_client, state, history):
        self._ai = ai_client
        self._state = state
        self._history = history

    def chat(self, question: str) -> str:
        state_context = self._build_state_context()

        system_prompt = (
            "You are Kernox, a penetration testing AI.\n\n"
            "The user asked a QUESTION or wants INFORMATION (not a command to run).\n\n"
            "RESPOND APPROPRIATELY:\n\n"
            "1. If they want a SCRIPT/PAYLOAD/CODE → provide it in markdown code blocks\n"
            "2. If they want an EXPLANATION → explain clearly and concisely\n"
            "3. If they want ADVICE → give practical, actionable advice\n"
            "4. If they want to LEARN about a tool → teach them how to use it\n\n"
            "DO NOT return JSON with steps.\n"
            "DO NOT assume they want to execute commands.\n\n"
            "CURRENT SESSION DATA:\n"
            f"{state_context}\n\n"
            "Be helpful, accurate, and security-focused."
        )

        response = self._ai.chat(
            messages=[{"role": "user", "content": question}],
            system=system_prompt,
            max_tokens=1500,
        )
        return response

    def _build_state_context(self) -> str:
        parts = []

        hosts = self._state.hosts
        if hosts:
            parts.append("=== HOSTS ===")
            for ip, host in hosts.items():
                hostname = f" ({host.hostname})" if host.hostname else ""
                parts.append(f"Host: {ip}{hostname}")
                if host.ports:
                    for p in host.ports[:20]:
                        service = p.get('service', '')
                        version = p.get('version', '')
                        port = p.get('port', '')
                        proto = p.get('proto', 'tcp')
                        parts.append(f"  Port {port}/{proto}: {service} {version}".strip())

        tool_results = self._state.tool_results
        if tool_results:
            parts.append("\n=== TOOL OUTPUT ===")
            for r in tool_results[-5:]:
                parts.append(f"\n[{r.tool}] target={r.target} exit={r.parsed.get('exit_code','?')}")
                if r.raw_output:
                    parts.append(r.raw_output[:2000])

        insights = self._state.ai_insights
        if insights:
            parts.append("\n=== VULNERABILITIES ===")
            for i in insights[-10:]:
                parts.append(f"[{i.severity.upper()}] {i.vulnerability} on {i.target}")

        vulns = self._state.vulns
        if vulns:
            for target, vuln_list in vulns.items():
                for v in vuln_list[-5:]:
                    parts.append(f"{target}: {v.get('name', v.get('title', 'Unknown'))}")

        if not parts:
            return "No session data yet."

        return "\n".join(parts)
