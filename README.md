```markdown
# Kernox – AI-Powered Offensive Security Agent

> [!WARNING]
> **For authorized penetration testing and ethical hacking only.**
> Never run Kernox against systems you do not have explicit permission to test.

---

## What is Kernox?

Kernox is an autonomous AI penetration testing agent that lives in your terminal. It combines AI planning with Kali Linux security tools to automate reconnaissance, enumeration, exploitation, and post-exploitation.

**Kernox plans, you confirm, it executes.**

```text
$ kernox

kernox⮞⮞ scan 192.168.1.0/24

┌─────────────────────────────────────────────────────────────┐
│ Execution Plan                                               │
├───┬────────────────────────────────────────────────┬─────────┤
│ # │ Command                                        │ Reason  │
├───┼────────────────────────────────────────────────┼─────────┤
│ 1 │ nmap -sn 192.168.1.0/24                       │ Host discovery │
│ 2 │ nmap -sV -p- 192.168.1.1                      │ Port scan │
│ 3 │ whatweb http://192.168.1.1                    │ Web enum │
└───┴────────────────────────────────────────────────┴─────────┘

Execute? [y/n]: y
```

---

## Features

| Feature | Description |
|---------|-------------|
| **AI Planning** | LLM generates execution plans from natural language |
| **Any Kali Tool** | Run any tool in your PATH — no hardcoded list |
| **4 Intensity Modes** | STEALTH (1) / NORMAL (2) / AGGRESSIVE (3) / FULL (4) |
| **AI Analysis** | Automatic vulnerability extraction from tool output |
| **Smart Chaining** | AI suggests next steps based on findings |
| **Session State** | Tracks hosts, ports, services, credentials, vulns |
| **CVE Enrichment** | Automatic NVD lookup for vulnerabilities |
| **Exploit Scoring** | CVSS-based risk scoring |
| **Attack Logging** | Timeline of all executed commands |
| **Payload Builder** | Interactive msfvenom payload generator |
| **PDF Reports** | Export findings to professional reports |
| **Encrypted Keys** | Fernet-encrypted API key storage |
| **Scope Enforcement** | Prevent scanning outside authorized targets |

---

## Requirements

- **Python:** ≥ 3.10
- **AI Backend:** Ollama (local), Anthropic Claude, or OpenAI-compatible API
- **Kali Linux** (recommended) or any system with security tools in `$PATH`

---

## Installation

### Option 1: Quick Install (Kali Linux)

```bash
git clone https://github.com/youruser/kernox.git
cd kernox
pip install -e .
kernox
```

### Option 2: Virtual Environment (Recommended)

```bash
git clone https://github.com/youruser/kernox.git
cd kernox
python -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate
pip install -e .
python -m kernox.cli
```

### First Run

On first launch, Kernox will:
1. Prompt for AI backend (Ollama/Claude/OpenAI)
2. Request API keys (if using Claude/OpenAI)
3. Save encrypted credentials to local database

---

## Usage

### Built-in Commands

| Command | Description |
|---------|-------------|
| `help` | Show help menu |
| `mode` | Change intensity (1-4) |
| `state` | Show current session state |
| `score` | Show CVSS risk summary |
| `log` | Show attack timeline |
| `cve <query>` | Search NVD for vulnerabilities |
| `payload` | Interactive msfvenom payload builder |
| `report` | Export findings to PDF |
| `save` | Save session to disk |
| `load` | Restore saved session |
| `sessions` | List saved sessions |
| `clear` | Reset session state |
| `raw on/off` | Toggle raw ANSI output |
| `auto [target]` | Autonomous chain (up to 5 steps) |
| `exit` / `quit` | Exit Kernox |

### Natural Language Examples

```bash
# Reconnaissance
kernox⮞⮞ scan 192.168.1.0/24
kernox⮞⮞ enumerate web server at example.com
kernox⮞⮞ find open ports on 10.0.0.1

# Vulnerability Discovery
kernox⮞⮞ check for SQL injection on http://test.com/page?id=1
kernox⮞⮞ scan for Apache vulnerabilities

# Exploitation
kernox⮞⮞ exploit vsftpd on 192.168.1.10
kernox⮞⮞ generate reverse shell payload

# Intelligence
kernox⮞⮞ what CVEs affect Apache 2.4.6
kernox⮞⮞ searchsploit WordPress 5.0
```

### Intensity Modes

| Mode | # | Timeout | Description |
|------|---|---------|-------------|
| STEALTH | 1 | 600s | Slow, quiet — avoid IDS detection |
| NORMAL | 2 | 300s | Standard speed and noise level |
| AGGRESSIVE | 3 | 180s | Fast scans, full enumeration |
| FULL | 4 | 120s | Maximum speed, all techniques |

Modes auto-detect from keywords: "stealth", "normal", "aggressive", "full"

---

## Architecture

```
kernox/
├── cli.py                     # Entry point
├── core/
│   ├── orchestrator.py        # Main REPL + AI planning
│   ├── executor.py            # Safe subprocess wrapper
│   └── orchestrator_helpers/
│       ├── ai_analyzer.py     # AI output analysis
│       ├── command_executor.py # Command execution + chaining
│       ├── output_formatter.py # Rich console formatting
│       ├── reflection_engine.py # Autonomous chaining
│       ├── state_manager.py   # Session state management
│       ├── session_manager.py # Save/load sessions
│       ├── report_handler.py  # PDF report generation
│       └── feature_handler.py # CVE, payload, log features
├── ai/                        # AI backends (Ollama, Claude, OpenAI)
├── engine/                    # Session state + parsers
├── features/                  # CVE lookup, exploit scoring, logging
├── guards/                    # Shell sanitizer + scope enforcement
├── security/                  # Encrypted key storage
├── tools/                     # Tool integrations (mail_crawler, etc.)
├── utils/                     # Formatters, helpers, wordlists
└── config/                    # SQLite config store
```

---

## Supported Tools (Any in $PATH)

Kernox can run **any tool** in your system PATH. Commonly used:

| Category | Tools |
|----------|-------|
| **Recon** | nmap, masscan, rustscan, naabu |
| **Web** | ffuf, gobuster, dirb, wfuzz, nikto, whatweb, wpscan, droopescan |
| **Exploit** | sqlmap, nuclei, metasploit, searchsploit |
| **Enumeration** | enum4linux, smbclient, snmpwalk, dnsenum, dnsrecon, onesixtyone |
| **Cracking** | hashcat, john, hydra, medusa |
| **Post-Exploit** | msfvenom, impacket, bloodhound |
| **Custom** | Any shell command or script |

---

## Configuration

### CLI Options

```bash
kernox                    # Normal mode
kernox --config           # Open configuration menu
kernox --reset            # Wipe all config and keys
kernox --version          # Show version
```

### Config Menu Options

- Change AI backend (Ollama/Claude/OpenAI)
- Update API keys
- Set default intensity mode
- Configure scope restrictions

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `Module not found` | Run `pip install -e .` inside virtual environment |
| `Tool not found` | Install tool: `sudo apt install <tool>` |
| `API key errors` | Run `kernox --config` to verify keys |
| `Ollama connection refused` | Start Ollama: `ollama serve` |
| `Permission denied` | Run without sudo — Kernox adds sudo automatically |

---

## License

**For authorized security testing only.**

---

## Star History

If you find Kernox useful, consider starring the repository and contributing.

**Happy hacking — stay legal, stay ethical.**
```
