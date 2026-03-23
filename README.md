Here's a perfectly organized README.md with both installation methods and the correct CLI entry point:

```markdown
# Kernox – AI-Powered Security Automation CLI

> **For authorized penetration testing and ethical hacking only.**
> Never run Kernox against systems you do not have explicit permission to test.

---

## What is Kernox?

Kernox is a terminal-based penetration testing and reconnaissance assistant that
combines AI intelligence with classic Linux security tools. It automates
enumeration, vulnerability discovery, and output analysis — all from a single CLI.

```
$ kernox
██ ▄█▀▓█████  ██▀███   ███▄    █  ▒█████  ▒██   ██▒
██▄█▒ ▓█   ▀ ▓██ ▒ ██▒ ██ ▀█   █ ▒██▒  ██▒▒▒ █ █ ▒░
▓███▄░ ▒███   ▓██ ░▄█ ▒▓██  ▀█ ██▒▒██░  ██▒░░  █   ░
▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄  ▓██▒  ▐▌██▒▒██   ██░ ░ █ █ ▒ 
▒██▒ █▄░▒████▒░██▓ ▒██▒▒██░   ▓██░░ ████▓▒░▒██▒ ▒██▒
▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ▒▒ ░ ░▓ ░
░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░░ ░░   ░ ▒░  ░ ▒ ▒░ ░░   ░▒ ░
░ ░░ ░    ░     ░░   ░    ░   ░ ░ ░ ░ ░ ▒   ░    ░  
░  ░      ░  ░   ░              ░     ░ ░   ░    ░  
         >>> K E R N O X <<<

Kernox > Scan target http://example.com

[Orchestrator] Planning 3 step(s):
  1. nmap     – Port and service enumeration
  2. ffuf     – Directory fuzzing
  3. sqlmap   – SQL injection test
```

---

## Features

| Feature | Detail |
|---|---|
| **AI backends** | Ollama (local), Claude (Anthropic), OpenAI-compatible |
| **Tools** | nmap, ffuf, gobuster, sqlmap, nikto, enum4linux, wpscan, smbclient, dnsenum, curl, hashcat, whatweb, wafw00f, sslscan, onesixtyone, dnsrecon, nuclei, privesc |
| **Smart parsing** | Structured extraction from raw tool output |
| **Session state** | Hosts, ports, paths, vulns tracked in memory |
| **Guard rules** | Scope enforcement, blocked commands, dangerous flag detection |
| **Encrypted keys** | Fernet-encrypted API keys in SQLite |
| **First-run wizard** | Interactive setup on first launch |
| **Config menu** | `kernox --config` to change anything later |

---

## Requirements

- Python ≥ 3.10
- One of: [Ollama](https://ollama.com) running locally, an Anthropic API key, or an OpenAI-compatible API key
- Optional tools installed and on `PATH`: nmap, ffuf, gobuster, sqlmap, nikto, enum4linux, wpscan, smbclient, dnsenum, curl, hashcat, whatweb, wafw00f, sslscan, onesixtyone, dnsrecon, nuclei, privesc

---

## Installation

### Option 1: System Installation (Global)

```bash
# Clone the repository
git clone https://github.com/youruser/kernox.git
cd kernox

# Install globally
pip install -e .

# Run
kernox
```

### Option 2: Virtual Environment (Recommended)

Using a virtual environment keeps dependencies isolated and prevents conflicts:

```bash
# Clone the repository
git clone https://github.com/youruser/kernox.git
cd kernox

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in editable mode
pip install -e .

# Run Kernox
python -m kernox.cli
```

### Kali Linux Quick Install

Kali Linux already includes most security tools. Install Kernox with:

```bash
# Clone and install
git clone https://github.com/youruser/kernox.git
cd kernox
pip install -e .

# Create and enter virtual environment (optional)
python -m venv venv
source venv/bin/activate
pip install -e .

# Run
python -m kernox.cli
```

---

## Usage

### First Run
On first launch, Kernox detects no existing configuration and runs the interactive
setup wizard. You choose an AI backend and optionally set scope restrictions.

### Configuration Menu

Access the configuration menu at any time:

```bash
# Using the installed command
kernox --config

# Or using the module directly
python -m kernox.cli --config
```

### Main REPL Commands

| Command | Description |
|---|---|
| `Scan target <ip/url>` | AI-orchestrated full scan |
| `Fuzz <url> with <wordlist>` | Directory fuzzing via ffuf |
| `Test SQL injection on <url>` | Run sqlmap |
| `tools` | List available security tools |
| `state` | Show current session state |
| `history` | Show last 20 AI messages |
| `clear` | Reset session state |
| `help` | Show help panel |
| `exit` / `quit` | Quit Kernox |

### Command Examples

```bash
# Start Kernox
kernox

# Or with virtual environment
python -m kernox.cli

# Within Kernox REPL
Kernox > Scan target 192.168.1.100
Kernox > Fuzz http://example.com/FUZZ with /usr/share/wordlists/dirb/common.txt
Kernox > Test SQL injection on http://example.com/page?id=1
Kernox > state
Kernox > tools
```

### Available Flags

```
kernox --config   # Open the settings menu
kernox --reset    # Wipe all config and keys
kernox --version  # Print version
```

---

## Architecture

```
kernox/
├── cli.py              Entry point & banner
├── core/
│   ├── orchestrator.py  Main REPL + AI-to-tool flow
│   ├── executor.py      Safe subprocess wrapper
│   ├── first_run*.py    First-run detection & wizard
│   └── config_menu.py   --config menu
├── ai/
│   ├── base.py          AI interface (ABC)
│   ├── ollama.py        Ollama client
│   ├── api.py           Claude / OpenAI clients
│   └── factory.py       Build client from config
├── tools/               Command builders (nmap, ffuf, gobuster, sqlmap, etc.)
├── parsers/             Structured output parsers
├── engine/              Session state + state updater
├── guards/              Safety rules & scope enforcement
├── security/            Encrypted key storage
├── config/              SQLite config store
└── utils/               Secure input helpers
```

---

## Available Tools

Kernox integrates with the following security tools:

| Tool | Purpose | Modes |
|------|---------|-------|
| nmap | Port scanning + NSE scripts | quick/service/aggressive/vuln/full/stealth/udp/script |
| ffuf | Web fuzzing | dir/vhost/param/post |
| gobuster | Directory/DNS/VHost busting | dir/dns/vhost/s3 |
| nikto | Web vulnerability scan | full/tuned/auth/sqli/ssl/quick |
| sqlmap | SQL injection testing | auto |
| enum4linux | SMB enumeration | auto -a |
| wpscan | WordPress scanning | passive/full/users/brute |
| smbclient | SMB share access | list/anon/connect/download |
| dnsenum | DNS enumeration | basic/full/zone/reverse |
| curl | HTTP probing | headers/methods/robots/tech |
| hashcat | Password cracking | auto GPU/CPU detect |
| whatweb | Web tech fingerprinting | aggressive/verbose/quiet |
| wafw00f | WAF detection | auto |
| sslscan | SSL/TLS vulnerability analysis | auto |
| onesixtyone | SNMP community string enum | auto |
| dnsrecon | Advanced DNS recon | std/brt/axfr/srv/full |
| nuclei | Template-based vuln scanner | quick/full/cves/exposures/logins |
| privesc | Linux privilege escalation enum | ssh/quick/full |

---

## Configuration Storage

All config is stored in `~/.kernox/`:

| File | Contents |
|---|---|
| `config.db` | AI backend choice, URLs, models, safety settings |
| `keys.db` | Fernet-encrypted API keys |

---

## Extending Kernox

### Add a new tool

1. Create `kernox/tools/mytool.py` with a class that implements `build_command(**kwargs) -> str` and `parse(output: str) -> dict`.
2. Create `kernox/parsers/mytool_parser.py`.
3. Register it in `kernox/core/orchestrator.py` under `self._tools`.
4. Mention the tool name in `SYSTEM_PROMPT` so the AI knows to use it.

### Add a new AI backend

1. Create `kernox/ai/mybackend.py` subclassing `BaseAIClient`.
2. Add a branch in `kernox/ai/factory.py`.
3. Add setup questions in `first_run_setup.py` and `config_menu.py`.

---

## Troubleshooting

### Module not found errors
Make sure you're in the virtual environment and have installed with `pip install -e .`:
```bash
source venv/bin/activate  # Activate virtual environment
pip list | grep kernox     # Verify installation
```

### Tools not found
Ensure security tools are installed and in PATH:
```bash
which nmap ffuf gobuster sqlmap  # Check tool locations
```

### API key issues
Run the config menu to update keys:
```bash
kernox --config
# or
python -m kernox.cli --config
```

---

## License

MIT – see [LICENSE](LICENSE).

---

*Kernox is a tool for professionals. Use responsibly and only on systems you own or have written permission to test.*
```

This README now:
1. Includes both global and virtual environment installation methods
2. Shows the correct CLI entry point (`python -m kernox.cli`) for venv usage
3. Maintains all the original content and structure
4. Adds proper formatting for the tools list
5. Includes troubleshooting section for common issues
6. Keeps the professional warning and ethical usage guidelines
