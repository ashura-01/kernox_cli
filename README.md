```markdown
# Kernox – AI-Powered Security Automation CLI

> [!WARNING]
> **For authorized penetration testing and ethical hacking only.**
> Never run Kernox against systems you do not have explicit permission to test.

---

## What is Kernox?

Kernox is a terminal-based penetration testing and reconnaissance assistant that combines AI intelligence with classic Linux security tools. It automates enumeration, vulnerability discovery, and output analysis — all from a single CLI.

```text
$ kernox
██ ▄█▀▓█████  ██▀███   ███▄    █  ▒█████  ▒██   ██▒
██▄█▒ ▓█   ▀ ▓██ ▒ ██▒ ██ ▀█    █ ▒██▒  ██▒▒▒ █ █ ▒░
▓███▄░ ▒███   ▓██ ░▄█ ▒▓██  ▀█ ██▒▒██░  ██▒░░  █   ░
▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄  ▓██▒  ▐▌██▒▒██   ██░ ░ █ █ ▒ 
▒██▒ █▄░▒████▒░██▓ ▒██▒▒██░   ▓██░░ ████▓▒░▒██▒ ▒██▒
           >>> K E R N O X <<<

Kernox > Scan target [http://example.com](http://example.com)

[Orchestrator] Planning 3 step(s):
  1. nmap     – Port and service enumeration
  2. ffuf     – Directory fuzzing
  3. sqlmap   – SQL injection test
```

---

## Features

| Feature | Detail |
|---|---|
| **AI Backends** | Ollama (local), Claude (Anthropic), OpenAI-compatible |
| **Tools** | nmap, ffuf, gobuster, sqlmap, nikto, enum4linux, wpscan, smbclient, dnsenum, curl, hashcat, whatweb, wafw00f, sslscan, onesixtyone, dnsrecon, nuclei, privesc |
| **Smart Parsing** | Structured extraction from raw tool output |
| **Session State** | Hosts, ports, paths, vulns tracked in memory |
| **Guard Rules** | Scope enforcement, blocked commands, dangerous flag detection |
| **Encrypted Keys** | Fernet-encrypted API keys in SQLite |
| **First-run Wizard** | Interactive setup on first launch |
| **Config Menu** | `kernox --config` to change settings later |

---

## Requirements

- Python $\ge$ 3.10
- **AI Backend:** Ollama (local), Anthropic API key, or OpenAI-compatible key
- **Path Tools:** Security tools (nmap, ffuf, etc.) must be installed and in your system `$PATH`.

---

## Installation

### Option 1: System Installation (Global)

```bash
git clone [https://github.com/youruser/kernox.git](https://github.com/youruser/kernox.git)
cd kernox
pip install -e .

# Run
kernox
```

### Option 2: Virtual Environment (Recommended)

```bash
git clone [https://github.com/youruser/kernox.git](https://github.com/youruser/kernox.git)
cd kernox

# Create and activate environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install and Run
pip install -e .
python -m kernox.cli
```

---

## Usage

### Commands

| Command | Description |
|---|---|
| `Scan target <ip/url>` | AI-orchestrated full scan |
| `Fuzz <url> with <wordlist>` | Directory fuzzing via ffuf |
| `tools` | List available security tools |
| `state` | Show current session discovery state |
| `history` | Show last 20 AI messages |
| `clear` | Reset session state |
| `exit` | Quit Kernox |

### CLI Flags

```bash
kernox --config   # Open the settings menu
kernox --reset    # Wipe all config and keys
kernox --version  # Print version
```

---

## Architecture

```text
kernox/
├── cli.py             Entry point & banner
├── core/
│   ├── orchestrator.py  Main REPL + AI-to-tool flow
│   ├── executor.py      Safe subprocess wrapper
│   └── config_menu.py   --config menu
├── ai/                Ollama, Claude, and OpenAI clients
├── tools/             Command builders (nmap, sqlmap, etc.)
├── parsers/           Structured output parsers
├── guards/            Safety rules & scope enforcement
├── security/          Encrypted key storage (Fernet)
└── config/            SQLite config store
```

---

## Troubleshooting

- **Module Not Found:** Ensure you are inside your virtual environment and ran `pip install -e .`.
- **Tool Not Found:** Verify the tool is installed on your OS (e.g., `which nmap`).
- **API Errors:** Run `kernox --config` to verify your keys and backend selection.

---

