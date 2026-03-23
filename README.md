# Kernox – AI-Powered Security Automation CLI

> **For authorized penetration testing and ethical hacking only.**
> Never run Kernox against systems you do not have explicit permission to test.

---

## What is Kernox?

Kernox is a terminal-based penetration testing and reconnaissance assistant that
combines AI intelligence with classic Linux security tools.  It automates
enumeration, vulnerability discovery, and output analysis — all from a single CLI.

```
$ kernox
 ██╗  ██╗███████╗██████╗ ███╗   ██╗ ██████╗ ██╗  ██╗
 ██║ ██╔╝██╔════╝██╔══██╗████╗  ██║██╔═══██╗╚██╗██╔╝
 █████╔╝ █████╗  ██████╔╝██╔██╗ ██║██║   ██║ ╚███╔╝
 ...

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
| **Tools** | nmap, ffuf, gobuster, sqlmap |
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
- Optional tools installed and on `PATH`: `nmap`, `ffuf`, `gobuster`, `sqlmap`

---

## Installation

```bash
# Clone
git clone https://github.com/youruser/kernox.git
cd kernox

# Install (editable)
pip install -e .

# Run
kernox
```

### Kali Linux one-liner (tools already installed)

```bash
pip install -e . && kernox
```

---

## Usage

### First Run
On first launch Kernox detects no existing configuration and runs the interactive
setup wizard.  You choose an AI backend and optionally set scope restrictions.

### Main REPL Commands

| Command | Description |
|---|---|
| `Scan target <ip/url>` | AI-orchestrated full scan |
| `Fuzz <url> with <wordlist>` | Directory fuzzing via ffuf |
| `Test SQL injection on <url>` | Run sqlmap |
| `state` | Show current session state |
| `history` | Show last 20 AI messages |
| `clear` | Reset session state |
| `help` | Show help panel |
| `exit` / `quit` | Quit Kernox |

### Flags

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
├── tools/               Command builders (nmap, ffuf, gobuster, sqlmap)
├── parsers/             Structured output parsers
├── engine/              Session state + state updater
├── guards/              Safety rules & scope enforcement
├── security/            Encrypted key storage
├── config/              SQLite config store
└── utils/               Secure input helpers
```

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

## Configuration Storage

All config is stored in `~/.kernox/`:

| File | Contents |
|---|---|
| `config.db` | AI backend choice, URLs, models, safety settings |
| `keys.db` | Fernet-encrypted API keys |

---

## License

MIT – see [LICENSE](LICENSE).

---

*Kernox is a tool for professionals.  Use responsibly and only on systems you own or have written permission to test.*
