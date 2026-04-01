"""
kernox.tools.hydra  –  Hydra credential brute-force wrapper.

Supports common services: ssh, ftp, http-post-form, http-get-form,
smb, rdp, telnet, mysql, mssql, pop3, smtp, imap, ldap.
"""

from __future__ import annotations

import re


class HydraTool:
    """Build Hydra commands and parse their output."""

    MODES = {
        "ssh":            "SSH brute force",
        "ftp":            "FTP brute force",
        "http-post-form": "HTTP login form (POST)",
        "http-get-form":  "HTTP login form (GET)",
        "smb":            "SMB/Windows brute force",
        "rdp":            "Remote Desktop Protocol",
        "telnet":         "Telnet brute force",
        "mysql":          "MySQL brute force",
        "mssql":          "MSSQL brute force",
        "pop3":           "POP3 email brute force",
        "smtp":           "SMTP brute force",
        "imap":           "IMAP brute force",
        "ldap2":          "LDAP brute force",
    }

    DEFAULT_WORDLISTS = {
        "users": "/usr/share/wordlists/metasploit/unix_users.txt",
        "passwords": "/usr/share/wordlists/rockyou.txt",
    }

    def build_command(
        self,
        target: str,
        mode: str = "ssh",
        userlist: str = "",
        passlist: str = "",
        username: str = "",
        password: str = "",
        port: int = 0,
        form_path: str = "/login",
        form_params: str = "username=^USER^&password=^PASS^:F=incorrect",
        threads: int = 16,
        flags: str = "",
    ) -> str:
        """
        Build the Hydra command.

        Parameters
        ----------
        target:       IP or hostname (no scheme).
        mode:         Service type (ssh, ftp, http-post-form, etc.).
        userlist:     Path to username wordlist file.
        passlist:     Path to password wordlist file.
        username:     Single username (overrides userlist).
        password:     Single password (overrides passlist).
        port:         Custom port (0 = use service default).
        form_path:    URL path for HTTP form modes.
        form_params:  Hydra form parameter string for http-*-form modes.
        threads:      Parallel task count (default 16).
        flags:        Extra raw flags appended to command.
        """
        # Strip scheme from target
        target = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]

        # User / password sources
        if username:
            user_part = f"-l {username}"
        else:
            wl = userlist or self.DEFAULT_WORDLISTS["users"]
            user_part = f"-L {wl}"

        if password:
            pass_part = f"-p {password}"
        else:
            wl = passlist or self.DEFAULT_WORDLISTS["passwords"]
            pass_part = f"-P {wl}"

        port_part = f"-s {port}" if port else ""
        thread_part = f"-t {threads}"

        # Service-specific syntax
        if mode in ("http-post-form", "http-get-form"):
            service = f"{mode} '{target}{form_path}:{form_params}'"
        else:
            service = f"{mode} {target}"

        # Use a temp output file for reliable parsing (avoids -V flood)
        import tempfile, os as _os
        out_file = f"/tmp/kernox_hydra_{int(__import__('time').time())}.txt"

        parts = [
            "hydra",
            user_part,
            pass_part,
            port_part,
            thread_part,
            "-q",            # quiet — only print found credentials to stdout
            "-I",            # ignore existing restore file
            f"-o {out_file}",  # write results to file too (fallback parser)
            flags,
            service,
        ]
        return " ".join(p for p in parts if p)

    def parse(self, output: str) -> dict:
        """Parse Hydra stdout/stderr into a structured dict."""
        return _parse_hydra_output(output)


# ── Parser ────────────────────────────────────────────────────────────────────

def _parse_hydra_output(raw: str) -> dict:
    """
    Parse Hydra CLI output.

    Hydra prints cracked credentials as:
      [PORT][SERVICE] host: <host>   login: <user>   password: <pass>
    """
    result: dict = {
        "cracked": [],
        "attempts": 0,
        "raw": raw[:2000],
    }

    # Count attempts
    for line in raw.splitlines():
        # Credential found
        m = re.search(
            r"\[(?P<port>\d+)\]\[(?P<service>[^\]]+)\]\s+host:\s+(?P<host>\S+)"
            r"\s+login:\s+(?P<login>\S+)\s+password:\s+(?P<password>\S+)",
            line,
            re.IGNORECASE,
        )
        if m:
            result["cracked"].append({
                "host": m.group("host"),
                "port": m.group("port"),
                "service": m.group("service"),
                "username": m.group("login"),
                "password": m.group("password"),
            })
            continue

        # Attempt count line: 1 of 1 target successfully completed, 1 valid password found
        am = re.search(r"(\d+) of \d+ target", line)
        if am:
            result["attempts"] = int(am.group(1))

    result["total_cracked"] = len(result["cracked"])
    return result
