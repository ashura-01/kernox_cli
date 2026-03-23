"""
kernox.parsers.privesc_parser  –  Parse privesc enumeration output.

Extracts juicy points, assigns severity, and returns structured findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# GTFOBins known exploitable binaries
GTFOBINS = {
    "nmap","vim","vi","nano","find","bash","sh","more","less","man","awk",
    "gawk","python","python3","ruby","perl","lua","php","node","tar","cp",
    "mv","cat","tee","env","time","watch","dd","xxd","base64","openssl",
    "curl","wget","git","zip","unzip","7z","scp","rsync","nc","netcat",
    "ncat","socat","screen","tmux","mysql","sqlite3","psql","ftp","tftp",
    "aria2c","apt","apt-get","pip","pip3","gem","npm","docker","lxc",
    "runc","podman","journalctl","systemctl","pkexec","xargs","tclsh",
    "expect","gcc","cc","make","busybox","ash","dash","zsh","ksh",
    "taskset","ionice","nice","dbus-send","gdbus",
}

# Kernel version to CVE mapping (common ones)
KERNEL_CVES = {
    "4.4":  [("CVE-2017-16995", "eBPF privilege escalation", "critical")],
    "4.8":  [("CVE-2017-16995", "eBPF privilege escalation", "critical")],
    "3.13": [("CVE-2014-3153", "futex privilege escalation (towTruck)", "critical")],
    "2.6":  [("CVE-2010-3301", "Linux x86 ptrace", "critical"),
             ("CVE-2012-0056", "mem write privilege escalation", "high")],
    "4.13": [("CVE-2017-1000405", "Huge Dirty Cow", "high")],
    "3.9":  [("CVE-2013-2094", "perf_swevent_init", "critical")],
    "5.8":  [("CVE-2021-3493", "overlayfs privilege escalation", "high")],
    "5.11": [("CVE-2021-3493", "overlayfs privilege escalation", "high")],
    "5.13": [("CVE-2021-4034", "Polkit pkexec (PwnKit)", "critical")],
}

@dataclass
class Finding:
    title: str
    severity: str           # critical / high / medium / low / info
    category: str           # suid / sudo / cron / kernel / nfs / caps / writable / path / file
    detail: str
    juicy_path: str = ""    # File/binary path highlighted
    exploit_hint: str = ""  # GTFOBins or CVE hint


class PrivescParser:

    # Section markers from our script
    SECTION_RE  = re.compile(r"^=== (.+) ===$", re.MULTILINE)
    SUID_RE     = re.compile(r"^(/[^\s]+)$", re.MULTILINE)
    CAPS_RE     = re.compile(r"^(/[^\s]+)\s+=\s+(.+)$", re.MULTILINE)
    SUDO_RE     = re.compile(r"\(ALL.*?\)\s+(?:NOPASSWD:\s+)?(.+)", re.IGNORECASE)
    SUDO_ALL_RE = re.compile(r"\(ALL\s*:\s*ALL\)", re.IGNORECASE)
    KERNEL_RE   = re.compile(r"Linux\s+\S+\s+(\d+\.\d+)[\.\d]*")
    CRON_CMD_RE = re.compile(r"[\d\*]+\s+[\d\*]+\s+[\d\*]+\s+[\d\*]+\s+[\d\*]+\s+(\S+.+)")
    NFS_RE      = re.compile(r"(/\S+)\s+.*(no_root_squash)", re.IGNORECASE)
    WRITABLE_RE = re.compile(r"^(/[^\s]+)$", re.MULTILINE)
    SHADOW_RE   = re.compile(r"(-r.+/etc/shadow)")

    def parse(self, raw: str) -> dict:
        findings: list[Finding] = []
        sections = self._split_sections(raw)

        # ── Kernel ────────────────────────────────────────────────────────────
        kernel_section = sections.get("KERNEL", "")
        km = self.KERNEL_RE.search(kernel_section)
        kernel_version = ""
        if km:
            kernel_version = km.group(1)
            findings += self._check_kernel(kernel_version, kernel_section)

        # ── Current user / sudo ───────────────────────────────────────────────
        user_section = sections.get("CURRENT USER", "")
        findings += self._check_sudo(user_section)

        # ── SUID ──────────────────────────────────────────────────────────────
        suid_section = sections.get("SUID BINARIES", "")
        findings += self._check_suid(suid_section)

        # ── SGID ──────────────────────────────────────────────────────────────
        sgid_section = sections.get("SGID BINARIES", "")
        findings += self._check_sgid(sgid_section)

        # ── Capabilities ─────────────────────────────────────────────────────
        caps_section = sections.get("CAPABILITIES", "")
        findings += self._check_capabilities(caps_section)

        # ── Writable passwd/shadow ────────────────────────────────────────────
        passwd_section = sections.get("WRITABLE PASSWD", "")
        findings += self._check_writable_passwd(passwd_section)

        # ── Cron jobs ─────────────────────────────────────────────────────────
        cron_section = sections.get("CRON JOBS", "") + sections.get("WRITABLE CRON SCRIPTS", "")
        findings += self._check_cron(cron_section)

        # ── NFS ───────────────────────────────────────────────────────────────
        nfs_section = sections.get("NFS", "")
        findings += self._check_nfs(nfs_section)

        # ── PATH hijacking ────────────────────────────────────────────────────
        path_section = sections.get("PATH", "")
        findings += self._check_path(path_section)

        # ── Sensitive files ───────────────────────────────────────────────────
        files_section = sections.get("SENSITIVE FILES", "")
        findings += self._check_sensitive_files(files_section)

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: sev_order.get(f.severity, 5))

        # Build juicy points list
        juicy_points = [
            {
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "path": f.juicy_path,
                "detail": f.detail,
                "exploit_hint": f.exploit_hint,
            }
            for f in findings
            if f.severity in ("critical", "high") or f.juicy_path
        ]

        return {
            "findings": [vars(f) for f in findings],
            "juicy_points": juicy_points,
            "kernel_version": kernel_version,
            "total": len(findings),
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high":     sum(1 for f in findings if f.severity == "high"),
            "medium":   sum(1 for f in findings if f.severity == "medium"),
            "low":      sum(1 for f in findings if f.severity == "low"),
            "raw": raw,
        }

    # ── Section splitter ──────────────────────────────────────────────────────

    def _split_sections(self, raw: str) -> dict[str, str]:
        sections: dict[str, str] = {}
        parts = self.SECTION_RE.split(raw)
        i = 1
        while i < len(parts) - 1:
            name    = parts[i].strip()
            content = parts[i + 1] if i + 1 < len(parts) else ""
            sections[name] = content
            i += 2
        return sections

    # ── Check methods ─────────────────────────────────────────────────────────

    def _check_kernel(self, version: str, section: str) -> list[Finding]:
        findings = []
        major_minor = ".".join(version.split(".")[:2])
        for kernel_ver, cves in KERNEL_CVES.items():
            if major_minor == kernel_ver:
                for cve, desc, sev in cves:
                    findings.append(Finding(
                        title=f"Kernel {version} — {cve}",
                        severity=sev,
                        category="kernel",
                        detail=f"{desc} (kernel {version})",
                        juicy_path=f"/proc/version",
                        exploit_hint=f"Search: {cve} exploit github",
                    ))
        if not findings:
            findings.append(Finding(
                title=f"Kernel version: {version}",
                severity="info",
                category="kernel",
                detail=f"Check https://www.linuxkernelcves.com for version {version}",
                juicy_path="/proc/version",
            ))
        return findings

    def _check_sudo(self, section: str) -> list[Finding]:
        findings = []
        if self.SUDO_ALL_RE.search(section):
            findings.append(Finding(
                title="sudo ALL:ALL — Full root access",
                severity="critical",
                category="sudo",
                detail="User can run ALL commands as root with sudo",
                juicy_path="/etc/sudoers",
                exploit_hint="Run: sudo su  OR  sudo bash",
            ))
            return findings

        for m in self.SUDO_RE.finditer(section):
            cmd = m.group(1).strip()
            binary = cmd.split("/")[-1].split()[0].lower()
            sev = "critical" if binary in GTFOBINS else "high"
            hint = f"GTFOBins: https://gtfobins.github.io/gtfobins/{binary}/" if binary in GTFOBINS else ""
            findings.append(Finding(
                title=f"sudo allowed: {cmd}",
                severity=sev,
                category="sudo",
                detail=f"User can run '{cmd}' as root",
                juicy_path=cmd.split()[0] if cmd.startswith("/") else "",
                exploit_hint=hint,
            ))
        return findings

    def _check_suid(self, section: str) -> list[Finding]:
        findings = []
        for m in self.SUID_RE.finditer(section):
            path = m.group(1).strip()
            binary = path.split("/")[-1].lower()
            if binary in GTFOBINS:
                findings.append(Finding(
                    title=f"SUID binary (GTFOBins): {path}",
                    severity="critical",
                    category="suid",
                    detail=f"SUID bit set on {path} — known GTFOBins binary",
                    juicy_path=path,
                    exploit_hint=f"GTFOBins: https://gtfobins.github.io/gtfobins/{binary}/#suid",
                ))
            else:
                findings.append(Finding(
                    title=f"SUID binary: {path}",
                    severity="medium",
                    category="suid",
                    detail=f"SUID bit set — check if exploitable",
                    juicy_path=path,
                    exploit_hint="Run: strings + ltrace + strace to analyse",
                ))
        return findings

    def _check_sgid(self, section: str) -> list[Finding]:
        findings = []
        for m in self.SUID_RE.finditer(section):
            path = m.group(1).strip()
            binary = path.split("/")[-1].lower()
            if binary in GTFOBINS:
                findings.append(Finding(
                    title=f"SGID binary (GTFOBins): {path}",
                    severity="high",
                    category="sgid",
                    detail=f"SGID bit set on known GTFOBins binary",
                    juicy_path=path,
                    exploit_hint=f"GTFOBins: https://gtfobins.github.io/gtfobins/{binary}/",
                ))
        return findings

    def _check_capabilities(self, section: str) -> list[Finding]:
        findings = []
        dangerous_caps = {
            "cap_setuid": ("critical", "Can set UID to root"),
            "cap_setgid": ("high",     "Can set GID"),
            "cap_sys_admin": ("critical", "Equivalent to root"),
            "cap_net_raw":   ("medium",   "Raw network access"),
            "cap_dac_read_search": ("high", "Read any file"),
            "cap_dac_override":    ("high", "Override file permissions"),
            "cap_chown":     ("high",     "Change file ownership"),
            "cap_fowner":    ("high",     "Override file ownership"),
            "ep":            ("critical", "All capabilities (=ep)"),
        }
        for m in self.CAPS_RE.finditer(section):
            path = m.group(1)
            caps = m.group(2).lower()
            binary = path.split("/")[-1].lower()
            for cap, (sev, desc) in dangerous_caps.items():
                if cap in caps:
                    findings.append(Finding(
                        title=f"Dangerous capability: {binary} ({cap})",
                        severity=sev,
                        category="capabilities",
                        detail=f"{path} has {caps} — {desc}",
                        juicy_path=path,
                        exploit_hint=f"GTFOBins: https://gtfobins.github.io/gtfobins/{binary}/#capabilities",
                    ))
                    break
        return findings

    def _check_writable_passwd(self, section: str) -> list[Finding]:
        findings = []
        if "-rw-rw-rw" in section or "-rwxrwxrwx" in section:
            if "/etc/passwd" in section:
                findings.append(Finding(
                    title="WRITABLE /etc/passwd",
                    severity="critical",
                    category="writable",
                    detail="/etc/passwd is world-writable — add root user",
                    juicy_path="/etc/passwd",
                    exploit_hint="echo 'hacker::0:0:root:/root:/bin/bash' >> /etc/passwd",
                ))
            if "/etc/shadow" in section:
                findings.append(Finding(
                    title="WRITABLE /etc/shadow",
                    severity="critical",
                    category="writable",
                    detail="/etc/shadow is world-writable — overwrite root hash",
                    juicy_path="/etc/shadow",
                    exploit_hint="Generate hash: python3 -c \"import crypt; print(crypt.crypt('password'))\"",
                ))
        # Readable shadow
        if "-r--r--r--" not in section and "/etc/shadow" in section:
            if "r" in section.split("/etc/shadow")[0].split("\n")[-1][:10]:
                findings.append(Finding(
                    title="READABLE /etc/shadow",
                    severity="critical",
                    category="writable",
                    detail="/etc/shadow may be readable — extract hashes",
                    juicy_path="/etc/shadow",
                    exploit_hint="cat /etc/shadow | grep -v '\\*\\|!' | awk -F: '{print $2}'",
                ))
        return findings

    def _check_cron(self, section: str) -> list[Finding]:
        findings = []
        for m in self.CRON_CMD_RE.finditer(section):
            cmd = m.group(1).strip()
            # Check if the script being called is writable
            script_path = cmd.split()[0]
            if script_path.startswith("/"):
                findings.append(Finding(
                    title=f"Cron job: {cmd[:60]}",
                    severity="medium",
                    category="cron",
                    detail=f"Scheduled task running: {cmd}",
                    juicy_path=script_path,
                    exploit_hint=f"Check if {script_path} is writable: ls -la {script_path}",
                ))
        # World-writable cron scripts
        if "-rwxrwxrwx" in section or "-rw-rw-rw" in section:
            findings.append(Finding(
                title="Writable cron script detected",
                severity="critical",
                category="cron",
                detail="A cron script is world-writable — inject commands",
                juicy_path="/etc/cron*",
                exploit_hint="echo 'chmod +s /bin/bash' >> /path/to/script",
            ))
        return findings

    def _check_nfs(self, section: str) -> list[Finding]:
        findings = []
        for m in self.NFS_RE.finditer(section):
            path = m.group(1)
            findings.append(Finding(
                title=f"NFS no_root_squash: {path}",
                severity="critical",
                category="nfs",
                detail=f"NFS export {path} has no_root_squash — mount and create SUID binary",
                juicy_path="/etc/exports",
                exploit_hint=(
                    f"Mount: mount -t nfs target:{path} /mnt/nfs\n"
                    "Create SUID: cp /bin/bash /mnt/nfs/bash && chmod +s /mnt/nfs/bash\n"
                    "Execute: /mnt/nfs/bash -p"
                ),
            ))
        return findings

    def _check_path(self, section: str) -> list[Finding]:
        findings = []
        writable_in_path = []
        for line in section.splitlines():
            line = line.strip()
            if line.startswith("/") and "Permission denied" not in line:
                writable_in_path.append(line)

        if writable_in_path:
            findings.append(Finding(
                title=f"Writable directories in PATH ({len(writable_in_path)} found)",
                severity="high",
                category="path",
                detail=f"Writable dirs in PATH: {', '.join(writable_in_path[:5])}",
                juicy_path="\n".join(writable_in_path[:10]),
                exploit_hint=(
                    "Create malicious binary with same name as a command run by root:\n"
                    "echo '/bin/bash' > /writable/path/binary && chmod +x /writable/path/binary"
                ),
            ))
        return findings

    def _check_sensitive_files(self, section: str) -> list[Finding]:
        findings = []
        lines = [l.strip() for l in section.splitlines() if l.strip().startswith("/")]

        ssh_keys = [l for l in lines if "id_rsa" in l or "id_dsa" in l or ".pem" in l]
        histories = [l for l in lines if "history" in l]
        configs   = [l for l in lines if ".conf" in l or ".cfg" in l]

        if ssh_keys:
            findings.append(Finding(
                title=f"SSH private keys found ({len(ssh_keys)})",
                severity="critical",
                category="file",
                detail="SSH private key files discovered",
                juicy_path="\n".join(ssh_keys[:5]),
                exploit_hint="cat <key_path> → use with: ssh -i key user@host",
            ))
        if histories:
            findings.append(Finding(
                title=f"History files found ({len(histories)})",
                severity="medium",
                category="file",
                detail="Shell history files — may contain passwords",
                juicy_path="\n".join(histories[:5]),
                exploit_hint="cat ~/.bash_history | grep -i 'pass\\|key\\|secret\\|sudo'",
            ))
        if configs:
            findings.append(Finding(
                title=f"Config files with credentials ({len(configs)})",
                severity="medium",
                category="file",
                detail="Config files may contain passwords",
                juicy_path="\n".join(configs[:5]),
                exploit_hint="grep -i 'password\\|passwd\\|secret' <config_file>",
            ))
        return findings
