"""
kernox.utils.formatter  –  Rich-powered post-scan output formatters.

Each formatter takes a parsed dict from a parser and renders a beautiful
structured table/panel to the terminal.
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

# ── Risk colour mapping ───────────────────────────────────────────────────────
# Ports considered high-risk get red highlights
HIGH_RISK_PORTS = {
    21, 23, 25, 53, 69, 110, 111, 135, 137, 138, 139, 143,
    445, 512, 513, 514, 1099, 1524, 2049, 2121, 3306, 3389,
    4444, 5432, 5900, 6667, 8009, 8080, 8443, 8888,
}

RISKY_SERVICES = {
    "ftp", "telnet", "rsh", "rlogin", "rexec", "vnc",
    "mysql", "postgresql", "mssql", "bindshell", "irc",
}


def _port_color(port: int, service: str) -> str:
    if port in HIGH_RISK_PORTS or service.lower() in RISKY_SERVICES:
        return "bold red"
    return "bold green"


def _risk_label(port: int, service: str) -> str:
    if port in HIGH_RISK_PORTS or service.lower() in RISKY_SERVICES:
        return "[bold red]HIGH[/bold red]"
    return "[green]LOW[/green]"


# ── Nmap formatter ────────────────────────────────────────────────────────────

def format_nmap(parsed: dict) -> None:
    hosts = parsed.get("hosts", [])
    if not hosts:
        console.print("[yellow]No hosts found in nmap output.[/yellow]")
        return

    for host in hosts:
        ip = host.get("ip", "?")
        hostname = host.get("hostname", "")
        os_info = host.get("os", "Unknown")
        ports = host.get("ports", [])

        title = f"[bold cyan]Host: {ip}[/bold cyan]"
        if hostname:
            title += f"  [dim]({hostname})[/dim]"

        # Summary line
        open_ports = [p for p in ports if p.get("state") == "open"]
        high_risk = [p for p in open_ports if p["port"] in HIGH_RISK_PORTS]

        summary = Text()
        summary.append(f"  OS: ", style="dim")
        summary.append(f"{os_info}\n", style="cyan")
        summary.append(f"  Open ports: ", style="dim")
        summary.append(f"{len(open_ports)}", style="bold green")
        summary.append(f"  |  High-risk: ", style="dim")
        summary.append(f"{len(high_risk)}", style="bold red" if high_risk else "green")

        console.print(Panel(summary, title=title, border_style="cyan", box=box.ROUNDED))

        if not open_ports:
            console.print("[yellow]  No open ports found.[/yellow]\n")
            continue

        # Ports table
        table = Table(
            show_header=True,
            header_style="bold magenta",
            box=box.SIMPLE_HEAVY,
            border_style="dim",
            pad_edge=False,
        )
        table.add_column("PORT", style="bold", width=10)
        table.add_column("PROTO", width=7)
        table.add_column("STATE", width=8)
        table.add_column("SERVICE", width=14)
        table.add_column("VERSION", style="dim")
        table.add_column("RISK", width=8)

        for p in sorted(open_ports, key=lambda x: x["port"]):
            port_num = p["port"]
            service = p.get("service", "")
            color = _port_color(port_num, service)
            risk = _risk_label(port_num, service)

            table.add_row(
                f"[{color}]{port_num}[/{color}]",
                p.get("proto", ""),
                "[green]open[/green]",
                f"[{color}]{service}[/{color}]",
                p.get("version", ""),
                risk,
            )

        console.print(table)

        # High-risk callout box
        if high_risk:
            risky_names = ", ".join(
                f"{p['port']}/{p.get('service','?')}" for p in high_risk
            )
            console.print(
                Panel(
                    f"[bold red]⚠ High-risk services detected:[/bold red] {risky_names}\n"
                    "[dim]These services are commonly exploitable. Investigate further.[/dim]",
                    border_style="red",
                    box=box.ROUNDED,
                )
            )
        console.print()


# ── Nikto formatter ───────────────────────────────────────────────────────────

def format_nikto(parsed: dict) -> None:
    target = parsed.get("target", "?")
    server = parsed.get("server", "Unknown")
    findings = parsed.get("findings", [])
    osvdb = parsed.get("osvdb_refs", [])

    # Header panel
    header = Text()
    header.append("  Target: ", style="dim")
    header.append(f"{target}\n", style="cyan")
    header.append("  Server: ", style="dim")
    header.append(f"{server}\n", style="yellow")
    header.append("  Findings: ", style="dim")
    header.append(f"{len(findings)}", style="bold red" if findings else "green")
    if osvdb:
        header.append(f"  |  OSVDB refs: ", style="dim")
        header.append(str(len(osvdb)), style="bold red")

    console.print(Panel(header, title="[bold cyan]Nikto Scan Results[/bold cyan]",
                        border_style="cyan", box=box.ROUNDED))

    if not findings:
        console.print("[green]  No vulnerabilities found.[/green]\n")
        return

    table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.SIMPLE_HEAVY,
        border_style="dim",
        show_lines=True,
    )
    table.add_column("#", width=4, style="dim")
    table.add_column("Finding", style="white")

    for i, finding in enumerate(findings, 1):
        # Color findings that mention OSVDB or CVE as red
        style = "bold red" if ("OSVDB" in finding or "CVE" in finding) else "white"
        table.add_row(str(i), f"[{style}]{finding}[/{style}]")

    console.print(table)
    console.print()


# ── Enum4linux formatter ──────────────────────────────────────────────────────

def format_enum4linux(parsed: dict) -> None:
    users = parsed.get("users", [])
    shares = parsed.get("shares", [])
    groups = parsed.get("groups", [])
    os_info = parsed.get("os", "Unknown")
    domain = parsed.get("domain", "")
    workgroup = parsed.get("workgroup", "")
    pw_policy = parsed.get("password_policy", {})

    # Header
    header = Text()
    header.append("  OS: ", style="dim")
    header.append(f"{os_info}\n", style="cyan")
    if domain:
        header.append("  Domain: ", style="dim")
        header.append(f"{domain}\n", style="yellow")
    if workgroup:
        header.append("  Workgroup: ", style="dim")
        header.append(f"{workgroup}\n", style="yellow")
    header.append("  Users: ", style="dim")
    header.append(f"{len(users)}", style="bold green")
    header.append("  |  Shares: ", style="dim")
    header.append(f"{len(shares)}", style="bold yellow")
    header.append("  |  Groups: ", style="dim")
    header.append(f"{len(groups)}", style="bold cyan")

    console.print(Panel(header, title="[bold cyan]Enum4linux Results[/bold cyan]",
                        border_style="cyan", box=box.ROUNDED))

    # Users table
    if users:
        console.print("[bold magenta]── Users ──[/bold magenta]")
        utbl = Table(show_header=True, header_style="bold magenta",
                     box=box.SIMPLE_HEAVY, border_style="dim")
        utbl.add_column("Username", style="bold green")
        utbl.add_column("RID", style="dim")
        for u in users:
            utbl.add_row(u["username"], u["rid"])
        console.print(utbl)
        console.print()

    # Shares table
    if shares:
        console.print("[bold magenta]── Shares ──[/bold magenta]")
        stbl = Table(show_header=True, header_style="bold magenta",
                     box=box.SIMPLE_HEAVY, border_style="dim")
        stbl.add_column("Share", style="bold yellow")
        stbl.add_column("Type", style="dim")
        stbl.add_column("Comment")
        for s in shares:
            stbl.add_row(s["name"], s["type"], s.get("comment", ""))
        console.print(stbl)
        console.print()

    # Groups
    if groups:
        console.print("[bold magenta]── Groups ──[/bold magenta]")
        gtbl = Table(show_header=True, header_style="bold magenta",
                     box=box.SIMPLE_HEAVY, border_style="dim")
        gtbl.add_column("Group", style="bold cyan")
        gtbl.add_column("RID", style="dim")
        for g in groups:
            gtbl.add_row(g["group"], g["rid"])
        console.print(gtbl)
        console.print()

    # Password policy
    if pw_policy:
        console.print(
            Panel(
                f"[dim]Minimum password length:[/dim] [bold]{pw_policy.get('min_length', '?')}[/bold]",
                title="[bold]Password Policy[/bold]",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )


# ── ffuf formatter ────────────────────────────────────────────────────────────

def format_ffuf(parsed: dict) -> None:
    findings = parsed.get("findings", [])
    total = parsed.get("total", 0)

    console.print(Panel(
        f"[dim]Paths found:[/dim] [bold {'red' if total else 'green'}]{total}[/bold]",
        title="[bold cyan]ffuf Directory Fuzz[/bold cyan]",
        border_style="cyan", box=box.ROUNDED,
    ))

    if not findings:
        console.print("[green]  No paths found.[/green]\n")
        return

    table = Table(show_header=True, header_style="bold magenta",
                  box=box.SIMPLE_HEAVY, border_style="dim")
    table.add_column("PATH", style="bold green")
    table.add_column("STATUS", width=8)
    table.add_column("SIZE", width=10, style="dim")

    for f in findings:
        status = f.get("status", 0)
        color = "green" if status == 200 else "yellow" if status in (301, 302) else "red"
        table.add_row(
            f["path"],
            f"[{color}]{status}[/{color}]",
            str(f.get("size", "")),
        )
    console.print(table)
    console.print()


# ── sqlmap formatter ──────────────────────────────────────────────────────────

def format_sqlmap(parsed: dict) -> None:
    vulnerable = parsed.get("vulnerable", False)
    params = parsed.get("parameters", [])
    dbms = parsed.get("dbms", "")
    databases = parsed.get("databases", [])

    status_color = "bold red" if vulnerable else "bold green"
    status_text = "VULNERABLE ⚠" if vulnerable else "NOT VULNERABLE ✓"

    header = Text()
    header.append("  Status: ", style="dim")
    header.append(f"{status_text}\n", style=status_color)
    if dbms:
        header.append("  DBMS: ", style="dim")
        header.append(f"{dbms}\n", style="cyan")
    if params:
        header.append("  Injectable params: ", style="dim")
        header.append(", ".join(params), style="bold red")

    console.print(Panel(header, title="[bold cyan]SQLMap Results[/bold cyan]",
                        border_style="red" if vulnerable else "green",
                        box=box.ROUNDED))

    if databases:
        console.print("[bold magenta]── Databases Found ──[/bold magenta]")
        dtbl = Table(show_header=True, header_style="bold magenta",
                     box=box.SIMPLE_HEAVY, border_style="dim")
        dtbl.add_column("Database", style="bold red")
        for db in databases:
            dtbl.add_row(db)
        console.print(dtbl)
    console.print()


# ── gobuster formatter ────────────────────────────────────────────────────────

def format_gobuster(parsed: dict) -> None:
    paths = parsed.get("paths", [])

    console.print(Panel(
        f"[dim]Paths found:[/dim] [bold {'green' if paths else 'yellow'}]{len(paths)}[/bold]",
        title="[bold cyan]Gobuster Results[/bold cyan]",
        border_style="cyan", box=box.ROUNDED,
    ))

    if not paths:
        console.print("[yellow]  No paths found.[/yellow]\n")
        return

    table = Table(show_header=True, header_style="bold magenta",
                  box=box.SIMPLE_HEAVY, border_style="dim")
    table.add_column("PATH", style="bold green")

    for p in paths:
        table.add_row(p)
    console.print(table)
    console.print()


# ── Dispatcher ────────────────────────────────────────────────────────────────

FORMATTERS = {
    "nmap": format_nmap,
    "nikto": format_nikto,
    "enum4linux": format_enum4linux,
    "ffuf": format_ffuf,
    "sqlmap": format_sqlmap,
    "gobuster": format_gobuster,
}


def format_results(tool_name: str, parsed: dict) -> None:
    """Dispatch to the correct formatter for *tool_name*."""
    if tool_name == "privesc":
        from kernox.utils.privesc_formatter import format_privesc
        format_privesc(parsed)
        return
    formatter = FORMATTERS.get(tool_name)
    if formatter:
        formatter(parsed)
    else:
        # Fallback: just print the dict nicely
        import json
        console.print(Panel(
            json.dumps(parsed, indent=2, default=str),
            title=f"[cyan]{tool_name} Results[/cyan]",
            border_style="cyan",
        ))


def format_wpscan(parsed: dict) -> None:
    version = parsed.get("wp_version", "Unknown")
    vulns   = parsed.get("vulnerabilities", [])
    plugins = parsed.get("plugins", [])
    users   = parsed.get("users", [])
    creds   = parsed.get("credentials", [])

    header = Text()
    header.append("  WP Version: ", style="dim")
    header.append(f"{version}\n", style="cyan")
    header.append("  Vulnerabilities: ", style="dim")
    header.append(str(len(vulns)), style="bold red" if vulns else "green")
    header.append("  | Plugins: ", style="dim")
    header.append(str(len(plugins)), style="yellow")
    header.append("  | Users: ", style="dim")
    header.append(str(len(users)), style="bold cyan")

    console.print(Panel(header, title="[bold cyan]WPScan Results[/bold cyan]",
                        border_style="red" if vulns else "cyan", box=box.ROUNDED))

    if vulns:
        console.print("[bold magenta]── Vulnerabilities ──[/bold magenta]")
        for v in vulns:
            console.print(f"  [red]•[/red] {v}")
        console.print()

    if users:
        console.print("[bold magenta]── Users Found ──[/bold magenta]")
        for u in users:
            console.print(f"  [bold green]•[/bold green] {u}")
        console.print()

    if creds:
        console.print("[bold magenta]── Credentials Cracked ──[/bold magenta]")
        for c in creds:
            console.print(f"  [bold red]•[/bold red] {c['user']} : {c['pass']}")
        console.print()


def format_smbclient(parsed: dict) -> None:
    shares = parsed.get("shares", [])
    files  = parsed.get("files", [])
    console.print(Panel(
        f"[dim]Shares found:[/dim] [bold cyan]{len(shares)}[/bold cyan]  "
        f"[dim]Files:[/dim] [bold]{len(files)}[/bold]",
        title="[bold cyan]SMBClient Results[/bold cyan]",
        border_style="cyan", box=box.ROUNDED,
    ))
    if shares:
        for s in shares:
            console.print(f"  [green]•[/green] {s}")
    if files:
        console.print("\n[bold magenta]── Files ──[/bold magenta]")
        for f in files[:30]:
            console.print(f"  [dim]{f}[/dim]")
    console.print()


def format_dnsenum(parsed: dict) -> None:
    subs = parsed.get("subdomains", [])
    ns   = parsed.get("nameservers", [])
    mx   = parsed.get("mx_records", [])

    header = Text()
    header.append("  Subdomains: ", style="dim")
    header.append(str(len(subs)), style="bold green" if subs else "yellow")
    header.append("  | NS records: ", style="dim")
    header.append(str(len(ns)), style="cyan")
    header.append("  | MX records: ", style="dim")
    header.append(str(len(mx)), style="cyan")

    console.print(Panel(header, title="[bold cyan]DNS Enumeration[/bold cyan]",
                        border_style="cyan", box=box.ROUNDED))

    if subs:
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("Subdomain", style="bold green")
        table.add_column("IP", style="cyan")
        for s in subs[:50]:
            table.add_row(s["subdomain"], s["ip"])
        console.print(table)
    console.print()


def format_curl(parsed: dict) -> None:
    headers = parsed.get("headers", {})
    tech    = parsed.get("tech", [])

    console.print(Panel(
        "\n".join(tech) if tech else "[dim]No tech fingerprint found[/dim]",
        title="[bold cyan]HTTP Probe Results[/bold cyan]",
        border_style="cyan", box=box.ROUNDED,
    ))

    if headers:
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("Header", style="bold cyan", width=25)
        table.add_column("Value")
        interesting = ["Server","X-Powered-By","Content-Type","Location",
                       "Set-Cookie","X-Frame-Options","Strict-Transport-Security"]
        for h in interesting:
            if h in headers:
                table.add_row(h, headers[h])
        console.print(table)
    console.print()


def format_hashcat(parsed: dict) -> None:
    cracked   = parsed.get("cracked", [])
    status    = parsed.get("status", "")
    speed     = parsed.get("speed", "")
    progress  = parsed.get("progress", "")
    recovered = parsed.get("recovered", "")
    time_est  = parsed.get("time_estimated", "")
    hash_type = parsed.get("hash_type", "")

    header = Text()
    header.append("  Status: ", style="dim")
    header.append(f"{status}\n", style="bold cyan")
    if hash_type:
        header.append("  Hash type: ", style="dim")
        header.append(f"{hash_type}\n", style="yellow")
    if speed:
        header.append("  Speed: ", style="dim")
        header.append(f"{speed}\n", style="yellow")
    if progress:
        header.append("  Progress: ", style="dim")
        header.append(f"{progress}\n", style="dim")
    if recovered:
        header.append("  Recovered: ", style="dim")
        header.append(f"{recovered}\n", style="bold green")
    if time_est:
        header.append("  ETA: ", style="dim")
        header.append(f"{time_est}\n", style="cyan")
    header.append("  Cracked: ", style="dim")
    header.append(str(len(cracked)), style="bold green" if cracked else "bold red")

    console.print(Panel(header, title="[bold cyan]Hashcat Results[/bold cyan]",
                        border_style="green" if cracked else "red", box=box.ROUNDED))

    if cracked:
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("HASH", style="dim", max_width=45)
        table.add_column("PLAINTEXT", style="bold green")
        for c in cracked:
            table.add_row(c["hash"], c["plaintext"])
        console.print(table)
    console.print()


# Update FORMATTERS
FORMATTERS.update({
    "wpscan":    format_wpscan,
    "smbclient": format_smbclient,
    "dnsenum":   format_dnsenum,
    "curl":      format_curl,
    "hashcat":   format_hashcat,
})


def format_whatweb(parsed: dict) -> None:
    techs   = parsed.get("technologies", [])
    versions= parsed.get("versions", [])
    emails  = parsed.get("emails", [])
    
    # Merge technologies with versions
    tech_dict = {}
    for v in versions:
        tech_dict[v["tech"]] = v["version"]
    for tech in techs:
        if tech not in tech_dict:
            tech_dict[tech] = ""
    
    header = Text()
    header.append("  Technologies: ", style="dim")
    header.append(str(len(tech_dict)), style="bold cyan")
    if emails:
        header.append("  | Emails: ", style="dim")
        header.append(str(len(emails)), style="bold green")
    
    console.print(Panel(header, title="[bold cyan]WhatWeb Results[/bold cyan]",
                        border_style="cyan", box=box.ROUNDED))
    
    # Display ALL technologies (with and without versions)
    if tech_dict:
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("Technology", style="bold cyan")
        table.add_column("Version", style="yellow")
        
        for tech, version in sorted(tech_dict.items()):
            if version:
                table.add_row(tech, version)
            else:
                table.add_row(tech, "[dim]detected[/dim]")
        console.print(table)
    else:
        console.print("[yellow]  No technologies detected.[/yellow]")
    
    # Display emails
    if emails:
        console.print("\n[bold magenta]── Emails ──[/bold magenta]")
        for e in emails:
            console.print(f"  [green]•[/green] {e}")
    
    console.print()

def format_wafw00f(parsed: dict) -> None:
    detected = parsed.get("detected", False)
    waf_names= parsed.get("waf_names", [])
    color = "red" if detected else "green"
    status = f"[bold {color}]{'WAF DETECTED ⚠' if detected else 'No WAF detected ✓'}[/bold {color}]"
    content = status
    if waf_names:
        content += f"\n  WAF: [bold red]{', '.join(waf_names)}[/bold red]"
    console.print(Panel(content, title="[bold cyan]WAF Detection[/bold cyan]",
                        border_style=color, box=box.ROUNDED))
    console.print()

def format_sslscan(parsed: dict) -> None:
    issues       = parsed.get("issues", [])
    weak_protos  = parsed.get("weak_protocols", [])
    weak_ciphers = parsed.get("weak_ciphers", [])
    header = Text()
    header.append("  Certificate CN: ", style="dim")
    header.append(f"{parsed.get('cert_cn','?')}\n", style="cyan")
    header.append("  Expiry: ", style="dim")
    header.append(f"{parsed.get('cert_expiry','?')}\n", style="yellow")
    header.append("  Issues: ", style="dim")
    header.append(str(len(issues)), style="bold red" if issues else "green")
    console.print(Panel(header, title="[bold cyan]SSL/TLS Scan[/bold cyan]",
                        border_style="red" if issues else "green", box=box.ROUNDED))
    if issues:
        console.print("[bold magenta]── Issues ──[/bold magenta]")
        for i in issues:
            console.print(f"  [red]•[/red] {i}")
    if weak_protos:
        console.print(f"\n  [red]Weak protocols:[/red] {', '.join(weak_protos)}")
    console.print()

def format_onesixtyone(parsed: dict) -> None:
    communities = parsed.get("communities", [])
    console.print(Panel(
        f"[dim]Community strings found:[/dim] [bold {'red' if communities else 'green'}]{len(communities)}[/bold]",
        title="[bold cyan]SNMP Enumeration[/bold cyan]",
        border_style="red" if communities else "green", box=box.ROUNDED,
    ))
    if communities:
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("IP", style="cyan")
        table.add_column("Community", style="bold red")
        table.add_column("Info")
        for c in communities:
            table.add_row(c["ip"], c["community"], c["info"])
        console.print(table)
    console.print()

def format_dnsrecon(parsed: dict) -> None:
    subs   = parsed.get("subdomains", [])
    a_rec  = parsed.get("a_records", [])
    mx_rec = parsed.get("mx_records", [])
    ns_rec = parsed.get("ns_records", [])
    axfr   = parsed.get("zone_transfer_possible", False)
    header = Text()
    header.append("  Subdomains: ", style="dim")
    header.append(str(len(subs)), style="bold green" if subs else "yellow")
    header.append("  | A records: ", style="dim")
    header.append(str(len(a_rec)), style="cyan")
    header.append("  | MX: ", style="dim")
    header.append(str(len(mx_rec)), style="cyan")
    if axfr:
        header.append("\n  [bold red]⚠ ZONE TRANSFER POSSIBLE![/bold red]")
    console.print(Panel(header, title="[bold cyan]DNSRecon Results[/bold cyan]",
                        border_style="red" if axfr else "cyan", box=box.ROUNDED))
    if subs:
        table = Table(show_header=True, header_style="bold magenta",
                      box=box.SIMPLE_HEAVY, border_style="dim")
        table.add_column("Subdomain", style="bold green")
        table.add_column("IP", style="cyan")
        for s in subs[:30]:
            table.add_row(s["subdomain"], s["ip"])
        console.print(table)
    console.print()

FORMATTERS.update({
    "whatweb":      format_whatweb,
    "wafw00f":      format_wafw00f,
    "sslscan":      format_sslscan,
    "onesixtyone":  format_onesixtyone,
    "dnsrecon":     format_dnsrecon,
})


def format_nuclei(parsed: dict) -> None:
    from rich.text import Text
    total    = parsed.get("total", 0)
    critical = parsed.get("critical", 0)
    high     = parsed.get("high", 0)
    medium   = parsed.get("medium", 0)
    low      = parsed.get("low", 0)
    findings = parsed.get("findings", [])

    header = Text()
    header.append("  Total findings: ", style="dim")
    header.append(f"{total}\n", style="bold white")
    header.append("  🔴 Critical: ", style="dim")
    header.append(f"{critical}  ", style="bold red")
    header.append("🟡 High: ", style="dim")
    header.append(f"{high}  ", style="bold yellow")
    header.append("🔵 Medium: ", style="dim")
    header.append(f"{medium}  ", style="bold cyan")
    header.append("🟢 Low: ", style="dim")
    header.append(str(low), style="green")

    border = "red" if critical > 0 else "yellow" if high > 0 else "cyan"
    console.print(Panel(
        header,
        title="[bold red]⚡ Nuclei Vulnerability Scan[/bold red]",
        border_style=border,
        box=box.ROUNDED,
    ))

    if not findings:
        console.print("[green]  No vulnerabilities found.[/green]\n")
        return

    SEV_COLORS = {
        "critical": "bold red",
        "high":     "bold yellow",
        "medium":   "bold cyan",
        "low":      "green",
        "info":     "dim",
    }
    SEV_ICONS = {
        "critical": "🔴",
        "high":     "🟡",
        "medium":   "🔵",
        "low":      "🟢",
        "info":     "⚪",
    }

    table = Table(
        show_header=True, header_style="bold magenta",
        box=box.SIMPLE_HEAVY, border_style="dim",
        show_lines=True,
    )
    table.add_column("SEV",      width=10)
    table.add_column("Template", width=28, style="bold cyan")
    table.add_column("Type",     width=8,  style="dim")
    table.add_column("Matched URL")

    for f in findings[:50]:
        sev   = f.get("severity", "info")
        color = SEV_COLORS.get(sev, "white")
        icon  = SEV_ICONS.get(sev, "")
        cvss  = f.get("cvss_score", "")
        cves  = f.get("cve_id", [])
        name  = f.get("name", f.get("template", ""))[:26]
        cve_str = f" [{cves[0]}]" if cves else ""

        table.add_row(
            f"[{color}]{icon} {sev.upper()}[/{color}]",
            f"{name}{cve_str}",
            f.get("type", ""),
            f.get("matched", "")[:60],
        )

    console.print(table)

    # Show descriptions for critical/high
    critical_high = [f for f in findings if f.get("severity") in ("critical","high")]
    if critical_high:
        console.print("\n[bold red]── Critical/High Details ──[/bold red]")
        for f in critical_high[:10]:
            sev   = f.get("severity","")
            color = SEV_COLORS.get(sev, "white")
            console.print(f"\n  [{color}]{SEV_ICONS.get(sev,'')} {f.get('name','')}[/{color}]")
            if f.get("description"):
                console.print(f"  [dim]{f['description'][:150]}[/dim]")
            if f.get("matched"):
                console.print(f"  [cyan]URL: {f['matched']}[/cyan]")
            if f.get("cvss_score"):
                console.print(f"  [yellow]CVSS: {f['cvss_score']}[/yellow]")
            if f.get("reference"):
                refs = f["reference"]
                if refs:
                    console.print(f"  [dim]Ref: {refs[0][:80]}[/dim]")

    console.print()

FORMATTERS.update({
    "nuclei": format_nuclei,
})
