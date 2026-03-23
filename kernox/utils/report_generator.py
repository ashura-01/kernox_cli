"""
kernox.utils.report_generator – Professional PDF report generator.
Light theme for readability.
"""

from __future__ import annotations
import os
from datetime import datetime
from rich.console import Console

console = Console()

# Known vulnerability database for explanations
VULN_EXPLANATIONS = {
    "heartbleed": {
        "name": "Heartbleed (CVE-2014-0160)",
        "severity": "CRITICAL",
        "description": (
            "Heartbleed is a critical vulnerability in OpenSSL's TLS heartbeat extension. "
            "It allows attackers to read up to 64KB of server memory per request without authentication, "
            "potentially exposing private keys, passwords, session tokens, and sensitive user data."
        ),
        "impact": "Private key theft, credential exposure, session hijacking",
        "recommendation": "Upgrade OpenSSL to 1.0.1g or later. Revoke and reissue all SSL certificates.",
        "references": ["CVE-2014-0160", "https://heartbleed.com"],
    },
    "shellshock": {
        "name": "Shellshock (CVE-2014-6271)",
        "severity": "CRITICAL",
        "description": (
            "Shellshock is a critical vulnerability in Bash that allows remote code execution. "
            "Attackers can inject malicious commands via environment variables processed by Bash, "
            "commonly exploited through CGI scripts on web servers."
        ),
        "impact": "Remote code execution, full system compromise",
        "recommendation": "Update Bash to patched version. Disable CGI scripts if not needed.",
        "references": ["CVE-2014-6271", "CVE-2014-7169"],
    },
    "ms17-010": {
        "name": "EternalBlue (MS17-010)",
        "severity": "CRITICAL",
        "description": (
            "EternalBlue exploits a critical SMBv1 vulnerability in Windows. "
            "Used by WannaCry and NotPetya ransomware. Allows unauthenticated remote code execution "
            "via crafted SMB packets on port 445."
        ),
        "impact": "Remote code execution, lateral movement, ransomware deployment",
        "recommendation": "Apply MS17-010 patch. Disable SMBv1. Block port 445 externally.",
        "references": ["MS17-010", "CVE-2017-0144"],
    },
    "vsftpd-backdoor": {
        "name": "vsftpd 2.3.4 Backdoor",
        "severity": "CRITICAL",
        "description": (
            "vsftpd 2.3.4 contains a deliberately introduced backdoor. "
            "When a username containing ':)' is sent, a shell is opened on port 6200 "
            "giving full root access without authentication."
        ),
        "impact": "Unauthenticated root shell on port 6200",
        "recommendation": "Upgrade vsftpd immediately. Check port 6200 for active backdoor.",
        "references": ["CVE-2011-2523"],
    },
    "unrealircd-backdoor": {
        "name": "UnrealIRCd Backdoor (CVE-2010-2075)",
        "severity": "CRITICAL",
        "description": (
            "UnrealIRCd 3.2.8.1 contains a backdoor that allows remote code execution. "
            "Sending 'AB;' followed by a command triggers execution as the IRC daemon user."
        ),
        "impact": "Remote code execution as IRC daemon user",
        "recommendation": "Upgrade UnrealIRCd to 3.2.8.2 or later.",
        "references": ["CVE-2010-2075"],
    },
    "ssl-poodle": {
        "name": "POODLE (CVE-2014-3566)",
        "severity": "HIGH",
        "description": (
            "POODLE (Padding Oracle On Downgraded Legacy Encryption) affects SSLv3. "
            "Allows attackers to decrypt encrypted communications via a padding oracle attack, "
            "potentially exposing session cookies and sensitive data."
        ),
        "impact": "Session cookie theft, HTTPS decryption",
        "recommendation": "Disable SSLv3 completely. Use TLS 1.2 or higher only.",
        "references": ["CVE-2014-3566"],
    },
    "default-credentials": {
        "name": "Default Credentials",
        "severity": "HIGH",
        "description": (
            "The service is accessible using factory-default credentials. "
            "This is a common misconfiguration that allows unauthorized access."
        ),
        "impact": "Unauthorized access, potential full system compromise",
        "recommendation": "Change all default passwords immediately.",
        "references": [],
    },
}


def explain_vulnerability(finding: str) -> dict | None:
    """Match a finding string to a known vulnerability explanation."""
    finding_lower = finding.lower()
    for key, info in VULN_EXPLANATIONS.items():
        if key in finding_lower:
            return info
    # Check CVE patterns
    import re
    cve_match = re.search(r"CVE-\d{4}-\d+", finding, re.IGNORECASE)
    if cve_match:
        return {
            "name": cve_match.group(0).upper(),
            "severity": "HIGH",
            "description": f"Known vulnerability {cve_match.group(0)}. Check NVD for full details.",
            "impact": "Varies by CVE",
            "recommendation": "Apply vendor patch for this CVE.",
            "references": [f"https://nvd.nist.gov/vuln/detail/{cve_match.group(0)}"],
        }
    return None


def generate_pdf_report(
    target: str,
    results: list[dict],
    output_path: str = "",
    privesc_data: dict | None = None,
    ai_insights: list[dict] | None = None,
) -> str:
    """Generate a professional light-theme PDF pentest report."""

    if not output_path:
        reports_dir = os.path.expanduser("~/.kernox/reports")
        os.makedirs(reports_dir, exist_ok=True)
        output_path = os.path.join(
            reports_dir,
            f"kernox_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor, black, white
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable,
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        console.print("[red]reportlab not installed. Run: pip install reportlab --break-system-packages[/red]")
        return ""

    # ── Light theme colours ───────────────────────────────────────────────────
    C_WHITE     = HexColor("#FFFFFF")
    C_LIGHT     = HexColor("#F6F8FA")
    C_BORDER    = HexColor("#D0D7DE")
    C_TEXT      = HexColor("#24292F")
    C_MUTED     = HexColor("#57606A")
    C_ACCENT    = HexColor("#0969DA")
    C_RED       = HexColor("#CF222E")
    C_ORANGE    = HexColor("#BC4C00")
    C_YELLOW    = HexColor("#9A6700")
    C_GREEN     = HexColor("#1A7F37")
    C_RED_BG    = HexColor("#FFEBE9")
    C_ORANGE_BG = HexColor("#FFF1E5")
    C_YELLOW_BG = HexColor("#FFF8C5")
    C_GREEN_BG  = HexColor("#DAFBE1")
    C_HEADER_BG = HexColor("#0969DA")

    SEV_COLORS = {
        "critical": (C_RED,     C_RED_BG),
        "high":     (C_ORANGE,  C_ORANGE_BG),
        "medium":   (C_YELLOW,  C_YELLOW_BG),
        "low":      (C_GREEN,   C_GREEN_BG),
        "info":     (C_MUTED,   C_LIGHT),
    }

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    def S(name, **kw):
        from reportlab.lib.styles import ParagraphStyle
        base = getSampleStyleSheet()["Normal"]
        return ParagraphStyle(name, parent=base, **kw)

    title_s   = S("T",  fontSize=26, textColor=C_ACCENT,  fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=4)
    sub_s     = S("Su", fontSize=11, textColor=C_MUTED,   alignment=TA_CENTER, spaceAfter=4)
    h1_s      = S("H1", fontSize=15, textColor=C_ACCENT,  fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=5)
    h2_s      = S("H2", fontSize=11, textColor=C_TEXT,    fontName="Helvetica-Bold", spaceBefore=8,  spaceAfter=3)
    body_s    = S("B",  fontSize=9,  textColor=C_TEXT,    spaceAfter=3, leading=14)
    muted_s   = S("M",  fontSize=8,  textColor=C_MUTED,   spaceAfter=2, leading=12)
    code_s    = S("C",  fontSize=8,  textColor=C_ACCENT,  fontName="Courier",
                  backColor=C_LIGHT, spaceAfter=3, leading=12, leftIndent=8)
    warn_s    = S("W",  fontSize=9,  textColor=C_RED,     fontName="Helvetica-Bold", spaceAfter=3)
    orange_s  = S("O",  fontSize=9,  textColor=C_ORANGE,  fontName="Helvetica-Bold", spaceAfter=3)

    story = []

    # ── Cover ─────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 2*cm))
    story.append(Paragraph("KERNOX", title_s))
    story.append(Paragraph("Security Assessment Report", sub_s))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=C_ACCENT))
    story.append(Spacer(1, 0.5*cm))

    cover_data = [
        ["Target",    target],
        ["Date",      datetime.now().strftime("%B %d, %Y  %H:%M")],
        ["Tools Run", str(len(results))],
        ["Generated", "Kernox AI Security Tool"],
    ]
    ct = Table(cover_data, colWidths=[4*cm, 13*cm])
    ct.setStyle(TableStyle([
        ("FONTNAME",     (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 10),
        ("TEXTCOLOR",    (0,0), (-1,-1), C_TEXT),
        ("TEXTCOLOR",    (0,0), (0,-1),  C_ACCENT),
        ("ROWBACKGROUNDS",(0,0),(-1,-1), [C_LIGHT, C_WHITE]),
        ("GRID",         (0,0), (-1,-1), 0.5, C_BORDER),
        ("LEFTPADDING",  (0,0), (-1,-1), 10),
        ("TOPPADDING",   (0,0), (-1,-1), 7),
        ("BOTTOMPADDING",(0,0), (-1,-1), 7),
    ]))
    story.append(ct)
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(
        "AUTHORIZED TESTING ONLY. This report is confidential and for authorized security testing purposes only.",
        muted_s
    ))
    story.append(PageBreak())

    # ── Count findings ────────────────────────────────────────────────────────
    total_findings = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    all_vulns = []  # collect all vulns for explanation section

    for r in results:
        tool = r.get("tool","")
        parsed = r.get("parsed",{})
        if tool == "nmap":
            for host in parsed.get("hosts",[]):
                hr = [p for p in host.get("ports",[])
                      if p.get("port") in {21,23,25,111,139,445,512,513,514,1099,1524,3306,5432,5900,6667,8009}]
                total_findings["high"] += len(hr)
                total_findings["info"] += len(host.get("ports",[])) - len(hr)
        elif tool == "nikto":
            total_findings["medium"] += parsed.get("total",0)
            for f in parsed.get("findings",[]):
                exp = explain_vulnerability(f)
                if exp:
                    all_vulns.append(exp)
        elif tool == "sqlmap" and parsed.get("vulnerable"):
            total_findings["critical"] += 1
        elif tool == "privesc":
            for sev in ("critical","high","medium","low"):
                total_findings[sev] += parsed.get(sev,0)
        elif tool == "sslscan":
            for issue in parsed.get("issues",[]):
                exp = explain_vulnerability(issue)
                if exp:
                    all_vulns.append(exp)
            total_findings["medium"] += len(parsed.get("issues",[]))
        elif tool == "nuclei":
            for sev in ("critical","high","medium","low"):
                total_findings[sev] += parsed.get(sev,0)
            for f in parsed.get("findings",[]):
                exp = explain_vulnerability(f.get("name","") + " " + f.get("template",""))
                if exp:
                    all_vulns.append(exp)
        elif tool == "wpscan":
            total_findings["high"] += parsed.get("total_vulns",0)

    # ── Executive Summary ─────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h1_s))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
    story.append(Spacer(1, 0.3*cm))

    risk = ("CRITICAL" if total_findings["critical"] > 0 else
            "HIGH"     if total_findings["high"] > 0 else
            "MEDIUM"   if total_findings["medium"] > 0 else "LOW")

    risk_colors = {"CRITICAL": C_RED, "HIGH": C_ORANGE, "MEDIUM": C_YELLOW, "LOW": C_GREEN}
    story.append(Paragraph(
        f"Overall Risk: <b><font color='#{risk_colors[risk].hexval()[2:]}'>{risk}</font></b>  |  "
        f"Target: <b>{target}</b>  |  "
        f"Tools: <b>{len(results)}</b>",
        body_s
    ))
    story.append(Spacer(1, 0.3*cm))

    sev_data = [["Severity","Count","Level"]]
    for label, key, color in [
        ("Critical","critical",C_RED),
        ("High","high",C_ORANGE),
        ("Medium","medium",C_YELLOW),
        ("Low","low",C_GREEN),
        ("Info","info",C_MUTED),
    ]:
        sev_data.append([label, str(total_findings[key]), label.upper()])

    st = Table(sev_data, colWidths=[5*cm,5*cm,7*cm])
    st.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(-1,0),  C_HEADER_BG),
        ("TEXTCOLOR",    (0,0),(-1,0),  C_WHITE),
        ("FONTNAME",     (0,0),(-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0,0),(-1,-1), 9),
        ("TEXTCOLOR",    (0,1),(-1,-1), C_TEXT),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_LIGHT, C_WHITE]),
        ("GRID",         (0,0),(-1,-1), 0.5, C_BORDER),
        ("LEFTPADDING",  (0,0),(-1,-1), 8),
        ("TOPPADDING",   (0,0),(-1,-1), 6),
        ("BOTTOMPADDING",(0,0),(-1,-1), 6),
    ]))
    story.append(st)
    story.append(PageBreak())

    # ── Vulnerability Explanations ────────────────────────────────────────────
    if all_vulns:
        story.append(Paragraph("Vulnerability Analysis", h1_s))
        story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
        story.append(Spacer(1, 0.3*cm))

        seen = set()
        for vuln in all_vulns:
            name = vuln.get("name","")
            if name in seen:
                continue
            seen.add(name)

            sev = vuln.get("severity","HIGH").lower()
            fg, bg = SEV_COLORS.get(sev, (C_TEXT, C_LIGHT))

            # Severity badge + name
            badge_data = [[f"{vuln['severity']}  {name}"]]
            bt = Table(badge_data, colWidths=[17*cm])
            bt.setStyle(TableStyle([
                ("BACKGROUND", (0,0),(-1,-1), bg),
                ("TEXTCOLOR",  (0,0),(-1,-1), fg),
                ("FONTNAME",   (0,0),(-1,-1), "Helvetica-Bold"),
                ("FONTSIZE",   (0,0),(-1,-1), 10),
                ("LEFTPADDING",(0,0),(-1,-1), 8),
                ("TOPPADDING", (0,0),(-1,-1), 6),
                ("BOTTOMPADDING",(0,0),(-1,-1),6),
                ("BOX",        (0,0),(-1,-1), 1, fg),
            ]))
            story.append(bt)
            story.append(Spacer(1, 0.1*cm))

            story.append(Paragraph("<b>Description:</b>", h2_s))
            story.append(Paragraph(vuln.get("description",""), body_s))

            story.append(Paragraph("<b>Impact:</b>", h2_s))
            story.append(Paragraph(vuln.get("impact",""), body_s))

            story.append(Paragraph("<b>Recommendation:</b>", h2_s))
            story.append(Paragraph(vuln.get("recommendation",""), body_s))

            if vuln.get("references"):
                story.append(Paragraph("<b>References:</b>", h2_s))
                for ref in vuln["references"]:
                    story.append(Paragraph(f"• {ref}", code_s))

            story.append(Spacer(1, 0.4*cm))
            story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
            story.append(Spacer(1, 0.2*cm))

        story.append(PageBreak())

    # ── AI-Generated Vulnerability Explanations ─────────────────────────────────────
    if ai_insights:
        story.append(Paragraph("AI Vulnerability Analysis", h1_s))
        story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
        story.append(Spacer(1, 0.3*cm))
        
        for insight in ai_insights[:10]:  # Limit to 10 vulnerabilities
            sev = insight.get("severity", "HIGH").lower()
            fg, bg = SEV_COLORS.get(sev, (C_TEXT, C_LIGHT))
            
            # Severity badge
            badge_data = [[f"{insight['severity'].upper()}  {insight['vulnerability']}"]]
            bt = Table(badge_data, colWidths=[17*cm])
            bt.setStyle(TableStyle([
                ("BACKGROUND", (0,0),(-1,-1), bg),
                ("TEXTCOLOR",  (0,0),(-1,-1), fg),
                ("FONTNAME",   (0,0),(-1,-1), "Helvetica-Bold"),
                ("FONTSIZE",   (0,0),(-1,-1), 10),
                ("LEFTPADDING",(0,0),(-1,-1), 8),
                ("TOPPADDING", (0,0),(-1,-1), 6),
                ("BOTTOMPADDING",(0,0),(-1,-1),6),
                ("BOX",        (0,0),(-1,-1), 1, fg),
            ]))
            story.append(bt)
            story.append(Spacer(1, 0.1*cm))
            
            explanation = insight.get("ai_explanation", {})
            story.append(Paragraph("<b>Description:</b>", h2_s))
            story.append(Paragraph(explanation.get("description", "No description available"), body_s))
            
            story.append(Paragraph("<b>Impact:</b>", h2_s))
            story.append(Paragraph(explanation.get("impact", "No impact information available"), body_s))
            
            story.append(Paragraph("<b>Recommendation:</b>", h2_s))
            story.append(Paragraph(explanation.get("recommendation", "No recommendation available"), body_s))
            
            if insight.get("tool"):
                story.append(Paragraph(f"<b>Discovered by:</b> {insight['tool']}", muted_s))
            if insight.get("target"):
                story.append(Paragraph(f"<b>Target:</b> {insight['target']}", muted_s))
            
            story.append(Spacer(1, 0.3*cm))
            story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
            story.append(Spacer(1, 0.2*cm))
        
        story.append(PageBreak())

    # ── Technical Details ─────────────────────────────────────────────────────
    story.append(Paragraph("Technical Findings", h1_s))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))

    for r in results:
        tool   = r.get("tool","")
        parsed = r.get("parsed",{})
        story.append(Spacer(1, 0.4*cm))

        # Tool header
        th = Table([[f"  {tool.upper()}"]], colWidths=[17*cm])
        th.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),C_HEADER_BG),
            ("TEXTCOLOR", (0,0),(-1,-1),C_WHITE),
            ("FONTNAME",  (0,0),(-1,-1),"Helvetica-Bold"),
            ("FONTSIZE",  (0,0),(-1,-1),10),
            ("TOPPADDING",(0,0),(-1,-1),6),
            ("BOTTOMPADDING",(0,0),(-1,-1),6),
        ]))
        story.append(th)
        story.append(Spacer(1, 0.2*cm))

        _write_tool_section_light(story, tool, parsed, body_s, code_s,
                                  muted_s, warn_s, orange_s, h2_s,
                                  C_ACCENT, C_RED, C_ORANGE, C_BORDER,
                                  C_LIGHT, C_WHITE, C_TEXT, C_HEADER_BG)

    # ── PrivEsc ───────────────────────────────────────────────────────────────
    if privesc_data:
        story.append(PageBreak())
        story.append(Paragraph("Privilege Escalation Findings", h1_s))
        story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
        _write_privesc_light(story, privesc_data, body_s, code_s,
                             warn_s, C_RED, C_ORANGE, C_BORDER,
                             C_LIGHT, C_WHITE, C_TEXT, C_ACCENT)

    # ── Notes ─────────────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Notes & Disclaimer", h1_s))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "This report was generated by Kernox for authorized security testing only. "
        "All findings should be verified manually. This information is confidential.",
        body_s
    ))

    doc.build(story)
    console.print(f"\n[bold green]✓ PDF report saved:[/bold green] [cyan]{output_path}[/cyan]")
    return output_path


def _write_tool_section_light(story, tool, parsed, body, code, muted,
                               warn, orange, h2, accent, red, ora,
                               border, light, white, text, header_bg):
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.units import cm

    if tool == "nmap":
        for host in parsed.get("hosts",[]):
            story.append(Paragraph(
                f"<b>Host:</b> {host.get('ip','')}  |  <b>OS:</b> {host.get('os','Unknown')}",
                body
            ))
            ports = [p for p in host.get("ports",[]) if p.get("state")=="open"]
            if ports:
                tdata = [["Port","Proto","Service","Version"]]
                for p in sorted(ports, key=lambda x:x["port"]):
                    tdata.append([str(p["port"]),p.get("proto",""),
                                  p.get("service",""),p.get("version","")[:40]])
                t = Table(tdata, colWidths=[2.5*cm,2.5*cm,3.5*cm,9*cm])
                t.setStyle(TableStyle([
                    ("BACKGROUND",(0,0),(-1,0),header_bg),
                    ("TEXTCOLOR",(0,0),(-1,0),white),
                    ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
                    ("FONTSIZE",(0,0),(-1,-1),8),
                    ("TEXTCOLOR",(0,1),(-1,-1),text),
                    ("ROWBACKGROUNDS",(0,1),(-1,-1),[light,white]),
                    ("GRID",(0,0),(-1,-1),0.3,border),
                    ("LEFTPADDING",(0,0),(-1,-1),4),
                    ("TOPPADDING",(0,0),(-1,-1),3),
                    ("BOTTOMPADDING",(0,0),(-1,-1),3),
                ]))
                story.append(t)

    elif tool == "nikto":
        story.append(Paragraph(
            f"<b>Server:</b> {parsed.get('server','')}  |  "
            f"<b>Findings:</b> {parsed.get('total',0)}",
            body
        ))
        for f in parsed.get("findings",[])[:30]:
            story.append(Paragraph(f"• {f[:120]}", body))

    elif tool == "sqlmap":
        vuln = parsed.get("vulnerable",False)
        story.append(Paragraph(
            f"<b>Status:</b> {'VULNERABLE' if vuln else 'Not Vulnerable'}  |  "
            f"<b>DBMS:</b> {parsed.get('dbms','')}",
            warn if vuln else body
        ))
        if parsed.get("parameters"):
            story.append(Paragraph(f"<b>Injectable:</b> {', '.join(parsed['parameters'])}", body))
        if parsed.get("databases"):
            story.append(Paragraph(f"<b>Databases:</b> {', '.join(parsed['databases'])}", body))

    elif tool == "sslscan":
        story.append(Paragraph(
            f"<b>CN:</b> {parsed.get('cert_cn','')}  |  "
            f"<b>Expiry:</b> {parsed.get('cert_expiry','')}",
            body
        ))
        for issue in parsed.get("issues",[]):
            story.append(Paragraph(f"• {issue}", warn))
        if parsed.get("weak_protocols"):
            story.append(Paragraph(
                f"<b>Weak protocols:</b> {', '.join(parsed['weak_protocols'])}",
                warn
            ))

    elif tool == "nuclei":
        story.append(Paragraph(
            f"<b>Critical:</b> {parsed.get('critical',0)}  |  "
            f"<b>High:</b> {parsed.get('high',0)}  |  "
            f"<b>Medium:</b> {parsed.get('medium',0)}",
            body
        ))
        for f in parsed.get("findings",[])[:25]:
            sev = f.get("severity","info").upper()
            story.append(Paragraph(
                f"[{sev}] {f.get('name','')} → {f.get('matched','')[:70]}",
                warn if sev in ("CRITICAL","HIGH") else body
            ))
            if f.get("description"):
                story.append(Paragraph(f.get("description","")[:150], muted))

    elif tool == "whatweb":
        techs = parsed.get("technologies", [])
        versions = parsed.get("versions", [])
        
        tech_dict = {}
        for v in versions:
            tech_name = v.get('tech', '')
            version = v.get('version', '')
            if tech_name:
                tech_dict[tech_name] = version
        for tech in techs:
            if tech not in tech_dict:
                tech_dict[tech] = ''
        
        if tech_dict:
            story.append(Paragraph("<b>Technologies Detected:</b>", body))
            for tech, version in sorted(tech_dict.items()):
                if version:
                    story.append(Paragraph(f"• {tech} {version}", body))
                else:
                    story.append(Paragraph(f"• {tech}", body))

    elif tool == "wafw00f":
        story.append(Paragraph(
            f"WAF {'DETECTED: ' + ', '.join(parsed.get('waf_names',[])) if parsed.get('detected') else 'Not detected'}",
            warn if parsed.get("detected") else body
        ))

    elif tool == "wpscan":
        story.append(Paragraph(
            f"<b>WP Version:</b> {parsed.get('wp_version','')}  |  "
            f"<b>Vulnerabilities:</b> {parsed.get('total_vulns',0)}",
            body
        ))
        for v in parsed.get("vulnerabilities",[])[:20]:
            story.append(Paragraph(f"• {v[:120]}", warn))
        if parsed.get("users"):
            story.append(Paragraph(f"<b>Users:</b> {', '.join(parsed['users'])}", body))

    elif tool == "enum4linux":
        story.append(Paragraph(
            f"<b>OS:</b> {parsed.get('os','')}  |  "
            f"<b>Domain:</b> {parsed.get('domain','')}",
            body
        ))
        for u in parsed.get("users",[])[:20]:
            story.append(Paragraph(f"• User: {u.get('username','')}  RID: {u.get('rid','')}", body))
        for s in parsed.get("shares",[])[:20]:
            story.append(Paragraph(f"• Share: {s.get('name','')} ({s.get('type','')})", body))

    elif tool == "dnsrecon":
        story.append(Paragraph(
            f"<b>Subdomains:</b> {parsed.get('total_subdomains',0)}  |  "
            f"<b>Zone Transfer:</b> {'YES ⚠' if parsed.get('zone_transfer_possible') else 'No'}",
            warn if parsed.get("zone_transfer_possible") else body
        ))
        for s in parsed.get("subdomains",[])[:20]:
            story.append(Paragraph(f"• {s.get('subdomain','')} → {s.get('ip','')}", body))

    else:
        story.append(Paragraph(str(parsed)[:400], muted))

    story.append(Spacer(1, 0.2*cm))


def _write_privesc_light(story, parsed, body, code, warn,
                         red, orange, border, light, white, text, accent):
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.units import cm

    juicy = parsed.get("juicy_points",[])
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        f"<b>Kernel:</b> {parsed.get('kernel_version','')}  |  "
        f"<b>Critical:</b> {parsed.get('critical',0)}  |  "
        f"<b>High:</b> {parsed.get('high',0)}",
        body
    ))

    if not juicy:
        story.append(Paragraph("No critical findings.", body))
        return

    tdata = [["Severity","Category","Finding","Path"]]
    for j in juicy:
        tdata.append([
            j.get("severity","").upper(),
            j.get("category",""),
            j.get("title","")[:55],
            j.get("path","")[:35],
        ])
    t = Table(tdata, colWidths=[2.5*cm,3*cm,7.5*cm,4*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),accent),
        ("TEXTCOLOR",(0,0),(-1,0),white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),8),
        ("TEXTCOLOR",(0,1),(-1,-1),text),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[light,white]),
        ("GRID",(0,0),(-1,-1),0.3,border),
        ("LEFTPADDING",(0,0),(-1,-1),4),
        ("TOPPADDING",(0,0),(-1,-1),3),
        ("BOTTOMPADDING",(0,0),(-1,-1),3),
    ]))
    story.append(t)

    # Exploit hints
    story.append(Spacer(1, 0.4*cm))
    for j in juicy:
        if j.get("exploit_hint"):
            story.append(Paragraph(
                f"<b>[{j['severity'].upper()}]</b> {j['title'][:60]}",
                body
            ))
            story.append(Paragraph(j["exploit_hint"][:200], code))