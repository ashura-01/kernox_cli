"""
kernox.utils.report_generator – Professional PDF report generator.
Light theme for readability. AI-powered vulnerability explanations.
NO HARDCODED TOOL NAMES – works with any tool automatically.
"""

from __future__ import annotations

import os
import json
import re
import hashlib
from datetime import datetime
from typing import Optional, Dict, Any
from collections import OrderedDict
from xml.sax.saxutils import escape

from rich.console import Console

console = Console()

# =============================================================================
# AI Explanation Cache
# =============================================================================

_AI_EXPLANATION_CACHE: OrderedDict[str, dict] = OrderedDict()
_AI_CACHE_MAX = 500
_AI_CLIENT = None

# =============================================================================
# Limits
# =============================================================================

MAX_HOSTS = 100
MAX_PORTS = 200
MAX_FINDINGS = 100
MAX_URLS = 100
MAX_EMAILS = 100
MAX_TECHS = 100
MAX_JUICY = 50


def _safe_text(value: Any, limit: int = 4000) -> str:
    """Escape text for safe ReportLab rendering."""
    if value is None:
        return ""

    text = str(value)
    text = text.replace("\x00", "")
    text = escape(text)

    if len(text) > limit:
        text = text[:limit] + "..."

    return text


def _normalize_severity(sev: str) -> str:
    """Normalize severity names."""
    if not sev:
        return "medium"

    sev = str(sev).strip().lower()

    mapping = {
        "critical": "critical",
        "crit": "critical",
        "high": "high",
        "medium": "medium",
        "med": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
    }

    return mapping.get(sev, "medium")


def _cache_set(key: str, value: dict):
    """LRU-style cache insertion."""
    global _AI_EXPLANATION_CACHE

    if key in _AI_EXPLANATION_CACHE:
        _AI_EXPLANATION_CACHE.move_to_end(key)

    _AI_EXPLANATION_CACHE[key] = value

    while len(_AI_EXPLANATION_CACHE) > _AI_CACHE_MAX:
        _AI_EXPLANATION_CACHE.popitem(last=False)


def _extract_json(text: str) -> dict:
    """Safely extract JSON from AI output."""
    text = text.strip()

    try:
        return json.loads(text)
    except Exception:
        pass

    try:
        matches = re.findall(r"\{.*?\}", text, re.DOTALL)

        for m in matches:
            try:
                return json.loads(m)
            except Exception:
                continue
    except Exception:
        pass

    raise ValueError("No valid JSON found")


def _get_ai_client():
    """Get or initialize AI client for report generation."""
    global _AI_CLIENT

    if _AI_CLIENT is None:
        try:
            from kernox.ai.factory import build_ai_client
            from kernox.config.config_store import ConfigStore

            config = ConfigStore()
            _AI_CLIENT = build_ai_client(config)

        except Exception as e:
            console.print(f"[dim]⚠ AI init failed: {e}[/dim]")

    return _AI_CLIENT


def _generate_ai_explanation(finding: str, tool_name: str = "") -> dict:
    """Generate vulnerability explanation using AI with caching."""

    cache_key = hashlib.md5(
        f"{finding}:{tool_name}".encode()
    ).hexdigest()

    if cache_key in _AI_EXPLANATION_CACHE:
        return _AI_EXPLANATION_CACHE[cache_key]

    ai_client = _get_ai_client()

    fallback = {
        "name": finding[:80],
        "severity": "MEDIUM",
        "description": f"Potential vulnerability: {finding[:200]}",
        "impact": "Investigate further",
        "recommendation": "Verify and patch if confirmed",
        "references": [],
    }

    if not ai_client:
        return fallback

    try:
        prompt = f"""Analyze this vulnerability finding. Return ONLY valid JSON.

Finding: {finding}
Tool: {tool_name}

Return JSON:
{{
  "name": "vulnerability name",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "description": "what it is and how it works",
  "impact": "what attacker can do",
  "recommendation": "remediation steps",
  "references": []
}}

Do NOT invent CVSS scores or CVE IDs.
"""

        response = ai_client.chat(
            messages=[{"role": "user", "content": prompt}],
            system="You are a security analyst. Extract only what is clearly indicated.",
            max_tokens=500,
            temperature=0.3,
        )

        explanation = _extract_json(response)

        explanation["name"] = _safe_text(
            explanation.get("name", finding[:80]),
            200
        )

        explanation["severity"] = _normalize_severity(
            explanation.get("severity", "medium")
        ).upper()

        explanation["description"] = _safe_text(
            explanation.get("description", "Security finding identified"),
            1500
        )

        explanation["impact"] = _safe_text(
            explanation.get("impact", "Requires investigation"),
            1000
        )

        explanation["recommendation"] = _safe_text(
            explanation.get("recommendation", "Verify and remediate"),
            1000
        )

        refs = explanation.get("references", [])

        if not isinstance(refs, list):
            refs = []

        explanation["references"] = [
            _safe_text(r, 300)
            for r in refs[:10]
        ]

        _cache_set(cache_key, explanation)

        return explanation

    except Exception as e:
        console.print(f"[dim]⚠ AI explanation failed: {e}[/dim]")
        return fallback


def explain_vulnerability(finding: str) -> dict | None:
    """AI-powered vulnerability explanation."""

    if not finding or not str(finding).strip():
        return None

    if re.search(r"CVE-\d{4}-\d+", finding, re.IGNORECASE):
        return None

    return _generate_ai_explanation(finding)


def generate_pdf_report(
    target: str,
    results: list[dict],
    output_path: str = "",
    privesc_data: dict | None = None,
    ai_insights: list[dict] | None = None,
) -> str:
    """Generate professional PDF report."""

    if not output_path:
        reports_dir = os.path.expanduser("~/.kernox/reports")
        os.makedirs(reports_dir, exist_ok=True)

        output_path = os.path.join(
            reports_dir,
            f"kernox_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        )

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.colors import HexColor
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
            PageBreak,
            HRFlowable,
        )
        from reportlab.lib.enums import TA_CENTER

    except ImportError:
        console.print(
            "[red]reportlab not installed. "
            "Run: pip install reportlab --break-system-packages[/red]"
        )
        return ""

    # =========================================================================
    # Colors
    # =========================================================================

    C_WHITE = HexColor("#FFFFFF")
    C_LIGHT = HexColor("#F6F8FA")
    C_BORDER = HexColor("#D0D7DE")
    C_TEXT = HexColor("#24292F")
    C_MUTED = HexColor("#57606A")
    C_ACCENT = HexColor("#0969DA")

    C_RED = HexColor("#CF222E")
    C_ORANGE = HexColor("#BC4C00")
    C_YELLOW = HexColor("#9A6700")
    C_GREEN = HexColor("#1A7F37")

    C_RED_BG = HexColor("#FFEBE9")
    C_ORANGE_BG = HexColor("#FFF1E5")
    C_YELLOW_BG = HexColor("#FFF8C5")
    C_GREEN_BG = HexColor("#DAFBE1")

    C_HEADER_BG = HexColor("#0969DA")

    SEV_COLORS = {
        "critical": (C_RED, C_RED_BG),
        "high": (C_ORANGE, C_ORANGE_BG),
        "medium": (C_YELLOW, C_YELLOW_BG),
        "low": (C_GREEN, C_GREEN_BG),
        "info": (C_MUTED, C_LIGHT),
    }

    # =========================================================================
    # Document
    # =========================================================================

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    from reportlab.lib.styles import ParagraphStyle

    def S(name, **kw):
        base = getSampleStyleSheet()["Normal"]
        return ParagraphStyle(name, parent=base, **kw)

    title_s = S(
        "T",
        fontSize=26,
        textColor=C_ACCENT,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
        spaceAfter=4,
    )

    sub_s = S(
        "Su",
        fontSize=11,
        textColor=C_MUTED,
        alignment=TA_CENTER,
        spaceAfter=4,
    )

    h1_s = S(
        "H1",
        fontSize=15,
        textColor=C_ACCENT,
        fontName="Helvetica-Bold",
        spaceBefore=14,
        spaceAfter=5,
    )

    h2_s = S(
        "H2",
        fontSize=11,
        textColor=C_TEXT,
        fontName="Helvetica-Bold",
        spaceBefore=8,
        spaceAfter=3,
    )

    body_s = S(
        "B",
        fontSize=9,
        textColor=C_TEXT,
        spaceAfter=3,
        leading=14,
    )

    muted_s = S(
        "M",
        fontSize=8,
        textColor=C_MUTED,
        spaceAfter=2,
        leading=12,
    )

    code_s = S(
        "C",
        fontSize=8,
        textColor=C_ACCENT,
        fontName="Courier",
        backColor=C_LIGHT,
        spaceAfter=3,
        leading=12,
        leftIndent=8,
    )

    story = []

    # =========================================================================
    # Cover
    # =========================================================================

    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph("KERNOX", title_s))
    story.append(Paragraph("Security Assessment Report", sub_s))
    story.append(Spacer(1, 0.3 * cm))
    story.append(HRFlowable(width="100%", thickness=2, color=C_ACCENT))
    story.append(Spacer(1, 0.5 * cm))

    cover_data = [
        ["Target", _safe_text(target, 200)],
        ["Date", datetime.now().strftime("%B %d, %Y  %H:%M")],
        ["Tools Run", str(len(results))],
        ["Generated", "Kernox AI Security Tool"],
    ]

    ct = Table(cover_data, colWidths=[4 * cm, 13 * cm], repeatRows=1)

    ct.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (-1, -1), C_TEXT),
        ("TEXTCOLOR", (0, 0), (0, -1), C_ACCENT),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_LIGHT, C_WHITE]),
        ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))

    story.append(ct)
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph(
        "AUTHORIZED TESTING ONLY. "
        "This report is confidential and for authorized security testing only.",
        muted_s
    ))

    story.append(PageBreak())

    # =========================================================================
    # Count Findings
    # =========================================================================

    total_findings = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    all_vulns = []

    for r in results:
        parsed = r.get("parsed", {})

        if not isinstance(parsed, dict):
            continue

        if "severity_counts" in parsed:
            sev_counts = parsed["severity_counts"]

            if isinstance(sev_counts, dict):
                for sev, count in sev_counts.items():
                    sev = _normalize_severity(sev)

                    try:
                        total_findings[sev] += int(count)
                    except Exception:
                        continue

        if "vulnerabilities" in parsed:
            for vuln in parsed["vulnerabilities"][:MAX_FINDINGS]:
                if isinstance(vuln, str):
                    exp = explain_vulnerability(vuln)

                    if exp:
                        all_vulns.append(exp)

                elif isinstance(vuln, dict):
                    all_vulns.append(vuln)

        for field in ["findings", "issues", "vulns"]:
            if field in parsed:
                for finding in parsed[field][:MAX_FINDINGS]:
                    if isinstance(finding, str):
                        exp = explain_vulnerability(finding)

                        if exp:
                            all_vulns.append(exp)

    # =========================================================================
    # Executive Summary
    # =========================================================================

    story.append(Paragraph("Executive Summary", h1_s))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
    story.append(Spacer(1, 0.3 * cm))

    risk = (
        "CRITICAL"
        if total_findings["critical"] > 0 else
        "HIGH"
        if total_findings["high"] > 0 else
        "MEDIUM"
        if total_findings["medium"] > 0 else
        "LOW"
    )

    risk_colors = {
        "CRITICAL": C_RED,
        "HIGH": C_ORANGE,
        "MEDIUM": C_YELLOW,
        "LOW": C_GREEN,
    }

    risk_color = risk_colors[risk].hexval().replace("0x", "")

    story.append(Paragraph(
        f"Overall Risk: "
        f"<b><font color='#{risk_color}'>{risk}</font></b> "
        f"| Target: <b>{_safe_text(target, 100)}</b> "
        f"| Tools: <b>{len(results)}</b>",
        body_s
    ))

    story.append(Spacer(1, 0.3 * cm))

    sev_data = [["Severity", "Count", "Level"]]

    for label, key in [
        ("Critical", "critical"),
        ("High", "high"),
        ("Medium", "medium"),
        ("Low", "low"),
        ("Info", "info"),
    ]:
        sev_data.append([
            label,
            str(total_findings[key]),
            label.upper(),
        ])

    st = Table(
        sev_data,
        colWidths=[5 * cm, 5 * cm, 7 * cm],
        repeatRows=1,
    )

    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 1), (-1, -1), C_TEXT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_LIGHT, C_WHITE]),
        ("GRID", (0, 0), (-1, -1), 0.5, C_BORDER),
    ]))

    story.append(st)
    story.append(PageBreak())

    # =========================================================================
    # Vulnerability Analysis
    # =========================================================================

    if all_vulns:
        story.append(Paragraph("Vulnerability Analysis", h1_s))
        story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))
        story.append(Spacer(1, 0.3 * cm))

        seen = set()

        for vuln in all_vulns[:MAX_FINDINGS]:
            vuln_hash = hashlib.md5(
                json.dumps(vuln, sort_keys=True).encode()
            ).hexdigest()

            if vuln_hash in seen:
                continue

            seen.add(vuln_hash)

            sev = _normalize_severity(
                vuln.get("severity", "medium")
            )

            fg, bg = SEV_COLORS.get(
                sev,
                (C_TEXT, C_LIGHT)
            )

            badge_text = (
                f"{sev.upper()}  "
                f"{_safe_text(vuln.get('name', 'Unknown'), 120)}"
            )

            bt = Table(
                [[Paragraph(badge_text, body_s)]],
                colWidths=[17 * cm]
            )

            bt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("TEXTCOLOR", (0, 0), (-1, -1), fg),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOX", (0, 0), (-1, -1), 1, fg),
            ]))

            story.append(bt)

            story.append(Paragraph("<b>Description:</b>", h2_s))
            story.append(Paragraph(
                _safe_text(vuln.get("description", "")),
                body_s
            ))

            story.append(Paragraph("<b>Impact:</b>", h2_s))
            story.append(Paragraph(
                _safe_text(vuln.get("impact", "")),
                body_s
            ))

            story.append(Paragraph("<b>Recommendation:</b>", h2_s))
            story.append(Paragraph(
                _safe_text(vuln.get("recommendation", "")),
                body_s
            ))

            refs = vuln.get("references", [])

            if refs:
                story.append(Paragraph("<b>References:</b>", h2_s))

                for ref in refs[:10]:
                    story.append(Paragraph(
                        f"• {_safe_text(ref, 300)}",
                        code_s
                    ))

            story.append(Spacer(1, 0.2 * cm))
            story.append(HRFlowable(
                width="100%",
                thickness=0.5,
                color=C_BORDER
            ))

        story.append(PageBreak())

    # =========================================================================
    # Technical Findings
    # =========================================================================

    story.append(Paragraph("Technical Findings", h1_s))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BORDER))

    for r in results:
        tool = _safe_text(r.get("tool", "unknown"), 100)
        parsed = r.get("parsed", {})

        story.append(Spacer(1, 0.3 * cm))

        th = Table(
            [[Paragraph(f"{tool.upper()}", body_s)]],
            colWidths=[17 * cm]
        )

        th.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), C_HEADER_BG),
            ("TEXTCOLOR", (0, 0), (-1, -1), C_WHITE),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
        ]))

        story.append(th)

        _write_generic_section(
            story,
            parsed,
            body_s,
            code_s,
            muted_s,
            h2_s,
            C_BORDER,
            C_LIGHT,
            C_WHITE,
            C_TEXT,
        )

    # =========================================================================
    # PrivEsc
    # =========================================================================

    if privesc_data:
        story.append(PageBreak())

        story.append(Paragraph(
            "Privilege Escalation Findings",
            h1_s
        ))

        story.append(HRFlowable(
            width="100%",
            thickness=1,
            color=C_BORDER
        ))

        _write_privesc_generic(
            story,
            privesc_data,
            body_s,
            code_s,
            C_BORDER,
            C_LIGHT,
            C_WHITE,
            C_TEXT,
            C_ACCENT,
        )

    # =========================================================================
    # Disclaimer
    # =========================================================================

    story.append(PageBreak())

    story.append(Paragraph("Notes & Disclaimer", h1_s))

    story.append(HRFlowable(
        width="100%",
        thickness=1,
        color=C_BORDER
    ))

    story.append(Paragraph(
        "This report was generated by Kernox for authorized "
        "security testing only. All findings should be verified manually.",
        body_s
    ))

    # =========================================================================
    # Build
    # =========================================================================

    try:
        doc.build(story)

        console.print(
            f"\n[bold green]✓ PDF report saved:[/bold green] "
            f"[cyan]{output_path}[/cyan]"
        )

        return output_path

    except Exception as e:
        console.print(f"[red]PDF generation failed: {e}[/red]")
        return ""


# =============================================================================
# GENERIC FORMATTERS
# =============================================================================

def _write_generic_section(
    story,
    parsed,
    body,
    code,
    muted,
    h2,
    border,
    light,
    white,
    text,
):
    """Generic formatter."""

    from reportlab.platypus import (
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    from reportlab.lib.units import cm

    if not parsed:
        story.append(Paragraph(
            "No structured data available.",
            muted
        ))
        return

    if not isinstance(parsed, dict):
        story.append(Paragraph(
            _safe_text(parsed, 500),
            muted
        ))
        return

    if "hosts" in parsed:
        for host in parsed.get("hosts", [])[:MAX_HOSTS]:
            story.append(Paragraph(
                f"<b>Host:</b> "
                f"{_safe_text(host.get('ip', 'unknown'), 50)} "
                f"| <b>OS:</b> "
                f"{_safe_text(host.get('os', 'Unknown'), 50)}",
                body
            ))

            ports = [
                p for p in host.get("ports", [])
                if p.get("state") == "open"
            ]

            ports = ports[:MAX_PORTS]

            if ports:
                tdata = [[
                    "Port",
                    "Protocol",
                    "Service",
                    "Version"
                ]]

                for p in ports:
                    tdata.append([
                        Paragraph(
                            _safe_text(p.get("port", ""), 20),
                            body
                        ),
                        Paragraph(
                            _safe_text(p.get("proto", ""), 20),
                            body
                        ),
                        Paragraph(
                            _safe_text(p.get("service", ""), 40),
                            body
                        ),
                        Paragraph(
                            _safe_text(p.get("version", ""), 100),
                            body
                        ),
                    ])

                t = Table(
                    tdata,
                    colWidths=[
                        2.5 * cm,
                        2.5 * cm,
                        3.5 * cm,
                        8 * cm,
                    ],
                    repeatRows=1,
                )

                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), white),
                    ("TEXTCOLOR", (0, 0), (-1, 0), text),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.3, border),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [light, white]),
                ]))

                story.append(t)
                story.append(Spacer(1, 0.2 * cm))

    elif any(k in parsed for k in ["findings", "issues", "vulns"]):
        findings_key = next(
            (k for k in ["findings", "issues", "vulns"] if k in parsed),
            None
        )

        findings = parsed.get(findings_key, [])[:MAX_FINDINGS]

        story.append(Paragraph(
            f"<b>Total findings:</b> {len(findings)}",
            body
        ))

        for f in findings:
            if isinstance(f, dict):
                text_value = (
                    f.get("name")
                    or f.get("description")
                    or str(f)
                )
            else:
                text_value = str(f)

            story.append(Paragraph(
                f"• {_safe_text(text_value, 150)}",
                body
            ))

    elif "emails" in parsed:
        emails = parsed["emails"][:MAX_EMAILS]

        story.append(Paragraph(
            f"<b>Total emails:</b> {len(emails)}",
            body
        ))

        for email in emails:
            story.append(Paragraph(
                f"• {_safe_text(email, 100)}",
                body
            ))

    elif "urls" in parsed:
        urls = parsed["urls"][:MAX_URLS]

        story.append(Paragraph(
            f"<b>URLs found:</b> {len(urls)}",
            body
        ))

        for url in urls:
            story.append(Paragraph(
                f"• {_safe_text(url, 150)}",
                code
            ))

    else:
        story.append(Paragraph("<b>Results:</b>", body))

        for key, value in list(parsed.items())[:50]:
            if isinstance(value, list):
                story.append(Paragraph(
                    f"{_safe_text(key, 50)}: "
                    f"{len(value)} items",
                    muted
                ))

            elif isinstance(value, dict):
                story.append(Paragraph(
                    f"{_safe_text(key, 50)}: object",
                    muted
                ))

            else:
                story.append(Paragraph(
                    f"{_safe_text(key, 50)}: "
                    f"{_safe_text(value, 120)}",
                    muted
                ))

    story.append(Spacer(1, 0.2 * cm))


def _write_privesc_generic(
    story,
    parsed,
    body,
    code,
    border,
    light,
    white,
    text,
    accent,
):
    """Generic privilege escalation formatter."""

    from reportlab.platypus import (
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    from reportlab.lib.units import cm

    juicy = parsed.get("juicy_points", [])[:MAX_JUICY]

    for key in ["kernel_version", "kernel", "os_version"]:
        if parsed.get(key):
            story.append(Paragraph(
                f"<b>System:</b> "
                f"{_safe_text(parsed[key], 100)}",
                body
            ))
            break

    story.append(Paragraph(
        f"<b>Critical:</b> {parsed.get('critical', 0)} "
        f"| <b>High:</b> {parsed.get('high', 0)} "
        f"| <b>Medium:</b> {parsed.get('medium', 0)}",
        body
    ))

    if not juicy:
        story.append(Paragraph(
            "No privilege escalation findings detected.",
            body
        ))
        return

    tdata = [[
        "Severity",
        "Category",
        "Title",
        "Path"
    ]]

    for j in juicy:
        tdata.append([
            Paragraph(
                _safe_text(
                    j.get("severity", "").upper(),
                    20
                ),
                body
            ),
            Paragraph(
                _safe_text(j.get("category", ""), 40),
                body
            ),
            Paragraph(
                _safe_text(j.get("title", ""), 100),
                body
            ),
            Paragraph(
                _safe_text(j.get("path", ""), 80),
                body
            ),
        ])

    t = Table(
        tdata,
        colWidths=[
            2.5 * cm,
            3 * cm,
            7 * cm,
            4 * cm,
        ],
        repeatRows=1,
    )

    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), accent),
        ("TEXTCOLOR", (0, 0), (-1, 0), white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.3, border),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [light, white]),
    ]))

    story.append(t)

    story.append(Spacer(1, 0.3 * cm))

    for j in juicy[:10]:
        if j.get("exploit_hint"):
            story.append(Paragraph(
                f"<b>[{_safe_text(j.get('severity', 'INFO').upper(), 20)}]</b> "
                f"{_safe_text(j.get('title', ''), 80)}",
                body
            ))

            story.append(Paragraph(
                _safe_text(j["exploit_hint"], 400),
                code
            ))

            story.append(Spacer(1, 0.2 * cm))
