"""
report_handler.py — Builds and generates the PDF pentest report.

Pulls ALL data from SessionState:
  - Discovered hosts + ports (from state_parser auto-parse)
  - AI vulnerability findings (from ai_analyzer)
  - CVSS scores (from exploit_score)
  - Tool run history (from attack_log)
  - Raw tool outputs (from state.get_tool_results())
  - Exploit commands (from ai_explanation dicts)

Does NOT rely on structured 'parsed' dicts — those are empty.
Uses the rich structured state that actually gets populated.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.live import Live
from rich.spinner import Spinner

from kernox.engine.state import SessionState

console = Console()


class ReportHandler:
    def __init__(self, state: SessionState) -> None:
        self._state = state

    def ask_report(self) -> None:
        """Collect output path then generate full PDF report."""
        insights = self._state.get_ai_insights()
        results  = self._state.get_tool_results()
        hosts    = self._state.hosts

        if not insights and not results and not hosts:
            console.print(
                "[dim]No findings yet. Run some tools first, then generate the report.[/dim]"
            )
            return

        # Derive target from state
        target = "unknown"
        for r in results:
            if r.target and r.target not in ("unknown", ""):
                target = r.target
                break
        if target == "unknown" and hosts:
            target = list(hosts.keys())[0]

        safe         = target.replace("http://","").replace("https://","").replace("/","_")[:40]
        default_path = f"/tmp/kernox/report_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

        console.print(f"\n[bold cyan]Report Generator[/bold cyan]")
        console.print(f"  [dim]Hosts:    {len(hosts)}[/dim]")
        console.print(f"  [dim]Findings: {len(insights)}[/dim]")
        console.print(f"  [dim]Tools run:{len(results)}[/dim]\n")

        out = Prompt.ask("  Save report to", default=default_path)

        Path(out).parent.mkdir(parents=True, exist_ok=True)

        with Live(Spinner("dots", text="[cyan]Generating PDF...[/cyan]"), refresh_per_second=10):
            path = self._generate(target, out)

        if path:
            console.print(f"\n[bold green]✓ Report saved → {path}[/bold green]")
            # Show in file manager if available
            import shutil
            if shutil.which("xdg-open"):
                if Confirm.ask("  Open PDF?", default=False):
                    import subprocess
                    subprocess.Popen(["xdg-open", path])
        else:
            console.print("[red]✗ Report generation failed — check reportlab is installed[/red]")
            console.print("[dim]  pip install reportlab --break-system-packages[/dim]")

    def _generate(self, target: str, output_path: str) -> str | None:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.colors import HexColor
            from reportlab.lib.units import cm
            from reportlab.lib.enums import TA_CENTER
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table,
                TableStyle, PageBreak, HRFlowable,
            )
        except ImportError:
            console.print("[red]✗ reportlab not installed.[/red]")
            console.print("[dim]  pip install reportlab --break-system-packages[/dim]")
            return None

        try:
            return self._do_build(target, output_path)
        except Exception as exc:
            console.print(f"[red]✗ PDF error: {exc}[/red]")
            import traceback; console.print(f"[dim]{traceback.format_exc()[-400:]}[/dim]")
            return None

    def _do_build(self, target: str, output_path: str) -> str:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.colors import HexColor
        from reportlab.lib.units import cm
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table,
            TableStyle, PageBreak, HRFlowable,
        )
        from datetime import datetime
        from kernox.features.exploit_score import score_from_severity

        W=HexColor("#FFFFFF"); LIGHT=HexColor("#F6F8FA"); BORD=HexColor("#D0D7DE")
        TEXT=HexColor("#24292F"); MUTE=HexColor("#57606A"); ACC=HexColor("#0969DA")
        RED=HexColor("#CF222E"); ORA=HexColor("#BC4C00"); YEL=HexColor("#9A6700")
        GRN=HexColor("#1A7F37"); REDB=HexColor("#FFEBE9"); ORAB=HexColor("#FFF1E5")
        YELB=HexColor("#FFF8C5"); GRNB=HexColor("#DAFBE1"); HDR=HexColor("#0969DA")
        SEV_COL={"critical":(RED,REDB),"high":(ORA,ORAB),"medium":(YEL,YELB),
                 "low":(GRN,GRNB),"info":(MUTE,LIGHT)}

        def sty(name,**kw):
            b=getSampleStyleSheet()["Normal"]
            return ParagraphStyle(name,parent=b,**kw)
        T =sty("T", fontSize=28,textColor=ACC, fontName="Helvetica-Bold",alignment=TA_CENTER,spaceAfter=4)
        SB=sty("SB",fontSize=11,textColor=MUTE,alignment=TA_CENTER,spaceAfter=4)
        H1=sty("H1",fontSize=15,textColor=ACC, fontName="Helvetica-Bold",spaceBefore=14,spaceAfter=6)
        H2=sty("H2",fontSize=10,textColor=TEXT,fontName="Helvetica-Bold",spaceBefore=6,spaceAfter=3)
        BD=sty("BD",fontSize=9, textColor=TEXT,spaceAfter=3,leading=14)
        MU=sty("MU",fontSize=8, textColor=MUTE,spaceAfter=2,leading=12)
        CD=sty("CD",fontSize=8, textColor=ACC, fontName="Courier",backColor=LIGHT,spaceAfter=3,leading=12,leftIndent=8)

        doc=SimpleDocTemplate(output_path,pagesize=A4,
                              rightMargin=2*cm,leftMargin=2*cm,topMargin=2*cm,bottomMargin=2*cm)
        story=[]

        insights=self._state.get_ai_insights()
        results =self._state.get_tool_results()
        hosts   =self._state.hosts
        paths   =self._state.paths
        notes   =getattr(self._state,'_notes',[])

        sev_order=["critical","high","medium","low","info"]
        sorted_insights=sorted(insights,
            key=lambda x:sev_order.index(x.severity.lower())
            if x.severity.lower() in sev_order else 5)
        counts={s:sum(1 for i in insights if i.severity.lower()==s) for s in sev_order}
        overall=next((s for s in sev_order if counts[s]>0),"info")

        def tbl(data,widths,hdr_row=True):
            t=Table(data,colWidths=widths)
            s=[("FONTSIZE",(0,0),(-1,-1),8),("TEXTCOLOR",(0,1),(-1,-1),TEXT),
               ("ROWBACKGROUNDS",(0,1),(-1,-1),[LIGHT,W]),("GRID",(0,0),(-1,-1),0.3,BORD),
               ("LEFTPADDING",(0,0),(-1,-1),4),("TOPPADDING",(0,0),(-1,-1),3),
               ("BOTTOMPADDING",(0,0),(-1,-1),3)]
            if hdr_row:
                s+=[("BACKGROUND",(0,0),(-1,0),HDR),("TEXTCOLOR",(0,0),(-1,0),W),
                    ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold")]
            t.setStyle(TableStyle(s)); return t

        # Cover
        story+=[Spacer(1,1.5*cm),Paragraph("KERNOX",T),
                Paragraph("AI-Powered Penetration Test Report",SB),
                Spacer(1,0.4*cm),HRFlowable(width="100%",thickness=2,color=ACC),Spacer(1,0.6*cm)]
        cover=[["Target",target],["Date",datetime.now().strftime("%B %d, %Y  %H:%M")],
               ["Overall Risk",overall.upper()],["Hosts Found",str(len(hosts))],
               ["AI Findings",str(len(insights))],["Tools Run",str(len(results))],
               ["Generated by","Kernox Autonomous Pentesting Agent"]]
        ct=Table(cover,colWidths=[4.5*cm,12.5*cm])
        ct.setStyle(TableStyle([("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),10),
            ("TEXTCOLOR",(0,0),(-1,-1),TEXT),("TEXTCOLOR",(0,0),(0,-1),ACC),
            ("ROWBACKGROUNDS",(0,0),(-1,-1),[LIGHT,W]),("GRID",(0,0),(-1,-1),0.5,BORD),
            ("LEFTPADDING",(0,0),(-1,-1),10),("TOPPADDING",(0,0),(-1,-1),7),("BOTTOMPADDING",(0,0),(-1,-1),7)]))
        story+=[ct,Spacer(1,0.5*cm),
                Paragraph("CONFIDENTIAL — Authorized security testing only.",MU),PageBreak()]

        # Executive summary
        story+=[Paragraph("Executive Summary",H1),HRFlowable(width="100%",thickness=1,color=BORD),Spacer(1,0.3*cm)]
        sev_data=[["Severity","Count","Visual"]]
        for s in sev_order:
            bar="█"*min(counts[s],25) if counts[s] else "—"
            sev_data.append([s.upper(),str(counts[s]),bar])
        story+=[tbl(sev_data,[4*cm,3*cm,10*cm]),Spacer(1,0.4*cm),PageBreak()]

        # Hosts
        if hosts:
            story+=[Paragraph("Discovered Hosts & Attack Surface",H1),
                    HRFlowable(width="100%",thickness=1,color=BORD),Spacer(1,0.3*cm)]
            for ip,h in hosts.items():
                story.append(Paragraph(
                    f"<b>{ip}</b>"+(f"  [{h.hostname}]" if h.hostname else "")+(f"  OS: {h.os}" if h.os else ""),H2))
                if h.ports:
                    pd=[["Port","Proto","Service","Version"]]
                    for p in sorted(h.ports,key=lambda x:x.get("port",0)):
                        pd.append([str(p.get("port","")),p.get("proto",""),p.get("service",""),p.get("version","")[:50]])
                    story.append(tbl(pd,[2.5*cm,2.5*cm,4*cm,8*cm]))
                else:
                    story.append(Paragraph("No port data recorded.",MU))
                story.append(Spacer(1,0.3*cm))
            story.append(PageBreak())

        # Vulnerabilities
        if sorted_insights:
            story+=[Paragraph("Vulnerability Findings",H1),
                    HRFlowable(width="100%",thickness=1,color=BORD),Spacer(1,0.3*cm)]
            for ins in sorted_insights:
                sev=ins.severity.lower()
                fg,bg=SEV_COL.get(sev,(MUTE,LIGHT))
                expl=ins.ai_explanation if isinstance(ins.ai_explanation,dict) else {}
                badge=Table([[f"{ins.severity.upper()}  —  {ins.vulnerability}"]],colWidths=[17*cm])
                badge.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),bg),("TEXTCOLOR",(0,0),(-1,-1),fg),
                    ("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),10),
                    ("LEFTPADDING",(0,0),(-1,-1),8),("TOPPADDING",(0,0),(-1,-1),6),
                    ("BOTTOMPADDING",(0,0),(-1,-1),6),("BOX",(0,0),(-1,-1),1,fg)]))
                story+=[badge,Spacer(1,0.1*cm),
                        Paragraph(f"<b>Target:</b> {ins.target}  |  <b>Tool:</b> {ins.tool}",MU)]
                score=score_from_severity(sev)
                if score>0:
                    story.append(Paragraph(f"<b>CVSS:</b> {score:.1f} ({sev.upper()})",BD))
                if expl.get("description"):
                    story+=[Paragraph("<b>Description:</b>",H2),Paragraph(expl["description"][:500],BD)]
                if expl.get("impact"):
                    story+=[Paragraph("<b>Impact:</b>",H2),Paragraph(expl["impact"][:300],BD)]
                if expl.get("exploit"):
                    story+=[Paragraph("<b>Exploit Command:</b>",H2),Paragraph(expl["exploit"][:300],CD)]
                story+=[Spacer(1,0.4*cm),HRFlowable(width="100%",thickness=0.5,color=BORD),Spacer(1,0.2*cm)]
            story.append(PageBreak())

        # Web paths
        if paths:
            story+=[Paragraph("Web Paths Discovered",H1),
                    HRFlowable(width="100%",thickness=1,color=BORD),Spacer(1,0.3*cm)]
            for tgt,found in paths.items():
                story.append(Paragraph(f"<b>{tgt}</b>  ({len(found)} paths)",H2))
                pd=[["#","Path","Status"]]
                for i,f in enumerate(found[:100],1):
                    pd.append([str(i),f.get("path",""),str(f.get("status","")or"—")])
                story+=[tbl(pd,[1*cm,12*cm,4*cm]),Spacer(1,0.4*cm)]
            story.append(PageBreak())

        # Timeline
        if results:
            story+=[Paragraph("Attack Timeline",H1),
                    HRFlowable(width="100%",thickness=1,color=BORD),Spacer(1,0.3*cm)]
            td=[["Tool","Target","Exit","Duration"]]
            for r in results:
                p=r.parsed or {}
                td.append([r.tool,r.target[:35],str(p.get("exit_code","—")),f"{p.get('duration',0):.1f}s"])
            story+=[tbl(td,[4*cm,7*cm,3*cm,3*cm]),Spacer(1,0.4*cm),PageBreak()]

        # AI notes
        reflections=[n for n in notes if n.startswith("[REFLECTION")]
        if reflections:
            story+=[Paragraph("AI Agent Observations",H1),
                    HRFlowable(width="100%",thickness=1,color=BORD),Spacer(1,0.3*cm)]
            for note in reflections[:10]:
                clean=note.replace("[REFLECTION after ","After ").replace("]",":",1)
                story.append(Paragraph(f"• {clean[:300]}",BD))
            story+=[Spacer(1,0.4*cm),PageBreak()]

        # Disclaimer
        story+=[Paragraph("Disclaimer",H1),HRFlowable(width="100%",thickness=1,color=BORD),Spacer(1,0.3*cm),
                Paragraph("This report was generated by Kernox for authorized security testing only. "
                           "All findings must be verified manually. Information herein is confidential.",BD)]

        doc.build(story)
        return output_path
