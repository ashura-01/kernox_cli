"""
Reconnaissance tool for Kernox - silent execution with AI summary.
"""

import subprocess
from rich.console import Console
from rich.panel import Panel
from rich import box
from rich.live import Live
from rich.spinner import Spinner

console = Console()

class ReconTool:
    """Reconnaissance tool - silent execution with AI analysis."""

    def __init__(self, ai_client=None):
        self.ai_client = ai_client

    def build_command(self, target: str, mode: str = "full", **kwargs) -> str:
        """Return a marker - this tool doesn't use shell."""
        return f"__RECON__:{target}:{mode}"

    def run_direct(self, target: str, mode: str = "full", **kwargs) -> dict:
        """Run reconnaissance silently and let AI analyze."""

        console.print(Panel(
            f"[bold cyan]🔍 RECONNAISSANCE: {target}[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(1, 2)
        ))

        results = {}

        # Run all recon tools silently (capture output, don't display)
        with Live(Spinner("dots", text="[dim]Running WHOIS lookup...[/dim]"), refresh_per_second=10, transient=True):
            whois_result = self._run_cmd(['whois', target])
            results['whois'] = whois_result['stdout'][:2000]

        with Live(Spinner("dots", text="[dim]Running DNS lookup...[/dim]"), refresh_per_second=10, transient=True):
            dns_result = self._run_cmd(['nslookup', target])
            results['dns'] = dns_result['stdout'][:1000]

        with Live(Spinner("dots", text="[dim]Running DIG...[/dim]"), refresh_per_second=10, transient=True):
            dig_result = self._run_cmd(['dig', target, '+short'])
            results['dig'] = dig_result['stdout'][:500]

        with Live(Spinner("dots", text="[dim]Testing connectivity...[/dim]"), refresh_per_second=10, transient=True):
            ping_result = self._run_cmd(['ping', '-c', '3', '-W', '2', target])
            results['ping'] = ping_result['stdout']

        with Live(Spinner("dots", text="[dim]Checking HTTP headers...[/dim]"), refresh_per_second=10, transient=True):
            url = target if target.startswith(('http://', 'https://')) else f"http://{target}"
            http_result = self._run_cmd(['curl', '-I', '-s', '-L', '--max-time', '8', url])
            results['http'] = http_result['stdout'][:1000]

        # Now let AI analyze and present clean results
        if self.ai_client:
            self._ai_summarize(target, results)
        else:
            # Fallback to raw output if no AI
            self._print_raw_fallback(results)

        console.print("\n[bold green]✓ Reconnaissance complete![/bold green]")

        return {
            'target': target,
            'findings': results,
            'summary': f"Recon complete for {target}"
        }

    def _ai_summarize(self, target: str, results: dict) -> None:
        """Send results to AI for clean summarization."""

        # Extract key info for AI
        summary_data = f"""
TARGET: {target}

WHOIS INFO (first 800 chars):
{results.get('whois', '')[:800]}

DNS INFO (first 500 chars):
{results.get('dns', '')[:500]}

IP ADDRESSES from DIG:
{results.get('dig', '')[:300]}

PING RESULT:
{results.get('ping', '')[:300]}

HTTP HEADERS (if any):
{results.get('http', '')[:500]}
"""

        prompt = f"""You are a penetration testing assistant. Analyze this reconnaissance data and provide a CLEAN, ACTIONABLE summary.

Do NOT repeat raw data. Extract ONLY the important information.

{summary_data}

Provide your response in this EXACT format (use markdown):

## 📋 DOMAIN INFO
- Domain:
- Registrar:
- Created:
- Expires:
- Name Servers:

## 🌐 NETWORK INFO
- IP Addresses:
- Connectivity: (up/down, response time)

## 🔧 WEB SERVER (if detected)
- Server:
- Technologies:

## 🎯 RECOMMENDED NEXT STEPS
1. `command here`
2. `command here`
3. `command here`

If information is missing, just say "Not detected" or "Unknown"."""

        try:
            with Live(Spinner("dots", text="[dim]🤖 AI analyzing reconnaissance data...[/dim]"), refresh_per_second=10):
                response = self.ai_client.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="You are a senior penetration tester. Provide clean, actionable summaries. Use markdown formatting.",
                    max_tokens=800,
                    temperature=0.3
                )

            console.print(Panel(
                response,
                title="[bold yellow]RECONNAISSANCE SUMMARY[/bold yellow]",
                border_style="yellow",
                box=box.ROUNDED,
                padding=(1, 2)
            ))

        except Exception as e:
            console.print(f"[red]AI analysis failed: {e}[/red]")
            self._print_raw_fallback(results)

    def _print_raw_fallback(self, results: dict) -> None:
        """Fallback to raw output if AI fails."""
        if results.get('whois'):
            console.print(Panel(results['whois'][:1000], title="WHOIS", border_style="dim"))
        if results.get('dns'):
            console.print(Panel(results['dns'][:500], title="DNS", border_style="dim"))

    def _run_cmd(self, cmd: list) -> dict:
        """Run shell command."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15
            )
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'stdout': '', 'stderr': 'Timeout'}
        except Exception as e:
            return {'success': False, 'stdout': '', 'stderr': str(e)}

    def parse(self, output: dict) -> dict:
        """Parse the results."""
        return {
            'target': output.get('target', ''),
            'findings': output.get('findings', {}),
            'summary': output.get('summary', '')
        }
