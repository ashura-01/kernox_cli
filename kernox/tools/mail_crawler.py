"""kernox.tools.mail_crawler – Email harvester from websites."""

from __future__ import annotations
import re
import random
import time
from collections import deque
from typing import Optional
import urllib.parse

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
from rich import box

console = Console()


class MailCrawlerTool:
    name = "mail_crawler"
    
    # Configuration
    MAX_URLS = 500
    CRAWL_DELAY = (1, 2)
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15"
    ]
    EMAIL_REGEX = r"[a-z0-9.\-+_]+@[a-z0-9.\-+_]+\.[a-z]+"

    def __init__(self):
        self._found_emails = set()
        self._crawled_urls = set()
        self._total_pages = 0

    def _normalize_url(self, base: str, link: str) -> str:
        """Normalize relative URLs to absolute."""
        link = link.strip()
        if link.startswith("//"):
            link = "http:" + link
        elif link.startswith("/"):
            link = urllib.parse.urljoin(base, link)
        elif not link.startswith(("http://", "https://")):
            link = urllib.parse.urljoin(base, link)
        return link.split("#")[0]

    def _extract_emails(self, text: str) -> set:
        """Extract emails from text using regex."""
        return set(re.findall(self.EMAIL_REGEX, text, re.IGNORECASE))

    def _should_crawl(self, url: str, base_url: str) -> bool:
        """Check if URL should be crawled."""
        return (url.startswith(base_url) and 
                url not in self._crawled_urls and 
                len(self._crawled_urls) < self.MAX_URLS)

    def crawl(self, target_url: str, max_pages: int = 200) -> dict:
        """
        Crawl website and extract emails.
        
        Args:
            target_url: Starting URL to crawl
            max_pages: Maximum number of pages to crawl
        
        Returns:
            dict with emails, pages crawled, and stats
        """
        # Reset state
        self._found_emails = set()
        self._crawled_urls = set()
        self._total_pages = 0
        interrupted = False
        
        # Normalize target URL
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
        
        urls_to_crawl = deque([target_url])
        base_url = '{0.scheme}://{0.netloc}'.format(urllib.parse.urlsplit(target_url))
        
        console.print(f"\n[cyan]🎯 Starting crawl: {target_url}[/cyan]")
        console.print(f"[dim]Domain: {base_url} | Max pages: {max_pages}[/dim]")
        console.print("[dim]Press Ctrl+C to stop gracefully[/dim]\n")
        
        try:
            with Live(console=console, refresh_per_second=4) as live:
                display_text = "[cyan]🔍 Crawling in progress...[/cyan]\n"
                live.update(display_text)
                
                while urls_to_crawl and self._total_pages < max_pages:
                    current_url = urls_to_crawl.popleft()
                    self._crawled_urls.add(current_url)
                    self._total_pages += 1
                    
                    # Update display
                    display_text = f"[cyan]📄 Page {self._total_pages}: {current_url[:60]}...[/cyan]\n"
                    display_text += f"[dim]Found: {len(self._found_emails)} emails | Queued: {len(urls_to_crawl)} pages[/dim]\n"
                    display_text += "[dim]Press Ctrl+C to stop[/dim]"
                    live.update(display_text)
                    
                    # Random delay to be polite
                    time.sleep(random.uniform(*self.CRAWL_DELAY))
                    
                    headers = {"User-Agent": random.choice(self.USER_AGENTS)}
                    
                    try:
                        response = requests.get(current_url, headers=headers, timeout=10)
                        if "text/html" not in response.headers.get("Content-Type", ""):
                            continue
                    except requests.exceptions.RequestException:
                        continue
                    
                    # Extract emails
                    emails = self._extract_emails(response.text)
                    new_emails = emails - self._found_emails
                    for email in new_emails:
                        self._found_emails.add(email)
                        console.print(f"[green]  [+] Found: {email}[/green]")
                    
                    # Extract links for crawling
                    soup = BeautifulSoup(response.text, "html.parser")
                    base = '{0.scheme}://{0.netloc}'.format(urllib.parse.urlsplit(current_url))
                    
                    for a_tag in soup.find_all("a", href=True):
                        link = self._normalize_url(base, a_tag['href'])
                        if self._should_crawl(link, base_url):
                            urls_to_crawl.append(link)
                            
        except KeyboardInterrupt:
            interrupted = True
            console.print(f"\n[yellow]⚠ Crawl interrupted by user after {self._total_pages} pages[/yellow]")
        
        # Show results after completion or interruption
        console.print(f"\n[bold cyan]📊 Crawl Results:[/bold cyan]")
        console.print(f"  • Pages crawled: {self._total_pages}")
        console.print(f"  • Unique emails: {len(self._found_emails)}")
        
        if interrupted:
            console.print(f"[yellow]  • Status: INTERRUPTED (partial results)[/yellow]")
        else:
            console.print(f"[green]  • Status: COMPLETED[/green]")
        
        # Ask if user wants to see emails
        if self._found_emails and Confirm.ask("\n[bold cyan]Show collected emails?[/bold cyan]", default=True):
            for i, email in enumerate(sorted(self._found_emails), 1):
                console.print(f"  {i}. [green]{email}[/green]")
        
        # Ask if user wants to save results
        if self._found_emails and Confirm.ask("\n[bold yellow]Save results to file?[/bold yellow]", default=True):
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"/tmp/emails_{target_url.replace('https://', '').replace('http://', '').replace('/', '_')}_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write(f"# Email harvest from {target_url}\n")
                f.write(f"# Date: {datetime.now().isoformat()}\n")
                f.write(f"# Pages crawled: {self._total_pages}\n")
                f.write(f"# Total emails: {len(self._found_emails)}\n\n")
                for email in sorted(self._found_emails):
                    f.write(f"{email}\n")
            
            console.print(f"[green]✓ Saved to: {filename}[/green]")
        
        return {
            "success": True,
            "emails": sorted(list(self._found_emails)),
            "pages_crawled": self._total_pages,
            "unique_emails": len(self._found_emails),
            "target": target_url,
            "interrupted": interrupted
        }

    def build_command(self, **kwargs) -> str:
        """Build command (this tool runs in Python, not shell)."""
        return ""

    def run_direct(self, **kwargs) -> dict:
        """Direct execution for the crawler."""
        target = kwargs.get("target", "")
        max_pages = kwargs.get("max_pages", 200)
        
        if not target:
            console.print("[red]No target URL provided[/red]")
            return {"success": False, "error": "No target URL"}
        
        return self.crawl(target, max_pages)

    def parse(self, output: str) -> dict:
        """Parse output (for orchestrator compatibility)."""
        return {"success": True, "raw": output}