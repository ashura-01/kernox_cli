"""kernox.tools.wafw00f – WAF detection."""
from __future__ import annotations
from rich.console import Console
from rich.prompt import Prompt
from kernox.utils.url_helper import preserve_url
console = Console()

class Wafw00fTool:
    name = "wafw00f"

    def build_command(self, target: str, flags: str = "", **kwargs) -> str:
        target = preserve_url(target)
        return f"wafw00f {target} -a"

    def parse(self, output: str) -> dict:
        import re
        detected, waf_names = False, []
        waf_re = re.compile(r"is behind (.+?)(?:\s+WAF|\s*$)", re.IGNORECASE)
        no_waf_re = re.compile(r"No WAF detected", re.IGNORECASE)
        for m in waf_re.finditer(output):
            detected = True
            waf_names.append(m.group(1).strip())
        return {
            "detected": detected,
            "waf_names": waf_names,
            "raw": output,
        }
