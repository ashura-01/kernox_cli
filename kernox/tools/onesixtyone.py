"""kernox.tools.onesixtyone – SNMP community string enumeration."""
from __future__ import annotations
from rich.console import Console
from rich.prompt import Prompt, Confirm
console = Console()

COMMON_COMMUNITIES = ["public", "private", "manager", "admin", "cisco", "snmp", "community", "guest"]

class OnesixtyoneTool:
    name = "onesixtyone"

    def build_command(self, target: str, flags: str = "", **kwargs) -> str:
        import tempfile, os
        # Write common community strings to temp file
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="kernox_snmp_")
        tmp.write("\n".join(COMMON_COMMUNITIES))
        tmp.close()
        return f"onesixtyone -c {tmp.name} {target}"

    def parse(self, output: str) -> dict:
        import re
        communities = []
        found_re = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+\[(\S+)\]\s+(.+)")
        for m in found_re.finditer(output):
            communities.append({
                "ip": m.group(1),
                "community": m.group(2),
                "info": m.group(3).strip(),
            })
        return {
            "communities": communities,
            "total": len(communities),
            "raw": output,
        }
