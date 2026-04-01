"""
kernox.parsers.zap_parser  –  Thin re-export so the tool's own parse() can be used
from the parsers package if needed directly.
"""

from kernox.tools.zapcli import _parse_zap_output as parse_zap_output

__all__ = ["parse_zap_output"]
