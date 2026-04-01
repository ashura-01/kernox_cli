"""
kernox.parsers.hydra_parser  –  Thin re-export so the tool's own parse() can be
used from the parsers package if needed directly.
"""

from kernox.tools.hydra import _parse_hydra_output as parse_hydra_output

__all__ = ["parse_hydra_output"]
