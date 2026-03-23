"""
kernox.utils.url_helper  –  Safe URL handling utilities.

Ensures URLs are never incorrectly trimmed when passed to tools.
"""

from __future__ import annotations
import re


def clean_url(url: str) -> str:
    """Ensure URL has scheme, strip trailing slashes cleanly."""
    url = url.strip()
    if not url:
        return url
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    return url


def get_domain(url: str) -> str:
    """Extract just the domain/IP from a URL — no path trimming."""
    url = url.strip()
    # Remove scheme
    url = re.sub(r"^https?://", "", url)
    # Remove path but keep port
    domain = url.split("/")[0]
    return domain


def get_base_url(url: str) -> str:
    """Get scheme + domain + port only (no path)."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    # Match scheme + host + optional port
    m = re.match(r"(https?://[^/]+)", url)
    if m:
        return m.group(1)
    return url


def preserve_url(url: str) -> str:
    """
    Preserve the FULL URL including path — do NOT strip anything.
    Use this when the full URL path matters (e.g. login pages, specific endpoints).
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    return url


def is_ip(target: str) -> bool:
    """Return True if target looks like an IP address."""
    import ipaddress
    try:
        ipaddress.ip_address(target.split(":")[0])
        return True
    except ValueError:
        return False


def smart_target(target: str, needs_domain: bool = False) -> str:
    """
    Smart target handler:
    - If needs_domain=True (DNS tools): extract domain only
    - If it's an IP: return as-is
    - Otherwise: preserve full URL
    """
    target = target.strip()

    # Already an IP
    if is_ip(target):
        return target

    if needs_domain:
        return get_domain(target)

    # Web URL — preserve full path
    return preserve_url(target)
