"""Chat detection and handling."""

import re
from typing import Optional

_ACTION_TOKENS = {
    "scan", "enumerate", "fuzz", "brute", "exploit", "crack",
    "nmap", "nikto", "ffuf", "gobuster", "whatweb", "sqlmap",
    "hydra", "dirb", "curl", "wget", "ping", "dig",
}

_GREETINGS = {
    "hi", "hello", "hey", "sup", "yo", "howdy",
    "good morning", "what's up", "how are you",
}

_CHAT_STARTS = (
    "what is", "what are", "what does", "how to",
    "how do", "why is", "can you", "tell me", "explain",
)

_TARGET_RE = re.compile(
    r"(\d{1,3}\.){3}\d{1,3}|https?://|\b\w+\.(com|net|org|io|dev)\b",
    re.IGNORECASE,
)


def is_chat(text: str) -> bool:
    """Return True if input is chat, False if action."""
    t = text.lower().strip()
    
    words = set(re.split(r"\W+", t))
    if words & _ACTION_TOKENS:
        return False
    
    if _TARGET_RE.search(t):
        return False
    
    if t in _GREETINGS or any(t.startswith(g + " ") for g in _GREETINGS):
        return True
    
    if any(t.startswith(p) for p in _CHAT_STARTS):
        return True
    
    if "?" in t and len(t.split()) < 10:
        return True
    
    return False


class ChatHandler:
    def __init__(self, ai_client, state, history):
        self._ai = ai_client
        self._state = state
        self._history = history
    
    def chat(self, question: str) -> str:
        """Handle chat question and return response."""
        response = self._ai.chat(
            messages=[{"role": "user", "content": question}],
            system="You are Kernox, an offensive security pentesting AI. Answer concisely with commands and exploitation techniques. Never suggest patching.",
            max_tokens=800,
        )
        return response