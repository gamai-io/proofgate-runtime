"""Lite prompt-injection check (stdlib, lexical only).

This is the fast lexical layer, not the full gamai-guard embedding cascade.
Use it as a cheap pre-filter; for production-grade coverage use
https://github.com/gamai-io/gamai-guard.
"""
from __future__ import annotations

import re

HIGH = "high"
MED = "med"
LOW = "low"

_RULES = [
    ("instruction_override", HIGH,
     r"\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|prompts?)\b"),
    ("instruction_override", HIGH,
     r"\b(ignorisi|zanemari|zaboravi)\s+(sva\s+)?(prethodna\s+)?(uputstva|pravila|instrukcije)\b"),
    ("system_prompt", HIGH,
     r"\b(reveal|show|print|repeat|leak)\s+(the\s+)?(system|developer|hidden)\s+(prompt|message|instructions?)\b"),
    ("system_prompt", HIGH,
     r"\b(ispisi|prikazi|otkrij)\s+(sistem(ski)?\s+)?(prompt|uputstvo)\b"),
    ("jailbreak", HIGH, r"\b(jailbreak|developer\s+mode|dan\s+mode|do\s+anything\s+now)\b"),
    ("secret_exfiltration", HIGH,
     r"\b(print|show|dump|list|reveal)\s+(all\s+)?(env|environment|secrets?|tokens?|api\s*keys?)\b"),
    ("secret_exfiltration", HIGH,
     r"\b(ispisi|prikazi|izlistaj|daj)\s+(mi\s+)?(sve\s+)?(env|environment|varijabl|tajne|tokene|kljuceve)\b"),
    ("destructive", HIGH,
     r"\b(rm\s+-rf\s+[/~*]|mkfs|dd\s+if=.*of=/dev/|drop\s+(table|database)|truncate\s+table)\b"),
    ("destructive", HIGH,
     r"\b(obrisi|izbrisi)\s+(sve|bazu|disk|/var|logove)\b"),
    ("mass_mail", HIGH,
     r"\b(send|posalji)\s+(mail|email|poruku)\b.*\b(all|svim|sve)\b"),
    ("role_shift", MED,
     r"\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be|from\s+now\s+on\s+you)\b"),
    ("role_shift", MED,
     r"\b(ti\s+si\s+sada|ponasaj\s+se\s+kao|od\s+sada\s+si)\b"),
    ("tool_injection", MED,
     r"<\|?(tool|function)[_ ]?call\|?>|\"tool_calls\"\s*:|<\|im_start\|>"),
    ("encoded_payload", LOW,
     r"\b(base64|hex)\s*(decode|dekodiraj)\b.*\b(execute|run|izvrsi)\b"),
]

_COMPILED = [(cls, risk, re.compile(rx, re.I | re.S)) for cls, risk, rx in _RULES]
_ORDER = {"none": 0, LOW: 1, MED: 2, HIGH: 3}


def check_injection(text: str, tool: str | None = None) -> dict:
    """Return allow/block with the strongest matched class."""
    value = str(text or "")
    matches = []
    for cls, risk, rx in _COMPILED:
        m = rx.search(value)
        if m:
            matches.append({"class": cls, "risk": risk, "match": m.group(0)[:120]})
    risk = "none"
    for m in matches:
        if _ORDER[m["risk"]] > _ORDER[risk]:
            risk = m["risk"]
    allow = risk in ("none", LOW)
    return {
        "allow": allow,
        "risk": risk,
        "attack_class": matches[0]["class"] if matches else None,
        "reason": "no lexical match" if not matches else "matched %d pattern(s)" % len(matches),
        "matches": matches[:8],
        "tool": tool,
        "engine": "lexical-lite",
    }
