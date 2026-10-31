"""Content detectors that don't fit a single regex: secrets (named key formats
plus a high-entropy fallback) and PII (email, SSN, and Luhn-checked card numbers).

Each detector returns a list of Hits, so it plugs into the same pipeline as the
rule patterns.
"""
from __future__ import annotations

import math
import re
from collections import Counter

from .model import Hit


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Named secret formats — high confidence, so they block by default.
_NAMED_SECRETS = [
    ("secret.aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("secret.github_pat", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("secret.openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("secret.slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("secret.jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")),
    ("secret.private_key", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
]
_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{24,}")
_ENTROPY_THRESHOLD = 4.0

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")


def find_secrets(text: str) -> list:
    hits = []
    covered = []
    for rule_id, pat in _NAMED_SECRETS:
        for m in pat.finditer(text):
            hits.append(Hit(rule_id, "secret", "high", "block", m.start(), m.end(), m.group(0)))
            covered.append((m.start(), m.end()))
    # A high-entropy run that isn't already a named key — a likely secret.
    for m in _TOKEN.finditer(text):
        s, e = m.span()
        if any(s < ce and e > cs for cs, ce in covered):
            continue
        if shannon_entropy(m.group(0)) >= _ENTROPY_THRESHOLD:
            hits.append(Hit("secret.high_entropy", "secret", "medium", "flag", s, e, m.group(0)))
    return hits


def find_pii(text: str) -> list:
    hits = []
    for m in _EMAIL.finditer(text):
        hits.append(Hit("pii.email", "pii", "medium", "flag", m.start(), m.end(), m.group(0)))
    for m in _SSN.finditer(text):
        hits.append(Hit("pii.ssn", "pii", "high", "flag", m.start(), m.end(), m.group(0)))
    for m in _CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            hits.append(Hit("pii.card", "pii", "high", "flag", m.start(), m.end(), m.group(0)))
    return hits
