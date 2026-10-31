"""Core types: a Rule, a Hit, a Verdict — plus the decision and redaction logic.

A screen never silently changes text. It returns a Verdict: a decision
(allow / flag / block) and the list of Hits that explain it, each with the rule
that fired and the span it matched. Redaction produces a *copy*; the original is
left intact for the caller to decide about.
"""
from __future__ import annotations

from dataclasses import dataclass

_SEVERITY = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Rule:
    id: str
    category: str
    severity: str
    action: str        # "flag" | "block"
    direction: str     # "input" | "output" | "both"
    pattern: object    # compiled regex
    description: str = ""


@dataclass
class Hit:
    rule: str
    category: str      # "injection" | "secret" | "pii"
    severity: str
    action: str
    start: int
    end: int
    match: str

    def to_dict(self, include_match: bool = False) -> dict:
        d = {
            "rule": self.rule,
            "category": self.category,
            "severity": self.severity,
            "action": self.action,
            "start": self.start,
            "end": self.end,
        }
        if include_match:
            d["match"] = self.match
        return d


@dataclass
class Verdict:
    direction: str
    decision: str      # "allow" | "flag" | "block"
    hits: list
    redacted: str
    text_len: int

    @property
    def blocked(self) -> bool:
        return self.decision == "block"

    @property
    def flagged(self) -> bool:
        return self.decision == "flag"

    def to_dict(self, include_match: bool = False) -> dict:
        return {
            "direction": self.direction,
            "decision": self.decision,
            "text_len": self.text_len,
            "hits": [h.to_dict(include_match) for h in self.hits],
            "redacted": self.redacted,
        }


def decide(hits) -> str:
    """block if anything demands it, flag if anything matched at all, else allow."""
    if any(h.action == "block" for h in hits):
        return "block"
    if hits:
        return "flag"
    return "allow"


def redact_text(text: str, hits) -> str:
    """Return a copy with every hit span replaced by ``[category]``.

    Overlapping or touching spans are merged and labelled by the
    highest-severity category among them.
    """
    if not hits:
        return text
    spans = sorted((h.start, h.end, h.category, h.severity) for h in hits)
    merged = []
    for start, end, cat, sev in spans:
        if merged and start <= merged[-1][1]:
            pstart, pend, pcat, psev = merged[-1]
            if _SEVERITY[sev] > _SEVERITY[psev]:
                pcat, psev = cat, sev
            merged[-1] = (pstart, max(pend, end), pcat, psev)
        else:
            merged.append((start, end, cat, sev))
    out = []
    last = 0
    for start, end, cat, _sev in merged:
        if start > last:
            out.append(text[last:start])
        out.append(f"[{cat}]")
        last = end
    out.append(text[last:])
    return "".join(out)
