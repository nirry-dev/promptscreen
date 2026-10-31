"""The Screener: run the rule patterns and detectors over a piece of text in a
given direction, and return a Verdict. Input and output go through the *same*
pipeline — only which rules apply differs (a rule's ``direction``)."""
from __future__ import annotations

from .detectors import find_pii, find_secrets
from .model import Hit, Verdict, decide, redact_text
from .rules import DEFAULT_RULES


class Screener:
    def __init__(self, rules=None, detect=True, audit=None, keeper=None, redact=True):
        self.rules = DEFAULT_RULES if rules is None else rules
        self.detect = detect
        self.audit = audit       # an AuditLog, or None
        self.keeper = keeper     # a KeeperQueue, or None
        self.redact = redact

    def screen(self, text: str, direction: str = "input") -> Verdict:
        hits = []
        for rule in self.rules:
            if rule.direction in (direction, "both"):
                for m in rule.pattern.finditer(text):
                    hits.append(
                        Hit(rule.id, rule.category, rule.severity, rule.action,
                            m.start(), m.end(), m.group(0))
                    )
        if self.detect:
            hits.extend(find_secrets(text))
            hits.extend(find_pii(text))

        hits.sort(key=lambda h: (h.start, h.end))
        decision = decide(hits)
        redacted = redact_text(text, hits) if self.redact else text
        verdict = Verdict(direction, decision, hits, redacted, len(text))

        if self.audit is not None:
            self.audit.record(verdict, text)
        if self.keeper is not None and decision == "flag":
            self.keeper.add(verdict, text)
        return verdict

    def input(self, text: str) -> Verdict:
        return self.screen(text, "input")

    def output(self, text: str) -> Verdict:
        return self.screen(text, "output")
