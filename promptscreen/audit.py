"""An append-only audit log and a keeper queue — both built so the record itself
can't leak what it was guarding."""
from __future__ import annotations

import hashlib
import json
import time


class AuditLog:
    """Append-only JSONL audit of screening decisions.

    By default it stores a sha256 of the content and the hit *locations* — never
    the raw text or the matched substrings — so the audit trail can't itself
    become the place a secret leaks. Pass ``log_content=True`` only when you know
    the traffic is safe to retain.
    """

    def __init__(self, path, log_content: bool = False):
        self.path = path
        self.log_content = log_content

    def record(self, verdict, text: str) -> dict:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "direction": verdict.direction,
            "decision": verdict.decision,
            "sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest(),
            "len": verdict.text_len,
            "hits": [h.to_dict(include_match=False) for h in verdict.hits],
        }
        if self.log_content:
            record["content"] = text
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        return record


class KeeperQueue:
    """Holds flagged items for human review.

    It stores the *redacted* text, so the queue is safe to read without
    re-exposing what was flagged. Optionally mirrors to a JSONL file.
    """

    def __init__(self, path=None):
        self.path = path
        self.items = []

    def add(self, verdict, text=None) -> dict:
        item = {
            "direction": verdict.direction,
            "decision": verdict.decision,
            "redacted": verdict.redacted,
            "hits": [h.to_dict(include_match=False) for h in verdict.hits],
        }
        self.items.append(item)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(item) + "\n")
        return item

    def pending(self) -> list:
        return list(self.items)
