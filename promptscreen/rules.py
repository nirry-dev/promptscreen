"""The built-in rule set: regex patterns for prompt-injection and prompt-leak
heuristics. These are advisory signals — most flag, a high-confidence few block.
Pass your own list to ``Screener`` to extend or replace them.
"""
from __future__ import annotations

import re

from .model import Rule


def _rule(rule_id, category, severity, action, direction, pattern, description=""):
    return Rule(rule_id, category, severity, action, direction, re.compile(pattern, re.I), description)


DEFAULT_RULES = [
    _rule(
        "injection.ignore_previous", "injection", "medium", "flag", "input",
        r"\bignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+"
        r"(?:instructions?|prompts?|messages?|context)\b",
        "Tries to discard earlier instructions",
    ),
    _rule(
        "injection.disregard_rules", "injection", "medium", "flag", "input",
        r"\bdisregard\s+(?:your|the|all)\s+(?:system\s+prompt|instructions?|rules?|guidelines?)\b",
        "Tries to discard the system prompt or rules",
    ),
    _rule(
        "injection.reveal_prompt", "injection", "medium", "flag", "both",
        r"\b(?:reveal|show|print|repeat|tell\s+me)\s+(?:your|the)\s+"
        r"(?:system\s+prompt|initial\s+prompt|instructions?)\b",
        "Tries to exfiltrate the system prompt",
    ),
    _rule(
        "injection.role_override", "injection", "medium", "flag", "input",
        r"\byou\s+are\s+now\s+(?:a|an|the)\b|\bpretend\s+(?:that\s+)?you(?:'re|\s+are)\b",
        "Tries to override the assistant's role",
    ),
    _rule(
        "injection.jailbreak", "injection", "medium", "flag", "input",
        r"\b(?:developer\s+mode|jailbreak|DAN\s+mode|do\s+anything\s+now)\b",
        "Named jailbreak marker",
    ),
    _rule(
        "injection.control_tokens", "injection", "high", "block", "input",
        r"<\|im_start\|>\s*system|<<SYS>>|\[/?INST\]|```+\s*system\b",
        "Chat control tokens / delimiter injection in user text",
    ),
    _rule(
        "leak.system_preamble", "injection", "medium", "flag", "output",
        r"\bmy\s+(?:system\s+prompt|instructions)\s+(?:is|are|says?)\b|\bI\s+was\s+instructed\s+to\b",
        "Output appears to be echoing its own instructions",
    ),
]
