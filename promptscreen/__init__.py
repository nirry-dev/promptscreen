"""promptscreen — a guardrail for local LLM inputs and outputs.

Screen only your own traffic.
"""
from .audit import AuditLog, KeeperQueue
from .detectors import find_pii, find_secrets, luhn_ok, shannon_entropy
from .model import Hit, Rule, Verdict
from .rules import DEFAULT_RULES
from .screener import Screener

__version__ = "0.1.0"
__all__ = [
    "Screener",
    "Verdict",
    "Hit",
    "Rule",
    "DEFAULT_RULES",
    "find_secrets",
    "find_pii",
    "shannon_entropy",
    "luhn_ok",
    "AuditLog",
    "KeeperQueue",
    "__version__",
]
