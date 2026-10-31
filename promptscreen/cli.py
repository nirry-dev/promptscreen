"""Command-line interface: ``promptscreen check <text>`` and ``promptscreen rules``."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .audit import AuditLog, KeeperQueue
from .rules import DEFAULT_RULES
from .screener import Screener


def _read_text(args) -> str:
    if args.text is not None:
        return args.text
    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as f:
            return f.read()
    return sys.stdin.read()


def _cmd_check(args) -> int:
    audit = AuditLog(args.audit, log_content=args.log_content) if args.audit else None
    keeper = KeeperQueue(args.keep) if args.keep else None
    screener = Screener(audit=audit, keeper=keeper, redact=not args.no_redact)

    direction = "output" if args.output else "input"
    text = _read_text(args)
    verdict = screener.screen(text, direction)

    if args.json:
        print(json.dumps(verdict.to_dict(include_match=args.show_matches), indent=2))
    else:
        print(f"decision: {verdict.decision.upper()}  ({direction}, {len(verdict.hits)} hit(s))")
        for h in verdict.hits:
            fragment = text[h.start:h.end].replace("\n", " ")
            print(f"  [{h.severity:<6}] {h.rule:<26} {h.action:<5} \"{fragment[:48]}\"")
        if not args.no_redact and verdict.hits:
            print("\nredacted:\n" + verdict.redacted)

    blocked = verdict.decision == "block" or (args.strict and verdict.decision == "flag")
    return 1 if blocked else 0


def _cmd_rules(_args) -> int:
    for r in DEFAULT_RULES:
        print(f"  {r.id:<28} {r.category:<10} {r.severity:<6} {r.action:<5} {r.direction:<6} {r.description}")
    print("  + detectors: secrets (named key formats + high-entropy), PII (email, SSN, card via Luhn)")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="promptscreen",
        description="Screen LLM inputs and outputs against rules and detectors, with "
                    "redaction, an audit log, and a keeper queue. Screen only your own traffic.",
    )
    parser.add_argument("--version", action="version", version=f"promptscreen {__version__}")
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check", help="screen a piece of text")
    check.add_argument("text", nargs="?", help="text to screen (or use -f / stdin)")
    check.add_argument("-f", "--file", help="read the text from a file")
    direction = check.add_mutually_exclusive_group()
    direction.add_argument("--input", action="store_true", help="screen as model input (default)")
    direction.add_argument("--output", action="store_true", help="screen as model output")
    check.add_argument("--json", action="store_true", help="emit the verdict as JSON")
    check.add_argument("--show-matches", action="store_true", help="with --json, include the matched text")
    check.add_argument("--no-redact", action="store_true", help="don't compute the redacted copy")
    check.add_argument("--strict", action="store_true", help="exit non-zero on flag, not only on block")
    check.add_argument("--audit", metavar="PATH", help="append a JSONL audit record")
    check.add_argument("--log-content", action="store_true",
                       help="store raw content in the audit log (default: hash only)")
    check.add_argument("--keep", metavar="PATH", help="append flagged items to a keeper-queue JSONL")

    sub.add_parser("rules", help="list the built-in rules and detectors")

    args = parser.parse_args(argv)
    if args.command == "check":
        return _cmd_check(args)
    if args.command == "rules":
        return _cmd_rules(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
