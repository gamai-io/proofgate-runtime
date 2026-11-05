#!/usr/bin/env python3
"""ProofGate Runtime CLI (stdlib only)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .claims import check, demo
from .guard import check_injection
from .receipts import make_receipt, verify_receipt


def _load(path: str):
    if path == "-":
        return json.load(sys.stdin)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _key(path: str | None) -> bytes | None:
    if not path:
        return None
    return Path(path).read_bytes().strip()


def _print(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="proofgate",
                                 description="Evidence-first claim verification and signed receipts")
    ap.add_argument("--version", action="version", version="proofgate-runtime " + __version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("verify-claims", help="verify a claims JSON file")
    c.add_argument("file", help="JSON file with a list of claims, or - for stdin")
    c.add_argument("--reported-hash", default=None)

    m = sub.add_parser("make-receipt", help="create a receipt from intent/result JSON files")
    m.add_argument("intent")
    m.add_argument("result")
    m.add_argument("--key-file", default=None, help="HMAC key file (required unless --allow-unsigned)")
    m.add_argument("--allow-unsigned", action="store_true", help="create an unsigned receipt (not recommended)")

    v = sub.add_parser("verify-receipt", help="verify a receipt JSON file")
    v.add_argument("receipt")
    v.add_argument("--key-file", default=None)
    v.add_argument("--allow-unsigned", action="store_true", help="accept an unsigned receipt")

    g = sub.add_parser("check-injection", help="lexical prompt-injection pre-filter")
    g.add_argument("text")
    g.add_argument("--tool", default=None)

    sub.add_parser("demo", help="run the built-in proofgate demo")

    args = ap.parse_args(argv)
    if args.cmd == "verify-claims":
        data = _load(args.file)
        claims = data.get("claims") if isinstance(data, dict) else data
        _print(check(claims or [], args.reported_hash))
        return 0
    if args.cmd == "make-receipt":
        key = _key(args.key_file)
        if key is None and not args.allow_unsigned:
            print("refusing unsigned receipt: pass --key-file or --allow-unsigned", file=sys.stderr)
            return 2
        _print(make_receipt(_load(args.intent), _load(args.result), key=key))
        return 0
    if args.cmd == "verify-receipt":
        res = verify_receipt(_load(args.receipt), key=_key(args.key_file),
                             require_signature=not args.allow_unsigned)
        _print(res)
        return 0 if res["valid"] else 1
    if args.cmd == "check-injection":
        _print(check_injection(args.text, args.tool))
        return 0
    if args.cmd == "demo":
        _print(demo())
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
