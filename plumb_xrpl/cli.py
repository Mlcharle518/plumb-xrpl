"""Command line: `plumb-xrpl tx|pay|record|serve`. Output is JSON in Plumb's envelope shape:
{"verified": true, "value": ..., "anchor": {...}} or {"verified": false, "reason": "..."}."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from . import prover as X


def _print(o: object) -> None:
    print(json.dumps(o, indent=2, default=str))


def cmd_tx(a: argparse.Namespace) -> None:
    _print(X.envelope(lambda: X.XrplHistory().transaction(a.hash)))


def cmd_pay(a: argparse.Namespace) -> None:
    _print(X.envelope(lambda: X.XrplHistory().verify_payment(a.hash, a.recipient, a.token, a.min, a.payer or None,
                                                             a.invoice or None)))


def cmd_record(a: argparse.Namespace) -> None:
    print(f"recording XRPL validator-quorum proofs every {a.every} ledgers to {X.Archive().path} (Ctrl+C to stop)",
          flush=True)
    X.record(every=a.every)


def cmd_serve(_a: argparse.Namespace) -> None:
    try:
        from .server import main as serve
    except ImportError as e:  # the MCP server is an extra
        sys.exit(f"the MCP server needs the extra: pip install plumb-xrpl[mcp] ({e})")
    serve()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="plumb-xrpl",
                                 description="XRP Ledger transactions and payments proven without trusting any server.")
    ap.add_argument("--version", action="version", version=f"plumb-xrpl {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("tx", help="any transaction, proven: full fields + metadata")
    p.add_argument("hash")
    p.set_defaults(fn=cmd_tx)
    p = sub.add_parser("pay", help="was this payment made? verdict bound to recipient, token, minimum, payer, invoice")
    p.add_argument("hash")
    p.add_argument("recipient")
    p.add_argument("--token", default="", help="XRP (default), RLUSD, or CURRENCY.rIssuer")
    p.add_argument("--min", type=int, default=0, help="minimum delivered amount: XRP drops or issued millionths")
    p.add_argument("--from", dest="payer", default="", help="count only a payment from this account")
    p.add_argument("--invoice", default="", help="the payment InvoiceID must equal this (64 hex)")
    p.set_defaults(fn=cmd_pay)
    p = sub.add_parser("record", help="keep validator-quorum proofs so payments older than the live stream stay provable")
    p.add_argument("--every", type=int, default=X.ARCHIVE_EVERY)
    p.set_defaults(fn=cmd_record)
    sub.add_parser("serve", help="MCP server over stdio (extra: plumb-xrpl[mcp])").set_defaults(fn=cmd_serve)
    a = ap.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
