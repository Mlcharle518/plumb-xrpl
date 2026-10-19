"""MCP server (stdio): the same proofs as the CLI, for agents. `plumb-xrpl serve` or `python -m plumb_xrpl.server`."""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import prover as X

mcp = FastMCP("plumb-xrpl")
_hist: X.XrplHistory | None = None


def hist() -> X.XrplHistory:
    global _hist
    if _hist is None:
        _hist = X.XrplHistory()
    return _hist


@mcp.tool()
def get_transaction(tx_hash: str) -> dict:
    """Any XRP Ledger transaction, proven (validator-list quorum -> hash links -> rebuilt transaction tree): its full
    decoded fields and metadata, including the ledger objects it created or changed (balances after the transaction,
    escrows, payment channels, credentials...). verified=false with a reason when it cannot be proven."""
    return X.envelope(lambda: hist().transaction(tx_hash))


@mcp.tool()
def verify_payment(tx_hash: str, recipient: str, token: str = "", min_amount_raw: str = "0", payer: str = "",
                   invoice: str = "") -> dict:
    """Did this payment happen? Verdict bound to recipient, token (XRP, RLUSD, or CURRENCY.rIssuer), minimum delivered
    amount (XRP drops or issued-currency millionths), optional payer and InvoiceID. Proven, never taken from a server."""
    return X.envelope(lambda: hist().verify_payment(tx_hash, recipient, token, int(min_amount_raw, 0), payer or None,
                                                    invoice or None))


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
