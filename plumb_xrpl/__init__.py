"""plumb-xrpl: XRP Ledger transactions and payments proven without trusting any server.

Servers are only a source of bytes. Every link is checked here: Ripple's validator list against the pinned publisher
key, a ledger signed by 80% of those validators, hash links back to the payment's ledger, the ledger's rebuilt
transaction tree, and the payment itself from those proven bytes. See `plumb_xrpl.prover`.
"""
from .prover import (Archive, HistoryError, PendingValidation, Source, XrplError, XrplHistory, envelope, judge,
                     parse_token, record)

__version__ = "0.1.0"
__all__ = ["Archive", "HistoryError", "PendingValidation", "Source", "XrplError", "XrplHistory", "envelope", "judge",
           "parse_token", "record", "__version__"]
