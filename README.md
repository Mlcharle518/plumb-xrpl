# plumb-xrpl

XRP Ledger transactions and payments **proven without trusting any server**. Servers are only a source of bytes;
every link of the chain of trust is checked on your machine:

1. **Ripple's validator list** (vl.ripple.com): the publisher's manifest must be signed by the pinned publisher master
   key, the list by the publisher's signing key, and every validator's manifest by its own master key. An expired list
   is refused. Validators that rotated their signing key are refreshed with a newer manifest signed by the same master key.
2. **A ledger signed by a quorum (80%)** of those validators: each validation's signature is checked against the
   validator's current signing key, over the validation's own bytes.
3. **Hash links** from that ledger back to the transaction's ledger: every header carries its parent's hash, and each
   header's hash is recomputed here (SHA-512Half over `LWR\0` + header).
4. **The ledger's transaction tree**, rebuilt from every transaction and its metadata (SHAMap) and compared with the
   header's transaction root.
5. **The payment itself**, from those proven bytes: a successful Payment, to the payee, of the right currency (issuer
   included), the *delivered* amount (never the requested `Amount`) at least the minimum, optionally from one payer and
   carrying one InvoiceID.

A lie at any link is caught by the tests (`tests/test_prover.py`): wrong publisher key, forged validation, broken
hash link, tampered transaction, wrong recipient, underpayment, partial payment, wrong invoice.

This is the XRPL prover of the [Plumb Data Exchange](https://numba2witcheese.tail7d8d44.ts.net:10000/llms.txt), where
it has proven live RLUSD, XRP, payment-channel, escrow and batch payments on mainnet since October 2026. It is published
so any seller, agent or wallet can hold a payment to the same standard.

## Install

```
pip install plumb-xrpl            # library + CLI
pip install "plumb-xrpl[mcp]"     # + the MCP server for agents
```

Python 3.11+. Dependencies: `xrpl-py` (byte codecs only; every hash and signature is checked here), `coincurve`
(secp256k1), `cryptography` (ed25519), `websockets`.

## Command line

```
plumb-xrpl tx  71100808DD3DF3EA693471FA...                       # any transaction, proven: fields + metadata
plumb-xrpl pay 71100808... r9Y5...P2d --token RLUSD --min 50000   # was at least 0.05 RLUSD delivered to this account?
plumb-xrpl pay 3A3915B2... rXXX --invoice C08EC114...             # ...and does the payment carry this InvoiceID?
plumb-xrpl record                                                 # keep quorum proofs (see "How old can a payment be?")
plumb-xrpl serve                                                  # MCP server over stdio (extra: plumb-xrpl[mcp])
```

Output is JSON in one envelope shape:

```json
{"verified": true,
 "value": {"verdict": "paid", "paid_raw": "50000", "reason": "...",
           "tx": {"tx_hash": "...", "block_number": 100000000, "block_hash": "...", "final": true, "...": "..."},
           "xrpl": {"level": "unl_quorum", "validators": 28, "of": 35, "quorum": 28, "proof_ledger": 100000120,
                    "walked": 120, "from_archive": false, "delivered": "...", "invoice_id": "..."}},
 "anchor": {"root": "<hash of the quorum-signed ledger>", "source": "XRPL validator list (vl.ripple.com seq N, pinned publisher ...): 28/35 validator signatures on ledger ..., 120 hash links back"}}
```

`verified: false` always comes with a `reason` and never a guess. A transaction the servers do not yet report in a
validated ledger is `verdict: pending_validation` with `retry_after_s`.

Amounts are raw integers: XRP in **drops**, issued currencies (RLUSD, ...) in **millionths** (value x 10^6, rounded
down). Tokens: `XRP` (default), `RLUSD`, or `CURRENCY.rIssuer`.

## Library

```python
from plumb_xrpl import XrplHistory, envelope

h = XrplHistory()
proof = h.verify_payment(tx_hash, recipient="r9Y5...P2d", token="RLUSD", min_raw=50_000, invoice=None)
# proof["verdict"] in {"paid", "not_paid", "underpaid", "failed_transaction", ...}; proof["xrpl"]["validators"] etc.

tx = h.transaction(tx_hash)          # any transaction type, decoded fields + metadata, proven
out = envelope(lambda: h.transaction(tx_hash))   # the CLI's {"verified": ..., "value": ..., "anchor": ...} shape
```

What a proven *transaction* gives you beyond payments: the metadata's `AffectedNodes` carry the final fields of every
ledger object the transaction created or changed, so the state **as of that transaction** is proven too: account
balances after it, a trust line, an escrow or payment channel it created, a credential it issued.

## MCP server

`plumb-xrpl serve` exposes two tools over stdio: `get_transaction(tx_hash)` and
`verify_payment(tx_hash, recipient, token="", min_amount_raw="0", payer="", invoice="")`. Same envelope as the CLI.

## How old can a payment be?

Validator signatures exist only live; rippled servers do not keep them. So a quorum proof comes from one of two places:

- **the live stream**: for a fresh payment, walk back from a ledger being validated now (up to `MAX_WALK` ledgers);
- **the proof archive**: `plumb-xrpl record` keeps one quorum-signed ledger per 256 ledgers (about every 16 minutes)
  in `~/.verified-reads/xrpl-proofs.jsonl` (override with `VR_XRPL_ARCHIVE`). Any older payment is then proven by hash
  links from the nearest archived proof. Run it as a service if you need to prove payments older than a few hours.

A payment older than both is reported **unverifiable**, never guessed. The validator list is cached at
`~/.verified-reads/xrpl-unl.json` (`VR_XRPL_UNL_CACHE`) and refreshed hourly.

## What this does not do

- It proves **transactions**, not the current state tree. "Current balance of account X" needs the full account-state
  SHAMap, which no public server proves. Balances are proven as of a transaction (see Library).
- It does not submit or sign anything. Keys never enter this package.
- It trusts Ripple's **validator list publisher key**, pinned in the source, and the 80% quorum rule of the XRP Ledger.
  That is the same trust assumption as a rippled node you run yourself, without running one.

## Development

```
pip install -e ".[test,mcp]"
python -m pytest -q
```

Fixtures are real mainnet bytes recorded with `tests/record_fixtures.py`; the tests replay them through a fake source
and then tamper with each link.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.
