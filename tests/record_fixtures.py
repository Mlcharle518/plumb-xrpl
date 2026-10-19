"""Record a real, fresh XRPL RLUSD payment and everything needed to prove it offline (tests/test_xrpl.py replays it).

  python tests/record_xrpl_fixtures.py     -> tests/fixtures/xrpl_bundle.json
"""
import base64
import json
from pathlib import Path

from plumb_xrpl import prover as X

MERCHANT = "rBi1QrVjwaNofisZAQnovoXdHkS73FG1tJ"   # receives RLUSD every few seconds: always a fresh payment to prove


class Recording(X.Source):
    def __init__(self):
        super().__init__()
        self.log = {"headers": {}, "ledgers": {}, "locate": {}, "manifests": {}, "proof": None}

    def header(self, index):
        raw = super().header(index)
        self.log["headers"][str(index)] = raw.hex()
        return raw

    def ledger_txs(self, index):
        pairs = super().ledger_txs(index)
        self.log["ledgers"][str(index)] = [[t.hex(), m.hex()] for t, m in pairs]
        return pairs

    def locate(self, tx_hash):
        i = super().locate(tx_hash)
        self.log["locate"][tx_hash] = i
        return i

    def unl_doc(self):
        self.log["unl_doc"] = super().unl_doc()
        return self.log["unl_doc"]

    def manifest(self, master_hex):
        raw = super().manifest(master_hex)
        if raw:
            self.log["manifests"][master_hex] = base64.b64encode(raw).decode()
        return raw

    def live_validations(self, min_index, unl, timeout_s=45):
        p = super().live_validations(min_index, unl, timeout_s)
        self.log["proof"] = p
        return p


def main():
    s = Recording()
    r = s.rpc("account_tx", {"account": MERCHANT, "limit": 10, "ledger_index_min": -1, "ledger_index_max": -1})
    t = next(t for t in r["transactions"] if (t.get("tx_json") or t.get("tx", {})).get("Destination") == MERCHANT)
    h = (t.get("hash") or (t.get("tx_json") or t["tx"]).get("hash")).upper()
    v = X.XrplHistory(s).verify_payment(h, MERCHANT, "RLUSD", 1)
    assert v["verdict"] == "paid", v
    out = {"payment": {"tx": h, "to": MERCHANT, "token": "RLUSD", "paid_raw": v["paid_raw"], "from": v["tx"]["from"],
                       "invoice_id": v["xrpl"]["invoice_id"], "ledger": v["tx"]["block_number"]}, **s.log}
    f = Path(__file__).parent / "fixtures" / "xrpl_bundle.json"
    f.write_text(json.dumps(out), encoding="utf-8")
    print(f"recorded {h} (ledger {v['tx']['block_number']}, proof ledger {s.log['proof']['ledger_index']}) -> {f}")


if __name__ == "__main__":
    main()
