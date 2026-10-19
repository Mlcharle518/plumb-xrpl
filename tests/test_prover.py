"""XRPL payments: a recorded real RLUSD payment proven offline, and a lie injected at every link of the chain of trust."""
import base64
import json
from pathlib import Path

import pytest

from plumb_xrpl import prover as X

B = json.loads((Path(__file__).parent / "fixtures" / "xrpl_bundle.json").read_text(encoding="utf-8"))
P = B["payment"]
NOW = B["proof"] and 1791643300   # a time inside the recorded validator list's validity


class Fake(X.Source):
    """Replays the recording. Mutators let a test make the 'servers' lie."""

    def __init__(self, **lies):
        super().__init__(rpcs=["x"], wss=["x"])
        self.lies = lies

    def rpc(self, method, params, tries=6):
        if method == "ledger" and params.get("ledger_index") == "validated":
            return {"ledger_index": self.lies.get("head", B["proof"]["ledger_index"])}
        raise AssertionError(f"unexpected rpc {method}")

    def header(self, index):
        raw = bytes.fromhex(B["headers"][str(index)])
        return self.lies["header"](index, raw) if "header" in self.lies else raw

    def ledger_txs(self, index):
        pairs = [(bytes.fromhex(t), bytes.fromhex(m)) for t, m in B["ledgers"][str(self.lies.get("serve_ledger", index))]]
        return self.lies["txs"](pairs) if "txs" in self.lies else pairs

    def locate(self, tx_hash):
        return self.lies["locate"](tx_hash) if "locate" in self.lies else B["locate"].get(tx_hash)

    def unl_doc(self):
        return self.lies["unl_doc"](json.loads(json.dumps(B["unl_doc"]))) if "unl_doc" in self.lies else B["unl_doc"]

    def manifest(self, master_hex):
        m = B["manifests"].get(master_hex)
        return base64.b64decode(m) if m else None

    def live_validations(self, min_index, unl, timeout_s=45):
        p = json.loads(json.dumps(B["proof"]))
        return self.lies["proof"](p) if "proof" in self.lies else p


@pytest.fixture(autouse=True)
def frozen_time(monkeypatch, tmp_path):
    monkeypatch.setattr(X.time, "time", lambda: NOW)
    global TMP
    TMP = tmp_path            # each test gets its own empty archive and validator-list cache


def run(source=None, archive=None, **kw):
    h = X.XrplHistory(source or Fake(), archive or X.Archive(TMP / "no-proofs.jsonl"), TMP / f"unl-{id(source)}.json")
    args = {"tx_hash": P["tx"], "recipient": P["to"], "token": "RLUSD", "min_raw": 1, **kw}
    return X.envelope(lambda: h.verify_payment(**args))


def test_a_real_payment_is_proven_offline():
    out = run(payer=P["from"], invoice=P["invoice_id"])
    v = out["value"]
    assert out["verified"] and v["verdict"] == "paid" and v["paid_raw"] == P["paid_raw"]
    assert v["xrpl"]["validators"] >= v["xrpl"]["quorum"] == 28 and v["xrpl"]["walked"] == B["proof"]["ledger_index"] - P["ledger"]
    assert v["tx"]["block_number"] == P["ledger"] and v["tx"]["final"] is True
    assert out["anchor"]["root"] == B["proof"]["ledger_hash"]
    assert (v["xrpl"]["type"], v["xrpl"]["result"]) == ("Payment", "tesSUCCESS") and isinstance(v["xrpl"]["flags"], int)


@pytest.mark.parametrize("kw,verdict", [
    ({"min_raw": 10 ** 9}, "underpaid"),
    ({"recipient": "rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY"}, "not_paid"),
    ({"token": "XRP"}, "not_paid"),
    ({"token": "RLUSD.rhub8VRN55s94qWKDv6jmDy1pUykJzF3wq"}, "not_paid"),       # same code, wrong issuer
    ({"payer": "rPEPPER7kfTD9w2To4CQk6UCfuHM9c6GDY"}, "not_paid"),
    ({"invoice": "00" * 32}, "not_paid"),
])
def test_the_payment_must_match_payee_currency_issuer_amount_payer_and_invoice(kw, verdict):
    assert run(**kw)["value"]["verdict"] == verdict


def flip(raw: bytes, at: int) -> bytes:
    return raw[:at] + bytes([raw[at] ^ 1]) + raw[at + 1:]


def test_a_tampered_header_anywhere_on_the_walk_is_refused():
    mid = P["ledger"] + 1
    out = run(Fake(header=lambda i, raw: flip(raw, 20) if i == mid else raw))
    assert not out["verified"] and "does not hash to the proven link" in out["reason"]


def test_tampered_transactions_or_metadata_do_not_match_the_proven_tree():
    def inflate(pairs):
        t, m = pairs[0]
        return [(t, flip(m, len(m) // 2))] + pairs[1:]
    out = run(Fake(txs=inflate))
    assert not out["verified"] and "do not match its proven header" in out["reason"]
    out = run(Fake(txs=lambda pairs: pairs[:-1]))                              # a server hides one transaction
    assert not out["verified"]


def test_a_server_pointing_at_the_wrong_ledger_is_caught():
    out = run(Fake(locate=lambda h: P["ledger"] + 1, serve_ledger=P["ledger"]))
    assert not out["verified"]


def test_one_signature_short_of_quorum_is_refused_and_forgeries_do_not_count():
    def drop_to(n):
        def f(p):
            unl = X.load_unl(B["unl_doc"]); X.refresh_rotations(unl, Fake())
            good = [v for v in p["validations"] if (X.check_validation(unl, v) or ("", "", 0))[1] == p["ledger_hash"]]
            p["validations"] = good[:n]
            return p
        return f
    out = run(Fake(proof=drop_to(27)))
    assert not out["verified"] and "need 28" in out["reason"]

    def forge(p):                                                              # flip a byte in every signature
        p["validations"] = [v[:-4] + ("00" if v[-4:-2] != "00" else "11") + v[-2:] for v in p["validations"]]
        return p
    assert not run(Fake(proof=forge))["verified"]

    def other_ledger(p):                                                       # real signatures, wrong ledger hash
        p["ledger_hash"] = "AB" * 32
        return p
    assert not run(Fake(proof=other_ledger))["verified"]


def test_the_validator_list_must_be_the_pinned_publishers_unexpired_and_untampered(monkeypatch):
    def add_validator(doc):
        b = json.loads(base64.b64decode(doc["blob"]))
        b["validators"].append(b["validators"][0])
        doc["blob"] = base64.b64encode(json.dumps(b).encode()).decode()
        return doc
    out = run(Fake(unl_doc=add_validator))
    assert not out["verified"] and "signature does not verify" in out["reason"]
    monkeypatch.setattr(X, "PUBLISHER_KEY", "ED" + "00" * 32)
    assert "not from the pinned publisher" in run()["reason"]
    monkeypatch.setattr(X, "PUBLISHER_KEY", "ED2677ABFFD1B33AC6FBC3062B71F1E8397C1505E1C42C64D11AD1B28FF73F4734")
    monkeypatch.setattr(X.time, "time", lambda: 2_000_000_000)                # after the list expired
    assert "expired" in run()["reason"]


def test_not_yet_validated_is_pending_never_not_paid():
    out = run(Fake(locate=lambda h: None))
    assert out["verified"] and out["value"]["verdict"] == "pending_validation" and out["value"]["retry_after_s"] > 0


def test_too_old_for_the_archive_and_the_walk_is_unverifiable(monkeypatch):
    monkeypatch.setattr(X, "MAX_WALK", 2)
    out = run()
    assert not out["verified"] and "older than the proof archive" in out["reason"]


def test_an_archived_proof_works_without_the_live_stream(tmp_path, monkeypatch):
    arc = X.Archive(tmp_path / "proofs.jsonl")
    arc.add({**B["proof"], "unl_sequence": 85, "at": NOW})

    class NoStream(Fake):
        def live_validations(self, *a, **k):
            raise AssertionError("the archive should have been used")
    out = run(NoStream(), arc)
    assert out["verified"] and out["value"]["verdict"] == "paid" and out["value"]["xrpl"]["from_archive"] is True


def test_node_public_key_encoding():
    # the validator list's first master key, as rippled's manifest RPC expects it (base58, 'n' prefix)
    assert X.node_public_b58(PUB := B["unl_doc"]["public_key"]).startswith("n") and len(X.node_public_b58(PUB)) > 40


def test_the_unl_cache_saves_fetching_never_checking(tmp_path):
    cache = tmp_path / "unl.json"
    unl = X.cached_unl(Fake(), cache, NOW)
    assert len(unl.masters) == 35 and cache.exists()

    class Offline(Fake):
        def unl_doc(self):
            raise AssertionError("cached: no fetch")
    assert X.cached_unl(Offline(), cache, NOW + 60).quorum == 28
    c = json.loads(cache.read_text())
    b = json.loads(base64.b64decode(c["doc"]["blob"])); b["validators"].append(b["validators"][0])
    c["doc"]["blob"] = base64.b64encode(json.dumps(b).encode()).decode()
    cache.write_text(json.dumps(c))                                           # someone edits the cache
    assert len(X.cached_unl(Fake(), cache, NOW + 120).masters) == 35          # refused, refetched and re-verified


def test_the_live_stream_works_from_inside_a_running_event_loop(monkeypatch):
    """`plumb serve` (MCP) calls tools inside its event loop; asyncio.run() there used to fail every XRPL check."""
    import asyncio

    class Stream(Fake):
        live_validations = X.Source.live_validations      # the real method, over a fake websocket

    class FakeWS:
        def __init__(self):
            self.msgs = [json.dumps({"type": "validationReceived", "ledger_index": B["proof"]["ledger_index"],
                                     "ledger_hash": B["proof"]["ledger_hash"], "data": v}) for v in B["proof"]["validations"]]

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def send(self, m):
            pass

        async def recv(self):
            return self.msgs.pop(0) if self.msgs else json.dumps({"type": "ledgerClosed"})
    import websockets
    monkeypatch.setattr(websockets, "connect", lambda *a, **k: FakeWS())

    async def inside():
        return run(Stream())
    out = asyncio.run(inside())
    assert out["verified"] and out["value"]["verdict"] == "paid"


def test_any_transaction_is_proven_with_its_full_fields_and_metadata():
    h = X.XrplHistory(Fake(), X.Archive(TMP / "none.jsonl"), TMP / "unl.json")
    out = X.envelope(lambda: h.transaction(P["tx"]))
    t = out["value"]["tx"]
    assert out["verified"] and t["type"] == "Payment" and t["result"] == "tesSUCCESS" and t["block_number"] == P["ledger"]
    assert t["fields"]["Destination"] == P["to"] and "AffectedNodes" in t["meta"]
    assert out["value"]["xrpl"]["validators"] >= 28
    bad = X.XrplHistory(Fake(txs=lambda pairs: pairs[:-1]), X.Archive(TMP / "none.jsonl"), TMP / "unl2.json")
    assert not X.envelope(lambda: bad.transaction(P["tx"]))["verified"]



def test_a_server_without_the_new_ledger_yet_means_retry_not_a_crash(monkeypatch):
    calls = []

    class Lagging(X.Source):
        def rpc(self, method, params, tries=6):
            calls.append(params)
            if len(calls) < 3:
                return {"error": "lgrNotFound", "status": "error"}           # the first servers lag behind
            return {"ledger": {"ledger_data": B["headers"][str(params["ledger_index"])]}}
    monkeypatch.setattr(X.time, "sleep", lambda s: None)
    src = Lagging(rpcs=["a", "b", "c"], wss=["x"])
    assert src.header(P["ledger"]) == bytes.fromhex(B["headers"][str(P["ledger"])])

    class Never(X.Source):
        def rpc(self, method, params, tries=6):
            return {"error": "lgrNotFound", "status": "error"}
    with pytest.raises(X.PendingValidation):
        Never(rpcs=["a", "b"], wss=["x"]).header(P["ledger"])
