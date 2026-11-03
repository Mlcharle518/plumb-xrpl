"""Archived XRPL proofs are checked against the validator list IN FORCE when they were signed, not today's.

Real bytes: vl.ripple.com list seq 85 and seq 86 (Ripple replaced one validator on 2026-10-28) and the last proof the
recorder kept under seq 85 (ledger 107970048, 28/35 signatures). Checked against seq 86 it has 27/35, one short of the
quorum: every archived proof from before the rotation failed that way.
"""
import base64
import json
from pathlib import Path

import pytest

from plumb_xrpl import prover as X

R = json.loads((Path(__file__).parent / "fixtures" / "xrpl_rotation.json").read_text(encoding="utf-8"))
PROOF = R["proof"]
TOP = PROOF["ledger_index"]
NOW = 1793720000            # 2026-11-03: the current list is seq 86


def unl_of(seq):
    c = R["lists"][seq]
    u = X.load_unl(c["doc"], NOW)
    X.refresh_rotations(u, None, {m: base64.b64decode(r) for m, r in c["manifests"].items()})
    return u


class Fake(X.Source):
    """Today's servers: they serve list seq 86 and the proof ledger's real header."""

    def __init__(self, current="86"):
        super().__init__(rpcs=["x"], wss=["x"])
        self.current = R["lists"][current]

    def rpc(self, method, params, tries=6):
        raise AssertionError(f"unexpected rpc {method}")

    def header(self, index):
        assert index == TOP
        return bytes.fromhex(R["header"])

    def unl_doc(self):
        return self.current["doc"]

    def manifest(self, master_hex):
        m = self.current["manifests"].get(master_hex)
        return base64.b64decode(m) if m else None

    def live_validations(self, *a, **k):
        raise AssertionError("an archived proof must not need the live stream")


@pytest.fixture(autouse=True)
def frozen(monkeypatch):
    monkeypatch.setattr(X.time, "time", lambda: NOW)


def cachefile(tmp_path, seq, mutate=None):
    c = json.loads(json.dumps(R["lists"][seq]))
    if mutate:
        mutate(c)
    p = tmp_path / f"cache-{seq}.json"
    p.write_text(json.dumps(c), encoding="utf-8")
    return p


def archive(tmp_path, proof=None, lists=("85", "86")):
    arc = X.Archive(tmp_path / "proofs.jsonl")
    arc.add(proof or PROOF)
    for s in lists:
        arc.lists.adopt(cachefile(tmp_path, s))
    return arc


def prove(arc, source=None):
    h = X.XrplHistory(source or Fake(), arc, arc.path.parent / "unl-cache.json")
    return h.proven_header(TOP)


def test_the_real_85_to_86_rotation_fails_on_todays_list_and_passes_on_the_list_in_force(tmp_path):
    assert len(X.quorum_of(unl_of("86"), PROOF["validations"], PROOF["ledger_hash"])) == 27      # the bug: 27 < 28
    assert len(X.quorum_of(unl_of("85"), PROOF["validations"], PROOF["ledger_hash"])) == 28
    assert "vl_seq" not in PROOF and PROOF["unl_sequence"] == 85                                # a pre-fix archive line
    h, how = prove(archive(tmp_path))
    assert h.hash == PROOF["ledger_hash"].upper() and how["from_archive"] is True
    assert (how["vl_seq"], how["unl_sequence"], how["validators"], how["quorum"]) == (85, 85, 28, 28)
    assert how["vl_checked_at"] == X.parse_header(bytes.fromhex(R["header"])).close_time


def test_the_answer_names_the_list_in_force(tmp_path):
    arc = archive(tmp_path)

    class Tx(Fake):                               # walk 0: prove the proof ledger itself through the envelope
        pass
    h = X.XrplHistory(Tx(), arc, tmp_path / "u.json")
    out = X.envelope(lambda: {"xrpl": h.proven_header(TOP)[1]})
    assert out["verified"] and "seq 85, in force when the archived proof ledger closed" in out["anchor"]["source"]


def test_the_list_is_checked_as_of_the_ledger_close_not_now(tmp_path, monkeypatch):
    arc = archive(tmp_path)
    monkeypatch.setattr(X.time, "time", lambda: 2_000_000_000)        # both lists have expired by now
    _, how = prove(arc)
    assert how["vl_seq"] == 85 and how["validators"] == 28


def test_without_the_old_list_the_proof_is_refused_never_checked_on_todays_list(tmp_path):
    arc = archive(tmp_path, lists=())
    with pytest.raises(X.XrplError, match="seq 85, which is not held"):
        prove(arc)
    assert X.Archive(arc.path).lists.sequences() == [86]               # today's list was kept, but cannot stand in


def test_a_forged_historical_list_is_never_stored_and_never_used(tmp_path, monkeypatch):
    def add_validator(c):
        b = json.loads(base64.b64decode(c["doc"]["blob"]))
        b["validators"].append(b["validators"][0])
        c["doc"]["blob"] = base64.b64encode(json.dumps(b).encode()).decode()
    arc = archive(tmp_path, lists=("86",))
    with pytest.raises(X.XrplError, match="signature does not verify"):
        arc.lists.adopt(cachefile(tmp_path, "85", add_validator))
    assert 85 not in arc.lists.sequences()
    rep = X.adopt_lists(arc, [cachefile(tmp_path, "85", add_validator)])
    assert rep["adopt"][0]["adopted"] is False and "NOT HELD" in rep["by_list"]["85"]["list"]

    arc.lists.adopt(cachefile(tmp_path, "85"))                         # someone edits the stored file afterwards
    f = arc.lists.root / "85.json"
    c = json.loads(f.read_text()); add_validator(c); f.write_text(json.dumps(c))
    with pytest.raises(X.XrplError, match="signature does not verify"):
        prove(arc)

    monkeypatch.setattr(X, "PUBLISHER_KEY", "ED" + "00" * 32)          # a list from anyone but the pinned publisher
    with pytest.raises(X.XrplError, match="not from the pinned publisher"):
        X.ListLibrary(tmp_path / "other").adopt(cachefile(tmp_path, "85"))


def shift_close(monkeypatch, to):
    real = X.parse_header

    def parse(raw):
        h = real(raw)
        h.close_time = to
        return h
    monkeypatch.setattr(X, "parse_header", parse)


def test_a_list_that_had_expired_when_the_ledger_closed_is_refused(tmp_path, monkeypatch):
    exp = json.loads(base64.b64decode(R["lists"]["85"]["doc"]["blob"]))["expiration"] + X.RIPPLE_EPOCH
    arc = archive(tmp_path, lists=("85",))
    shift_close(monkeypatch, exp + 1)
    with pytest.raises(X.XrplError, match="seq 85 was not valid when ledger .* closed: validator list has expired"):
        prove(arc)


def test_a_list_already_replaced_when_the_ledger_closed_is_refused(tmp_path, monkeypatch):
    arc = archive(tmp_path)
    seen86 = arc.lists.get(86)["first_seen"]
    shift_close(monkeypatch, int(seen86 + X.SUPERSEDE_GRACE_S + 60))     # 85 not expired yet, but 86 had replaced it
    with pytest.raises(X.XrplError, match="seq 85 was no longer in force .* seq 86 had replaced it"):
        prove(arc)


def test_validations_claimed_under_a_list_that_was_not_in_force_are_refused(tmp_path):
    with pytest.raises(X.XrplError, match="27 of 35 listed validators .* seq 86"):     # relabelled to today's list
        prove(archive(tmp_path / "a", {**PROOF, "vl_seq": 86}))
    with pytest.raises(X.XrplError, match="seq 99, which is not held"):                 # a list nobody holds
        prove(archive(tmp_path / "b", {**PROOF, "vl_seq": 99}))
    bare = {k: v for k, v in PROOF.items() if k != "unl_sequence"}
    with pytest.raises(X.XrplError, match="does not name the validator list"):          # no list named at all
        prove(archive(tmp_path / "c", bare))


def test_the_recorder_keeps_the_list_it_records_under(tmp_path, monkeypatch):
    class Stop(BaseException):
        pass

    class Rec(Fake):
        def __init__(self):
            super().__init__("85")

        def rpc(self, method, params, tries=6):
            return {"ledger_index": TOP - 10}

        def live_validations(self, min_index, unl, timeout_s=45):
            return {k: PROOF[k] for k in ("ledger_index", "ledger_hash", "validations")}

    class OneShot(X.Archive):
        def add(self, proof):
            super().add(proof)
            raise Stop

    monkeypatch.setattr(X.time, "time", lambda: PROOF["at"])
    arc = OneShot(tmp_path / "proofs.jsonl")
    with pytest.raises(Stop):
        X.record(Rec(), arc)
    line = json.loads(arc.path.read_text().splitlines()[0])
    assert (line["vl_seq"], line["unl_sequence"], line["signed"]) == (85, 85, 28)
    saved = arc.lists.get(85)
    assert line["vl_manifests"] in saved["manifest_sets"] and saved["first_seen"] == PROOF["at"]
    monkeypatch.setattr(X.time, "time", lambda: NOW)                    # later, list 86 is current: still proven
    arc.lists.adopt(cachefile(tmp_path, "86"))
    _, how = prove(X.Archive(arc.path))
    assert how["vl_seq"] == 85 and how["vl_manifests"] == line["vl_manifests"]


def test_backfill_adopts_verifiable_documents_from_disk(tmp_path):
    arc = X.Archive(tmp_path / "proofs.jsonl")
    arc.add(PROOF)
    rep = X.adopt_lists(arc, [cachefile(tmp_path, "85"), tmp_path / "missing.json"])
    assert rep["adopt"][0] == {"file": str(tmp_path / "cache-85.json"), "adopted": True, "vl_seq": 85,
                               "manifest_set": rep["adopt"][0]["manifest_set"]}
    assert rep["adopt"][1]["adopted"] is False
    assert rep["by_list"]["85"]["proofs"] == 1 and rep["by_list"]["85"]["list"].startswith("held")
    first = arc.lists.get(85)["first_seen"]
    X.adopt_lists(arc, [cachefile(tmp_path, "85")])                     # idempotent
    assert arc.lists.get(85)["first_seen"] == first and len(arc.lists.get(85)["manifest_sets"]) == 1
    bare = tmp_path / "vl.json"                                          # a bare vl.ripple.com document
    bare.write_text(json.dumps(R["lists"]["86"]["doc"]))
    assert arc.lists.adopt(bare)[0] == 86


def test_the_archive_is_indexed_and_reports_its_oldest_ledger(tmp_path, monkeypatch):
    arc = X.Archive(tmp_path / "proofs.jsonl")
    assert arc.bounds() is None and arc.oldest() is None and arc.covering(5) is None
    for i in (1000, 1256, 1512):
        arc.add({"ledger_index": i, "ledger_hash": "AA" * 32, "validations": [], "unl_sequence": 85, "at": i})
    monkeypatch.setattr(X, "MAX_WALK", 300)
    assert arc.oldest() == 1000 and arc.bounds() == (1000, 1512)
    assert arc.covering(1001)["ledger_index"] == 1256 and arc.covering(1000)["ledger_index"] == 1000
    assert arc.covering(1513) is None and arc.covering(600) is None

    monkeypatch.setattr(X.Archive, "proofs", lambda self: (_ for _ in ()).throw(AssertionError("full re-parse")))
    with open(arc.path, "a", encoding="utf-8") as fh:                    # the recorder appends; a line half-written
        fh.write(json.dumps({"ledger_index": 1768, "ledger_hash": "BB" * 32, "validations": []}) + "\n")
        fh.write('{"ledger_index": 2024, "ledger_')
    assert arc.covering(1700)["ledger_index"] == 1768 and arc.bounds() == (1000, 1768)
    with open(arc.path, "a", encoding="utf-8") as fh:
        fh.write('hash": "CC", "validations": []}\n')
    assert arc.bounds() == (1000, 2024)
    arc.path.write_text(json.dumps({"validations": [], "ledger_index": 7}) + "\n")   # replaced; key order differs
    assert arc.bounds() == (7, 7) and arc.covering(7)["ledger_index"] == 7
