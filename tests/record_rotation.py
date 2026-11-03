"""Record the real validator-list rotation (vl.ripple.com seq 85 -> 86, 2026-10-28) for tests/test_lists.py.

  python tests/record_xrpl_rotation.py OLD_LIST NEW_LIST [ARCHIVE]   -> tests/fixtures/xrpl_rotation.json

OLD_LIST / NEW_LIST: UNL cache files ({fetched, doc, manifests}) holding seq 85 and seq 86. ARCHIVE: the proof archive
(default ~/.verified-reads/xrpl-proofs.jsonl); its last seq-85 proof is kept with that ledger's real header. Under seq 85
that proof carries 28/35 signatures; under seq 86 (one validator replaced) only 27/35: the failure this fixes.
"""
import json
import sys
from pathlib import Path

from plumb_xrpl import prover as X


def main():
    old, new = (json.loads(Path(p).read_text(encoding="utf-8")) for p in sys.argv[1:3])
    arc = Path(sys.argv[3]) if len(sys.argv) > 3 else Path.home() / ".verified-reads" / "xrpl-proofs.jsonl"
    proof = None
    for line in arc.read_text(encoding="utf-8").splitlines():
        if line.strip() and json.loads(line).get("unl_sequence") == 85:
            proof = json.loads(line)
    head = X.Source().header(proof["ledger_index"]).hex()
    assert X.parse_header(bytes.fromhex(head)).hash == proof["ledger_hash"].upper()
    out = {"lists": {"85": old, "86": new}, "proof": proof, "header": head}
    f = Path(__file__).parent / "fixtures" / "xrpl_rotation.json"
    f.write_text(json.dumps(out), encoding="utf-8")
    print(f"recorded proof ledger {proof['ledger_index']} -> {f}")


if __name__ == "__main__":
    main()
