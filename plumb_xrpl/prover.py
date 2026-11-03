"""XRP Ledger payments proven without trusting any server.

The chain of trust, every link checked here (servers are only a source of bytes):

  1. Ripple's validator list (vl.ripple.com): the publisher's manifest must be signed by the PINNED publisher master
     key, the list by the publisher's signing key, and every validator's manifest by its own master key. A list past its
     expiration is refused. Validators that rotated their signing key since the list was published are refreshed with a
     newer manifest, which must be signed by the same master key.
  2. A ledger signed by a quorum (80%) of those validators: each validation's signature is checked against the
     validator's current signing key, over the validation's own bytes.
  3. Hash links from that ledger back to the payment's ledger: every ledger header carries its parent's hash, and we
     recompute each header's hash ourselves (SHA-512Half over "LWR\\0" + header).
  4. The payment's ledger contains the transaction: we rebuild the ledger's transaction tree (SHAMap) from every
     transaction + metadata in it and compare its root with the header's.
  5. The payment itself, from those proven bytes: a successful Payment, to the payee, of the right currency (issuer
     included), delivered amount (never the requested Amount) at least the minimum, optionally from the payer.

Validator signatures exist only live (servers do not keep them), so a quorum proof comes from the live stream (fresh
payments: walk back from a ledger signed now) or from the proof archive (`plumb-xrpl record` keeps one quorum proof per
256 ledgers). A payment older than both is reported unverifiable, never guessed.

An archived proof is checked against the validator list that was IN FORCE when it was signed, not today's: the recorder
keeps every list document it records under (publisher manifest + blob + signature + the validator manifests it used),
keyed by list sequence, beside the archive. That list is re-verified end to end against the pinned publisher key, and it
must have been valid at the proof ledger's close time (not expired, effective, not superseded by a newer list held by
then). Ripple publishes new lists from time to time; validations signed under the old one are not forgeries.

Amounts are raw integers: XRP in drops; issued currencies (RLUSD...) in millionths (value x 10^6, rounded down).
"""
from __future__ import annotations

import asyncio
import base64
import bisect
import hashlib
import json
import os
import re
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_DOWN
from pathlib import Path


class HistoryError(Exception):
    """Base error for provable-history reads (kept for compatibility with the parent package)."""


# --- pins and defaults -------------------------------------------------------------------------------------------------

PUBLISHER_KEY = "ED2677ABFFD1B33AC6FBC3062B71F1E8397C1505E1C42C64D11AD1B28FF73F4734"   # vl.ripple.com master key
VL_URL = "https://vl.ripple.com"
QUORUM = 0.8
RPCS = ["https://s1.ripple.com:51234/", "https://s2.ripple.com:51234/", "https://xrplcluster.com/"]
WSS = ["wss://s2.ripple.com", "wss://s1.ripple.com", "wss://xrplcluster.com"]
RLUSD = ("524C555344000000000000000000000000000000", "rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De")
RIPPLE_EPOCH = 946684800
ARCHIVE_EVERY = 256
MAX_WALK = int(os.environ.get("VR_XRPL_MAX_WALK", "3000"))    # headers we will walk back (~3.3 h of ledgers)
TF_PARTIAL = 0x00020000
PREFIX = {"ledger": b"LWR\x00", "tx_id": b"TXN\x00", "tx_node": b"SND\x00", "inner": b"MIN\x00",
          "validation": b"VAL\x00", "manifest": b"MAN\x00"}
UA = {"content-type": "application/json", "user-agent": "plumb-xrpl"}


class XrplError(HistoryError):
    pass


class PendingValidation(XrplError):
    def __init__(self, msg: str, retry_after_s: int = 10):
        super().__init__(msg)
        self.retry_after_s = retry_after_s


def half(b: bytes) -> bytes:
    return hashlib.sha512(b).digest()[:32]


def _codec():
    from xrpl.core import binarycodec   # decoding only; every hash is computed here over the raw bytes
    return binarycodec


def verify_sig(pub_hex: str, message: bytes, sig: bytes) -> bool:
    """rippled's verify(): Ed25519 signs the message itself; secp256k1 signs SHA-512Half(message), DER, low-S."""
    try:
        pub = bytes.fromhex(pub_hex)
        if pub[0] == 0xED:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            Ed25519PublicKey.from_public_bytes(pub[1:]).verify(sig, message)
            return True
        import coincurve
        return coincurve.PublicKey(pub).verify(sig, half(message), hasher=None)
    except Exception:  # noqa: BLE001 - any malformed key/signature is simply not valid
        return False


def signing_bytes(obj_hex: str, *drop: str) -> bytes:
    """An STObject's bytes without its signature fields. Refuses when the codec cannot reproduce the exact bytes
    (then we would be checking a signature over something other than what was signed)."""
    bc = _codec()
    d = bc.decode(obj_hex.upper())
    if bc.encode(d).upper() != obj_hex.upper():
        raise XrplError("object does not re-encode byte-identically; refusing to check its signature")
    return bytes.fromhex(bc.encode({k: v for k, v in d.items() if k not in drop}))


# --- 1. the validator list -------------------------------------------------------------------------------------------

@dataclass
class Manifest:
    master: str
    ephemeral: str | None
    seq: int


def parse_manifest(raw: bytes) -> Manifest:
    """A validator's key certificate: the master key signs its current signing (ephemeral) key, and so does that key."""
    h = raw.hex().upper()
    d = _codec().decode(h)
    msg = PREFIX["manifest"] + signing_bytes(h, "Signature", "MasterSignature")
    if not verify_sig(d["PublicKey"], msg, bytes.fromhex(d.get("MasterSignature", ""))):
        raise XrplError("manifest not signed by its master key")
    if "SigningPubKey" in d and not verify_sig(d["SigningPubKey"], msg, bytes.fromhex(d.get("Signature", ""))):
        raise XrplError("manifest not signed by its signing key")
    return Manifest(d["PublicKey"].upper(), (d.get("SigningPubKey") or "").upper() or None, int(d["Sequence"]))


@dataclass
class Unl:
    signing_to_master: dict[str, str]
    masters: set[str]
    sequence: int
    expires: int                      # unix time
    manifests: dict[str, Manifest] = field(default_factory=dict)

    @property
    def quorum(self) -> int:
        return -(-len(self.masters) * 8 // 10)    # ceil(0.8 n)

    def adopt(self, m: Manifest) -> bool:
        """A newer manifest for a listed validator (key rotation)."""
        cur = self.manifests.get(m.master)
        if m.master not in self.masters or (cur and m.seq <= cur.seq) or not m.ephemeral:
            return False
        if cur and cur.ephemeral:
            self.signing_to_master.pop(cur.ephemeral, None)
        self.manifests[m.master] = m
        self.signing_to_master[m.ephemeral] = m.master
        return True


def verify_doc(doc: dict) -> dict:
    """The decoded blob of a vl.ripple.com document whose publisher manifest is signed by the PINNED publisher key and
    whose blob is signed by that publisher's signing key. Time is not checked here (see load_unl)."""
    try:
        pub = parse_manifest(base64.b64decode(doc["manifest"]))
        blob = base64.b64decode(doc["blob"])
        sig = bytes.fromhex(doc["signature"])
    except (KeyError, TypeError, ValueError) as e:
        raise XrplError(f"validator list document is malformed ({type(e).__name__})") from None
    if pub.master != PUBLISHER_KEY:
        raise XrplError("validator list is not from the pinned publisher")
    if not pub.ephemeral or not verify_sig(pub.ephemeral, blob, sig):
        raise XrplError("validator list signature does not verify")
    return json.loads(blob)


def load_unl(doc: dict, now: float | None = None) -> Unl:
    """Verify a vl.ripple.com document end to end against the pinned publisher key, valid at `now` (default: the
    current time; for an archived proof: the proof ledger's close time)."""
    b = verify_doc(doc)
    t = time.time() if now is None else now
    expires = int(b["expiration"]) + RIPPLE_EPOCH
    if t >= expires:
        raise XrplError("validator list has expired")
    if "effective" in b and t < int(b["effective"]) + RIPPLE_EPOCH:
        raise XrplError("validator list was not yet effective")
    unl = Unl({}, set(), int(b["sequence"]), expires)
    for v in b["validators"]:
        m = parse_manifest(base64.b64decode(v["manifest"]))
        if m.master != v["validation_public_key"].upper() or not m.ephemeral:
            raise XrplError(f"validator {v['validation_public_key'][:12]} has a mismatched manifest")
        unl.masters.add(m.master)
        unl.manifests[m.master] = m
        unl.signing_to_master[m.ephemeral] = m.master
    return unl


# --- 2. validations --------------------------------------------------------------------------------------------------

def check_validation(unl: Unl, data_hex: str) -> tuple[str, str, int] | None:
    """(validator master key, ledger hash, ledger index) for a correctly signed validation by a listed validator."""
    try:
        d = _codec().decode(data_hex.upper())
        signer = str(d["SigningPubKey"]).upper()
        master = unl.signing_to_master.get(signer)
        if not master:
            return None
        ok = verify_sig(signer, PREFIX["validation"] + signing_bytes(data_hex, "Signature"), bytes.fromhex(d["Signature"]))
        return (master, str(d["LedgerHash"]).upper(), int(d["LedgerSequence"])) if ok else None
    except Exception:  # noqa: BLE001 - a malformed validation is not a vote
        return None


def quorum_of(unl: Unl, validations: list[str], ledger_hash: str) -> set[str]:
    """Distinct listed validators that signed THIS ledger hash."""
    signed = set()
    for v in validations:
        r = check_validation(unl, v)
        if r and r[1] == ledger_hash.upper():
            signed.add(r[0])
    return signed


# --- 3 + 4. headers and the transaction tree -------------------------------------------------------------------------

@dataclass
class Header:
    index: int
    parent: str
    tx_root: str
    close_time: int
    hash: str


def parse_header(raw: bytes) -> Header:
    if len(raw) != 118:
        raise XrplError(f"ledger header is {len(raw)} bytes, expected 118")
    return Header(int.from_bytes(raw[0:4], "big"), raw[12:44].hex().upper(), raw[44:76].hex().upper(),
                  int.from_bytes(raw[112:116], "big") + RIPPLE_EPOCH, half(PREFIX["ledger"] + raw).hex().upper())


def _vl(n: int) -> bytes:
    if n <= 192:
        return bytes([n])
    if n <= 12480:
        n -= 193
        return bytes([193 + (n >> 8), n & 0xFF])
    n -= 12481
    return bytes([241 + (n >> 16), (n >> 8) & 0xFF, n & 0xFF])


def tx_id(tx: bytes) -> bytes:
    return half(PREFIX["tx_id"] + tx)


def tx_root(pairs: list[tuple[bytes, bytes]]) -> str:
    """Root of a ledger's transaction tree from its (tx, metadata) blobs."""
    leaves = {}
    for tx, meta in pairs:
        k = tx_id(tx)
        leaves[k] = half(PREFIX["tx_node"] + _vl(len(tx)) + tx + _vl(len(meta)) + meta + k)

    def build(items: dict, depth: int) -> bytes:
        if not items:
            return b"\x00" * 32
        if len(items) == 1 and depth > 0:
            return next(iter(items.values()))
        groups: dict[int, dict] = {}
        for k, h in items.items():
            groups.setdefault((k[depth // 2] >> (4 if depth % 2 == 0 else 0)) & 0xF, {})[k] = h
        return half(PREFIX["inner"] + b"".join(build(groups[i], depth + 1) if i in groups else b"\x00" * 32 for i in range(16)))
    return build(leaves, 0).hex().upper()


# --- untrusted sources -----------------------------------------------------------------------------------------------

class Source:
    """Public rippled servers: a source of bytes, never of truth."""

    def __init__(self, rpcs: list[str] | None = None, wss: list[str] | None = None):
        self.rpcs = rpcs or os.environ.get("VR_XRPL_RPC", ",".join(RPCS)).split(",")
        self.wss = wss or os.environ.get("VR_XRPL_WSS", ",".join(WSS)).split(",")
        self._i = 0

    def rpc(self, method: str, params: dict, tries: int = 6) -> dict:
        err = ""
        for n in range(tries):
            url = self.rpcs[(self._i + n) % len(self.rpcs)]
            try:
                body = json.dumps({"method": method, "params": [params]}).encode()
                r = json.load(urllib.request.urlopen(urllib.request.Request(url, body, UA), timeout=30))["result"]
                if r.get("status") == "error" and r.get("error") not in ("txnNotFound", "lgrNotFound"):
                    raise RuntimeError(r.get("error_message") or r.get("error"))
                self._i += 1
                return r
            except Exception as e:  # noqa: BLE001 - next server
                err = str(e)
                time.sleep(min(2 ** n, 8) * 0.25)
        raise XrplError(f"{method}: no server answered ({err[:120]})")

    def _ledger(self, params: dict) -> dict:
        """A ledger by index. A server that does not have it yet (a brand-new ledger) is skipped for the next one; if none
        has it, the answer is 'pending, retry', never a crash (live 2026-10-10: KeyError 'ledger' on a just-validated batch)."""
        for _ in range(len(self.rpcs) * 2):
            r = self.rpc("ledger", params)
            if isinstance(r.get("ledger"), dict):
                return r["ledger"]
            time.sleep(1.0)
        raise PendingValidation(f"ledger {params.get('ledger_index')} is not available from the servers yet", 10)

    def header(self, index: int) -> bytes:
        return bytes.fromhex(self._ledger({"ledger_index": index, "binary": True})["ledger_data"])

    def ledger_txs(self, index: int) -> list[tuple[bytes, bytes]]:
        led = self._ledger({"ledger_index": index, "transactions": True, "expand": True, "binary": True})
        return [(bytes.fromhex(t["tx_blob"]), bytes.fromhex(t["meta"])) for t in led["transactions"]]

    def locate(self, tx_hash: str) -> int | None:
        """Which validated ledger the servers SAY holds the tx (checked against the tree before it is believed)."""
        r = self.rpc("tx", {"transaction": tx_hash, "binary": True})
        if r.get("error") == "txnNotFound" or not r.get("validated"):
            return None
        return int(r["ledger_index"])

    def unl_doc(self) -> dict:
        return json.load(urllib.request.urlopen(urllib.request.Request(VL_URL, None, UA), timeout=30))

    def manifest(self, master_hex: str) -> bytes | None:
        try:
            r = self.rpc("manifest", {"public_key": node_public_b58(master_hex)}, tries=3)
            return base64.b64decode(r["manifest"]) if r.get("manifest") else None
        except XrplError:
            return None

    def live_validations(self, min_index: int, unl: Unl, timeout_s: float = 45) -> dict:
        """Listen for validations until some ledger >= min_index has a quorum of listed validators."""
        async def run() -> dict:
            import websockets
            by: dict[str, list[str]] = {}
            signed: dict[str, set[str]] = {}
            idx: dict[str, int] = {}
            deadline = time.time() + timeout_s
            last, n = "", 0
            while time.time() < deadline:
                url = self.wss[n % len(self.wss)]
                n += 1
                try:
                    async with websockets.connect(url, max_size=2 ** 22, open_timeout=15) as ws:
                        await ws.send(json.dumps({"command": "subscribe", "streams": ["validations"]}))
                        while time.time() < deadline:
                            m = json.loads(await asyncio.wait_for(ws.recv(), timeout=max(1.0, deadline - time.time())))
                            if m.get("type") != "validationReceived" or int(m.get("ledger_index", 0)) < min_index or "data" not in m:
                                continue
                            r = check_validation(unl, m["data"])          # each validation checked once, on arrival
                            if not r:
                                continue                                   # not a listed validator, or a bad signature
                            h = r[1]
                            by.setdefault(h, []).append(m["data"])
                            signed.setdefault(h, set()).add(r[0])
                            idx[h] = r[2]
                            if len(signed[h]) >= unl.quorum and idx[h] >= min_index:
                                return {"ledger_index": idx[h], "ledger_hash": h, "validations": by[h]}
                except Exception as e:  # noqa: BLE001 - next stream (servers refuse bursts of new connections)
                    last = f"{url}: {type(e).__name__} {e}"[:160]
                    await asyncio.sleep(min(2.0, max(0.0, deadline - time.time())))
            raise PendingValidation(f"no ledger reached a validator quorum on the live stream in time ({last or 'no answer'})", 15)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(run())
        # called from inside an event loop (the MCP server `plumb-xrpl serve`): run the stream on its own thread and loop
        with ThreadPoolExecutor(1) as ex:
            return ex.submit(lambda: asyncio.run(run())).result()


_B58 = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"


def node_public_b58(key_hex: str) -> str:
    raw = bytes([0x1C]) + bytes.fromhex(key_hex)
    raw += hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    n, out = int.from_bytes(raw, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return _B58[0] * (len(raw) - len(raw.lstrip(b"\x00"))) + out


# --- the proof archive -----------------------------------------------------------------------------------------------

SUPERSEDE_GRACE_S = 2 * 86400   # the recorder refreshes its list daily: an old list stays acceptable this long after a newer one is held


def _manifest_set_id(raws: dict[str, bytes]) -> str:
    body = json.dumps(sorted((m.upper(), base64.b64encode(r).decode()) for m, r in raws.items()))
    return hashlib.sha256(body.encode()).hexdigest()[:16]


class ListLibrary:
    """Every validator-list document the archive was recorded under, by list sequence (<dir>/<seq>.json):
    {"sequence", "doc" (vl.ripple.com: public_key, manifest, blob, signature), "first_seen" (unix), "manifest_sets"
    {id: {master: raw manifest b64}}}. A file only saves fetching, never checking: every use re-verifies the document
    against the pinned publisher key and every manifest against its validator's master key. A document that does not
    verify is never stored."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def _file(self, seq: int) -> Path:
        return self.root / f"{int(seq)}.json"

    def get(self, seq: int) -> dict | None:
        try:
            return json.loads(self._file(seq).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def sequences(self) -> list[int]:
        try:
            return sorted(int(p.stem) for p in self.root.glob("*.json") if p.stem.isdigit())
        except OSError:
            return []

    def save(self, doc: dict, raws: dict[str, bytes] | None = None, seen_at: float | None = None) -> tuple[int, str]:
        """Keep a verified list document and the validator manifests used with it. Returns (sequence, manifest set id).
        Raises XrplError for a document that does not verify against the pinned publisher."""
        b = verify_doc(doc)
        seq, listed = int(b["sequence"]), {v["validation_public_key"].upper() for v in b["validators"]}
        good = {}
        for r in (raws or {}).values():                  # only manifests that verify, of validators on this list
            try:
                man = parse_manifest(r)
            except XrplError:
                continue
            if man.master in listed:
                good[man.master] = r
        sid = _manifest_set_id(good)
        seen = float(time.time() if seen_at is None else seen_at)
        cur = self.get(seq) or {}
        if cur.get("doc") and cur["doc"] != doc:
            try:
                verify_doc(cur["doc"])
                doc = cur["doc"]                         # the same signed list already held: keep that copy
            except (XrplError, KeyError, TypeError):
                cur = {}                                 # a damaged file is replaced by the verified document
        sets = dict(cur.get("manifest_sets") or {})
        first = min(float(cur.get("first_seen", seen)), seen)
        if cur.get("doc") == doc and sid in sets and float(cur.get("first_seen", -1)) == first:
            return seq, sid                              # nothing new
        sets[sid] = {m: base64.b64encode(r).decode() for m, r in sorted(good.items())}
        out = {"sequence": seq, "doc": doc, "first_seen": first, "manifest_sets": sets}
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self._file(seq).with_suffix(f".tmp{os.getpid()}")
        tmp.write_text(json.dumps(out), encoding="utf-8")
        os.replace(tmp, self._file(seq))
        return seq, sid

    def adopt(self, path: Path) -> tuple[int, str]:
        """Backfill from a file on disk: a UNL cache ({fetched, doc, manifests}), a library file, or a bare
        vl.ripple.com document. Verified before it is kept; XrplError otherwise."""
        try:
            c = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise XrplError(f"{path}: not readable JSON ({type(e).__name__})") from None
        if not isinstance(c, dict):
            raise XrplError(f"{path}: not a validator-list document")
        if "blob" in c and "manifest" in c:
            return self.save(c, {}, None)
        if "manifest_sets" in c and "doc" in c:
            out = self.save(c["doc"], {}, c.get("first_seen"))
            for ms in c["manifest_sets"].values():
                out = self.save(c["doc"], {m: base64.b64decode(r) for m, r in ms.items()}, c.get("first_seen"))
            return out
        if "doc" in c:
            return self.save(c["doc"], {m: base64.b64decode(r) for m, r in (c.get("manifests") or {}).items()},
                             c.get("fetched"))
        raise XrplError(f"{path}: not a validator-list document")


def _proof_seq(proof: dict) -> int | None:
    s = proof.get("vl_seq", proof.get("unl_sequence"))     # unl_sequence: archives recorded before vl_seq existed
    return int(s) if s is not None else None


class Archive:
    """Quorum proofs kept from the live stream (one per ARCHIVE_EVERY ledgers), so older payments stay provable.
    Read through an index of (ledger index, byte offset), refreshed incrementally as the recorder appends, so a proof
    never re-parses the whole file. Beside it, `lists` holds the validator-list documents the proofs were recorded under."""

    def __init__(self, path: Path | None = None, lists: Path | None = None):
        self.path = Path(path or os.environ.get("VR_XRPL_ARCHIVE", Path.home() / ".verified-reads" / "xrpl-proofs.jsonl"))
        self.lists = ListLibrary(lists or self.path.parent / f"{self.path.stem}-lists")
        self._idx: list[tuple[int, int]] = []
        self._size = 0
        self._lock = threading.Lock()

    def _refresh(self) -> None:
        try:
            size = self.path.stat().st_size
        except OSError:
            self._idx, self._size = [], 0
            return
        if size == self._size:
            return
        if size < self._size:                                 # replaced or truncated: start over
            self._idx, self._size = [], 0
        new = []
        with open(self.path, "rb") as fh:
            fh.seek(self._size)
            pos = self._size
            for raw in fh:
                if not raw.endswith(b"\n"):
                    break                                     # a line still being written
                m = re.match(rb'\{"ledger_index":\s*(\d+)', raw)
                if m:
                    new.append((int(m.group(1)), pos))
                elif raw.strip():
                    try:
                        new.append((int(json.loads(raw)["ledger_index"]), pos))
                    except (ValueError, KeyError, TypeError):
                        pass
                pos += len(raw)
        self._size = pos
        self._idx = sorted(self._idx + new)

    def proofs(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]

    def add(self, proof: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(proof) + "\n")

    def bounds(self) -> tuple[int, int] | None:
        """(oldest, newest) archived proof ledger, or None for an empty archive."""
        with self._lock:
            self._refresh()
            return (self._idx[0][0], self._idx[-1][0]) if self._idx else None

    def oldest(self) -> int | None:
        """The oldest archived proof ledger: nothing much older than this is provable from the archive."""
        b = self.bounds()
        return b[0] if b else None

    def covering(self, index: int) -> dict | None:
        """The nearest archived proof at or after `index` within walking distance."""
        with self._lock:
            self._refresh()
            i = bisect.bisect_left(self._idx, (index, -1))
            hit = self._idx[i] if i < len(self._idx) and self._idx[i][0] <= index + MAX_WALK else None
        if hit is None:
            return None
        with open(self.path, "rb") as fh:
            fh.seek(hit[1])
            return json.loads(fh.readline())

    def save_list(self, doc: dict, raws: dict[str, bytes] | None = None, seen_at: float | None = None) -> tuple[int, str]:
        return self.lists.save(doc, raws, seen_at)

    def list_report(self) -> dict:
        """Per list sequence the archive references: how many proofs, and whether a verified document is held."""
        refs: dict[int | None, list[int]] = {}
        for p in self.proofs():
            refs.setdefault(_proof_seq(p), []).append(p["ledger_index"])
        out = {}
        for seq, idx in sorted(refs.items(), key=lambda kv: (kv[0] is None, kv[0] or 0)):
            row: dict = {"proofs": len(idx), "ledgers": [min(idx), max(idx)]}
            saved = self.lists.get(seq) if seq is not None else None
            if seq is None:
                row["list"] = "NOT NAMED by these proofs: they cannot be checked"
            elif saved is None:
                row["list"] = "NOT HELD: these proofs cannot be checked until a verifiable document for this sequence is adopted"
            else:
                try:
                    verify_doc(saved["doc"])
                    row.update(list="held; verifies against the pinned publisher",
                               manifest_sets=len(saved.get("manifest_sets") or {}), first_seen=saved.get("first_seen"))
                except (XrplError, KeyError) as e:
                    row["list"] = f"held but REFUSED: {e}"
            out[str(seq)] = row
        return {"archive": str(self.path), "lists_dir": str(self.lists.root), "bounds": self.bounds(), "by_list": out}


def adopt_lists(archive: Archive, paths: list[Path] | None = None) -> dict:
    """Backfill the archive's list library from documents already on disk (default: this machine's UNL cache), each
    verified against the pinned publisher before it is kept, then report which archived proofs have their list."""
    if paths is None:
        paths = [Path(os.environ.get("VR_XRPL_UNL_CACHE", Path.home() / ".verified-reads" / "xrpl-unl.json"))]
    adopted = []
    for p in paths:
        try:
            seq, sid = archive.lists.adopt(Path(p))
            adopted.append({"file": str(p), "adopted": True, "vl_seq": seq, "manifest_set": sid})
        except XrplError as e:
            adopted.append({"file": str(p), "adopted": False, "reason": str(e)})
    return {"adopt": adopted, **archive.list_report()}


def record(source: Source | None = None, archive: Archive | None = None, every: int = ARCHIVE_EVERY) -> None:
    """Run forever: keep a quorum proof for every `every`-th ledger (and refresh the validator list daily)."""
    source, archive = source or Source(), archive or Archive()
    unl, loaded, last, sid = None, 0.0, 0, None
    while True:
        if unl is None or time.time() - loaded > 86400:
            doc = source.unl_doc()
            unl, loaded = load_unl(doc), time.time()
            raws = refresh_rotations(unl, source)
            _, sid = archive.save_list(doc, raws, loaded)   # the exact list + keys these proofs will be checked against
        try:
            head = int(source.rpc("ledger", {"ledger_index": "validated"})["ledger_index"])
            target = max((head // every + 1) * every, (last // every + 1) * every)   # never the same boundary twice
            p = source.live_validations(target, unl, timeout_s=every * 5)
            last = p["ledger_index"]
            signed = quorum_of(unl, p["validations"], p["ledger_hash"])
            archive.add({**p, "unl_sequence": unl.sequence, "vl_seq": unl.sequence, "vl_manifests": sid,
                         "signed": len(signed), "of": len(unl.masters), "at": int(time.time())})
            print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} kept ledger {p['ledger_index']} "
                  f"({len(signed)}/{len(unl.masters)} validators)", flush=True)
        except Exception as e:  # noqa: BLE001 - keep recording
            print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} retrying: {type(e).__name__} {str(e)[:120]}", flush=True)
            time.sleep(10)


def refresh_rotations(unl: Unl, source: Source, raws: dict[str, bytes] | None = None) -> dict[str, bytes]:
    """Validators that rotated their signing key after the list was published: fetch their newer manifests (in
    parallel), each checked against that validator's master key before it is adopted. Returns the raw manifests."""
    masters = sorted(unl.masters)
    if raws is None:
        with ThreadPoolExecutor(12) as ex:
            raws = {m: r for m, r in zip(masters, ex.map(source.manifest, masters)) if r}
    for raw in raws.values():
        try:
            unl.adopt(parse_manifest(raw))
        except XrplError:
            pass
    return raws


UNL_CACHE_S = 3600


def _keep(lists: "ListLibrary | None", doc: dict, raws: dict[str, bytes], seen_at: float) -> None:
    if lists is not None:
        try:
            lists.save(doc, raws, seen_at)
        except (OSError, XrplError):
            pass


def cached_unl(source: Source, cache: Path | None = None, now: float | None = None,
               lists: ListLibrary | None = None) -> Unl:
    """The validator list, from a one-hour disk cache of the RAW signed documents. Everything is re-verified on load
    (pinned publisher, list signature, every manifest), so the cache saves fetching, never checking. With `lists`, the
    current document is also kept there by sequence, so proofs archived under it stay checkable after it is replaced."""
    cache = cache or Path(os.environ.get("VR_XRPL_UNL_CACHE", Path.home() / ".verified-reads" / "xrpl-unl.json"))
    now = now or time.time()
    try:
        c = json.loads(cache.read_text(encoding="utf-8"))
        if now - c["fetched"] < UNL_CACHE_S:
            unl = load_unl(c["doc"], now)
            raws = {m: base64.b64decode(r) for m, r in c["manifests"].items()}
            refresh_rotations(unl, source, raws)
            _keep(lists, c["doc"], raws, c["fetched"])
            return unl
    except (OSError, ValueError, KeyError, XrplError):
        pass
    doc = source.unl_doc()
    unl = load_unl(doc, now)
    raws = refresh_rotations(unl, source)
    _keep(lists, doc, raws, now)
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps({"fetched": now, "doc": doc, "manifests": {m: base64.b64encode(r).decode() for m, r in raws.items()}}),
                         encoding="utf-8")
    except OSError:
        pass
    return unl


# --- 5. the payment --------------------------------------------------------------------------------------------------

def parse_token(token: str) -> tuple[str, str | None]:
    """'' or 'XRP' -> native; 'RLUSD' -> Ripple USD; 'CUR.rIssuer' (3-letter or 40-hex code) -> that issued currency."""
    t = (token or "XRP").strip()
    if t.upper() == "XRP":
        return "XRP", None
    if t.upper() == "RLUSD":
        return RLUSD
    if "." in t:
        cur, issuer = t.split(".", 1)
        return (cur.upper() if len(cur) == 40 else cur), issuer
    raise XrplError("token must be XRP, RLUSD, or CURRENCY.rIssuer")


def _currency_matches(amount_cur: str, want: str) -> bool:
    if amount_cur == want:
        return True
    if len(want) == 3 and len(amount_cur) == 40:
        return bytes.fromhex(amount_cur)[12:15].decode(errors="replace") == want and bytes.fromhex(amount_cur)[:12] == b"\x00" * 12
    return False


def raw_amount(amount, want: tuple[str, str | None]) -> int | None:
    """The amount in raw units if it is the wanted currency (XRP drops; issued x10^6, rounded down), else None."""
    cur, issuer = want
    if isinstance(amount, str):                    # XRP, drops
        return int(amount) if cur == "XRP" else None
    if cur == "XRP" or amount.get("issuer") != issuer or not _currency_matches(str(amount.get("currency")), cur):
        return None
    return int((Decimal(str(amount["value"])) * 10 ** 6).to_integral_value(rounding=ROUND_DOWN))


def judge(tx: dict, meta: dict, recipient: str, want: tuple[str, str | None], min_raw: int, payer: str | None,
          invoice: str | None) -> tuple[str, int, str]:
    """(verdict, paid_raw, reason) from the proven transaction and metadata."""
    if meta.get("TransactionResult") != "tesSUCCESS":
        return "failed_transaction", 0, f"the transaction did not succeed ({meta.get('TransactionResult')})"
    if tx.get("TransactionType") != "Payment":
        return "not_paid", 0, f"not a Payment ({tx.get('TransactionType')})"
    if tx.get("Destination") != recipient:
        return "not_paid", 0, "paid someone else"
    if payer and tx.get("Account") != payer:
        return "not_paid", 0, "sent by a different account than the payer"
    if invoice and str(tx.get("InvoiceID", "")).upper() != invoice.upper():
        return "not_paid", 0, "InvoiceID does not match"
    delivered = meta.get("DeliveredAmount")
    if delivered is None:
        if int(tx.get("Flags", 0)) & TF_PARTIAL:
            return "not_paid", 0, "partial payment without a delivered amount"
        delivered = tx.get("Amount")
    paid = raw_amount(delivered, want)
    if paid is None:
        return "not_paid", 0, "delivered a different currency or issuer"
    if paid < min_raw:
        return "underpaid", paid, f"delivered {paid}, below the minimum {min_raw}"
    return "paid", paid, "delivered amount meets the minimum"


# --- the whole proof -------------------------------------------------------------------------------------------------

class XrplHistory:
    def __init__(self, source: Source | None = None, archive: Archive | None = None, unl_cache: Path | None = None):
        self.source, self.archive, self.unl_cache = source or Source(), archive or Archive(), unl_cache
        self._unl: Unl | None = None
        self._unl_at = 0.0

    def unl(self) -> Unl:
        if self._unl is None or time.time() - self._unl_at > UNL_CACHE_S:
            self._unl = cached_unl(self.source, self.unl_cache, lists=self.archive.lists)
            self._unl_at = time.time()
        return self._unl

    def list_in_force(self, proof: dict, at: int) -> tuple[Unl, set[str], str]:
        """(list, validators that signed, manifest set id) for an ARCHIVED proof: the list it was recorded under,
        re-verified end to end, valid at `at` (the proof ledger's close time, not now) and not superseded by then."""
        seq = _proof_seq(proof)
        if seq is None:
            raise XrplError("the archived proof does not name the validator list it was recorded under; cannot tell "
                            "which list was in force")
        saved = self.archive.lists.get(seq)
        if not saved or "doc" not in saved:
            raise XrplError(f"the archived proof was recorded under validator list seq {seq}, which is not held in "
                            f"{self.archive.lists.root} (adopt a verifiable copy: `plumb-xrpl lists --adopt FILE`); "
                            "cannot prove it")
        try:
            load_unl(saved["doc"], at)
        except XrplError as e:
            raise XrplError(f"validator list seq {seq} was not valid when ledger {proof['ledger_index']} closed: {e}") from None
        for s in self.archive.lists.sequences():
            newer = self.archive.lists.get(s) if s > seq else None
            if newer and float(newer.get("first_seen", float("inf"))) + SUPERSEDE_GRACE_S <= at:
                try:
                    verify_doc(newer["doc"])
                except (XrplError, KeyError, TypeError):
                    continue                                # an unverifiable file supersedes nothing
                raise XrplError(f"validator list seq {seq} was no longer in force when ledger {proof['ledger_index']} "
                                f"closed: seq {s} had replaced it")
        sets = dict(saved.get("manifest_sets") or {})
        order = [proof["vl_manifests"]] if proof.get("vl_manifests") in sets else []
        order += [k for k in sets if k not in order] + [""]     # "": only the manifests inside the list itself
        best: tuple[Unl, set[str], str] | None = None
        for sid in order:                                       # each set is a verified key state of THIS list
            unl = load_unl(saved["doc"], at)
            refresh_rotations(unl, self.source, {m: base64.b64decode(r) for m, r in sets.get(sid, {}).items()})
            signed = quorum_of(unl, proof["validations"], proof["ledger_hash"])
            if best is None or len(signed) > len(best[1]):
                best = (unl, signed, sid)
            if len(signed) >= unl.quorum:
                break
        return best

    def proven_header(self, index: int) -> tuple[Header, dict]:
        """The header of ledger `index`, proven by a quorum-signed ledger at or after it plus hash links. A live proof
        is checked against the current validator list; an archived one against the list in force when it was signed."""
        proof = self.archive.covering(index)
        archived = proof is not None
        if archived:
            try:
                self.unl()                 # keeps the current list in the library; the archived proof does not depend on it
            except Exception:  # noqa: BLE001 - offline / current list unavailable: the archived list decides
                pass
            top = proof["ledger_index"]
            top_h = parse_header(self.source.header(top))
            if top_h.index != top or top_h.hash != str(proof["ledger_hash"]).upper():
                raise XrplError(f"header {top} does not hash to the proven link")
            unl, signed, sid = self.list_in_force(proof, top_h.close_time)
        else:
            unl = self.unl()
            head = int(self.source.rpc("ledger", {"ledger_index": "validated"})["ledger_index"])
            if head - index > MAX_WALK:
                raise XrplError(f"ledger {index} is older than the proof archive and {MAX_WALK} ledgers of walking "
                                "(run `plumb-xrpl record` to keep proofs); cannot prove it")
            proof = self.source.live_validations(index, unl)
            top, sid = proof["ledger_index"], None
            signed = quorum_of(unl, proof["validations"], proof["ledger_hash"])
        if len(signed) < unl.quorum:
            where = f" on validator list seq {unl.sequence}, the list it was recorded under" if archived else ""
            raise XrplError(f"only {len(signed)} of {len(unl.masters)} listed validators signed the proof ledger{where} "
                            f"(need {unl.quorum})")
        with ThreadPoolExecutor(8) as ex:
            raws = dict(zip(range(index, top + 1), ex.map(self.source.header, range(index, top + 1))))
        expect = proof["ledger_hash"]
        h = None
        for i in range(top, index - 1, -1):
            h = parse_header(raws[i])
            if h.index != i or h.hash != expect:
                raise XrplError(f"header {i} does not hash to the proven link")
            expect = h.parent
        how = {"proof_ledger": top, "proof_hash": proof["ledger_hash"], "validators": len(signed), "of": len(unl.masters),
               "quorum": unl.quorum, "unl_sequence": unl.sequence, "vl_seq": unl.sequence, "walked": top - index,
               "from_archive": archived}
        if archived:
            how.update(vl_checked_at=top_h.close_time, vl_manifests=sid or "list")
        return h, how

    def proven_tx(self, tx_hash: str) -> tuple[dict, dict, int, Header, dict]:
        """(tx, metadata, ledger index, proven header, how) for a transaction in a validated ledger: the tx and its
        metadata are decoded from bytes that are leaves of the ledger's rebuilt transaction tree."""
        tx_hash = tx_hash.upper().removeprefix("0X")
        if len(tx_hash) != 64:
            raise XrplError("an XRPL transaction hash is 64 hex characters")
        index = self.source.locate(tx_hash)
        if index is None:
            raise PendingValidation("the servers do not report this transaction in a validated ledger yet", 10)
        header, how = self.proven_header(index)
        pairs = self.source.ledger_txs(index)
        if tx_root(pairs) != header.tx_root:
            raise XrplError(f"the transactions served for ledger {index} do not match its proven header")
        hit = next(((t, m) for t, m in pairs if tx_id(t).hex().upper() == tx_hash), None)
        if hit is None:
            raise XrplError(f"ledger {index} (proven) does not contain this transaction: a server pointed at the wrong ledger")
        bc = _codec()
        return bc.decode(hit[0].hex().upper()), bc.decode(hit[1].hex().upper()), index, header, how

    def transaction(self, tx_hash: str) -> dict:
        """Any XRPL transaction, proven: its full decoded fields and metadata (e.g. a PaymentChannelCreate, whose
        metadata names the channel it created, its amount, settle delay and public key)."""
        tx, meta, index, header, how = self.proven_tx(tx_hash)
        return {"tx": {"tx_hash": tx_hash.upper().removeprefix("0X"), "block_number": index, "block_hash": header.hash,
                       "timestamp": header.close_time, "final": True, "type": tx.get("TransactionType"),
                       "result": meta.get("TransactionResult"), "fields": tx, "meta": meta,
                       "finality": f"validated (UNL quorum {how['validators']}/{how['of']})"},
                "xrpl": {"level": "unl_quorum", **how}}

    def verify_payment(self, tx_hash: str, recipient: str, token: str = "", min_raw: int = 0, payer: str | None = None,
                       invoice: str | None = None) -> dict:
        want = parse_token(token)
        tx_hash = tx_hash.upper().removeprefix("0X")
        tx, meta, index, header, how = self.proven_tx(tx_hash)
        verdict, paid, reason = judge(tx, meta, recipient, want, min_raw, payer, invoice)
        return {"verdict": verdict, "paid_raw": str(paid), "reason": reason,
                "tx": {"tx_hash": tx_hash, "block_number": index, "block_hash": header.hash, "from": tx.get("Account"),
                       "to": tx.get("Destination"), "status": 1 if meta.get("TransactionResult") == "tesSUCCESS" else 0,
                       "finality": f"validated (UNL quorum {how['validators']}/{how['of']})", "timestamp": header.close_time, "final": True},
                "xrpl": {"level": "unl_quorum", **how, "delivered": meta.get("DeliveredAmount", tx.get("Amount")),
                         "invoice_id": tx.get("InvoiceID"), "type": tx.get("TransactionType"),
                         "result": meta.get("TransactionResult"), "flags": int(tx.get("Flags", 0))},
                "note": "XRPL validated ledgers are final; amounts are XRP drops or issued-currency millionths"}


def envelope(fn) -> dict:
    """Same shape as Plumb's other chains: verified=True with value + anchor, or verified=False with a reason."""
    try:
        v = fn()
    except PendingValidation as e:
        return {"verified": True, "value": {"verdict": "pending_validation", "paid_raw": None, "reason": str(e),
                                            "retry_after_s": e.retry_after_s},
                "anchor": {"root": None, "source": "XRPL: nothing proven yet"}}
    except HistoryError as e:
        return {"verified": False, "reason": str(e)}
    except Exception as e:  # noqa: BLE001
        return {"verified": False, "reason": f"{type(e).__name__}: {e}"[:300]}
    x = v["xrpl"]
    return {"verified": True, "value": v, "anchor": {"root": x["proof_hash"], "source":
            f"XRPL validator list (vl.ripple.com seq {x['unl_sequence']}"
            f"{', in force when the archived proof ledger closed' if x.get('from_archive') else ''}, "
            f"pinned publisher {PUBLISHER_KEY[:10]}...): "
            f"{x['validators']}/{x['of']} validator signatures on ledger {x['proof_ledger']}, {x['walked']} hash links back"}}
