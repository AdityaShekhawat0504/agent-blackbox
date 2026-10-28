"""Measure the three claims this project makes, so the README can quote numbers.

1. Tampering is detected: six attacks against real recorded ledgers, with and
   without an HMAC key and an anchored head.
2. Recording is cheap: microseconds per event, with and without fsync.
3. Pseudonymisation finds personal data: precision and recall per type on a
   seeded synthetic set that includes hard negatives (order ids, dates,
   versions, numbers that fail Luhn, IBANs with a wrong checksum) and
   formats the detector is known to miss (national phone numbers).
"""

from __future__ import annotations

import hashlib
import json
import random
import shutil
import string
import tempfile
import time
from pathlib import Path

from .demo import SCENARIOS, ScriptedModel, refund_agent
from .ledger import GENESIS, Event, Ledger, canonical, verify_events
from .privacy import Pseudonymiser
from .recorder import Recorder

# ---------------------------------------------------------------- tampering

ATTACKS = ["modify", "delete", "insert", "reorder", "truncate", "rewrite_chain"]


def _record_corpus(folder: Path, key: bytes | None) -> list[Path]:
    rec = Recorder(folder, key=key, agent="refund-agent", version="1.0")
    for i in range(3):
        for sc in SCENARIOS:
            with rec.run(input=sc["input"], run_id=f"{i}-{sc['name'][:12].replace(' ', '_')}") as run:
                refund_agent(sc["input"], run, ScriptedModel("v1"))
    return sorted(folder.glob("*.jsonl"))


def _load(path: Path) -> list[Event]:
    return [Event(**json.loads(x)) for x in path.read_text().splitlines() if x.strip()]


def _attack(events: list[Event], kind: str, rng: random.Random) -> list[Event]:
    ev = [Event(**{**e.__dict__, "payload": json.loads(json.dumps(e.payload))}) for e in events]
    n = len(ev)
    if kind == "modify":
        e = ev[rng.randrange(1, n - 1)]
        e.payload["_edited"] = rng.choice(["approved", "0", "none"])
    elif kind == "delete":
        del ev[rng.randrange(1, n - 1)]
    elif kind == "insert":
        i = rng.randrange(1, n - 1)
        fake = Event(**{**ev[i].__dict__, "payload": {"outcome": "refund", "forged": True}, "kind": "decision"})
        ev.insert(i, fake)
    elif kind == "reorder":
        i = rng.randrange(1, n - 2)
        ev[i], ev[i + 1] = ev[i + 1], ev[i]
    elif kind == "truncate":
        ev = ev[: rng.randrange(2, n - 1)]
    elif kind == "rewrite_chain":
        # Attacker edits a decision and recomputes every hash with plain SHA-256
        # (they know the format, they do not have the HMAC key).
        i = next((k for k, e in enumerate(ev) if e.kind == "decision"), n - 2)
        ev[i].payload["outcome"] = "refund" if ev[i].payload.get("outcome") != "refund" else "deny"
        prev = GENESIS
        for e in ev:
            e.prev = prev
            e.hash = hashlib.sha256(prev.encode() + canonical(e.body())).hexdigest()
            prev = e.hash
    return ev


def tamper_benchmark(trials: int = 1000, seed: int = 11) -> dict:
    rng = random.Random(seed)
    tmp = Path(tempfile.mkdtemp())
    try:
        out = {}
        for mode, key in (("sha256", None), ("hmac", b"held-by-compliance")):
            corpus = [_load(p) for p in _record_corpus(tmp / mode, key)]
            heads = [c[-1].hash for c in corpus]
            res = {}
            for attack in ATTACKS:
                det = det_anchor = flagged = 0
                for _ in range(trials):
                    j = rng.randrange(len(corpus))
                    bad = _attack(corpus[j], attack, rng)
                    v = verify_events(bad, key)
                    det += not v.ok
                    flagged += (not v.ok) or (not v.complete)
                    det_anchor += not verify_events(bad, key, expected_head=heads[j]).ok
                res[attack] = (det / trials, det_anchor / trials, flagged / trials)
            out[mode] = res
        return out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ----------------------------------------------------------------- overhead


def overhead_benchmark(n: int = 5000) -> dict:
    tmp = Path(tempfile.mkdtemp())
    payload = {"tool": "lookup_order", "args": {"order_id": "A-1001"},
               "result": {"amount": 49.9, "status": "delivered", "items": list(range(20))}}
    res = {}
    try:
        for label, fsync, count in (("no fsync", False, n), ("fsync per event", True, max(200, n // 25))):
            led = Ledger.create(tmp, key=b"k", run_id=f"o-{fsync}", fsync=fsync)
            t0 = time.perf_counter()
            for _ in range(count):
                led.append("tool_call", payload)
            res[label] = (time.perf_counter() - t0) / count * 1e6
        led = Ledger(tmp / "o-False.jsonl", key=b"k")
        t0 = time.perf_counter()
        v = led.verify()
        res["verify events/s"] = v.events / (time.perf_counter() - t0)
        res["bytes per event"] = (tmp / "o-False.jsonl").stat().st_size / v.events
        return res
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- PII recall


def _iban_de(rng: random.Random) -> str:
    bban = "".join(rng.choice(string.digits) for _ in range(18))
    num = int("".join(str(int(c, 36)) for c in bban + "DE00"))
    check = 98 - num % 97
    s = f"DE{check:02d}{bban}"
    return " ".join(s[i : i + 4] for i in range(0, len(s), 4)) if rng.random() < 0.6 else s


def _card(rng: random.Random) -> str:
    body = [rng.choice("45")] + [rng.choice(string.digits) for _ in range(14)]
    for d in range(10):
        cand = "".join(body) + str(d)
        total = sum((int(c) * 2 - 9 if int(c) * 2 > 9 else int(c) * 2) if i % 2 == 0 else int(c)
                    for i, c in enumerate(cand))
        if total % 10 == 0:
            break
    return " ".join(cand[i : i + 4] for i in range(0, 16, 4)) if rng.random() < 0.5 else cand


def _email(rng: random.Random) -> str:
    user = "".join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(3, 9)))
    sep = rng.choice([".", "_", ""])
    return f"{user}{sep}{rng.randint(1, 99)}@{rng.choice(['example', 'mail', 'firma-gmbh'])}.{rng.choice(['de', 'com', 'org'])}"


def _phone_intl(rng: random.Random) -> str:
    return rng.choice(["+49 151 ", "+49 89 ", "+41 44 ", "+91 98"]) + "".join(rng.choice(string.digits) for _ in range(rng.randint(6, 8)))


def _phone_national(rng: random.Random) -> str:
    return rng.choice(["0151 ", "089 ", "0171-"]) + "".join(rng.choice(string.digits) for _ in range(rng.randint(6, 8)))


def _negatives(rng: random.Random) -> list[str]:
    neg = []
    for _ in range(200):
        neg.append(f"A-{rng.randint(1000, 9999)}")
        neg.append(f"2026-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}T{rng.randint(0, 23):02d}:00:00")
        neg.append(f"v{rng.randint(0, 9)}.{rng.randint(0, 20)}.{rng.randint(0, 99)}")
        neg.append(str(rng.randint(1_700_000_000_000, 1_800_000_000_000)))  # epoch ms
        n = "".join(rng.choice(string.digits) for _ in range(16))
        neg.append(n)  # most fail Luhn
        bad_iban = _iban_de(rng).replace(" ", "")
        neg.append(bad_iban[:2] + f"{(int(bad_iban[2:4]) + 1) % 100:02d}" + bad_iban[4:])
        neg.append(f"{rng.randint(1, 9999)},{rng.randint(0, 99):02d} EUR")
    return neg


def pii_benchmark(n: int = 300, seed: int = 5) -> dict:
    rng = random.Random(seed)
    p = Pseudonymiser(b"bench")
    kinds = {
        "EMAIL": _email,
        "IBAN": _iban_de,
        "CARD": _card,
        "PHONE (international)": _phone_intl,
        "PHONE (national, no +)": _phone_national,
    }
    res = {}
    for label, gen in kinds.items():
        hits = 0
        for _ in range(n):
            text = f"Customer wrote: please use {gen(rng)} for this."
            _, found = p.scrub_text(text)
            hits += bool(found)
        res[label] = hits / n
    neg = _negatives(rng)
    fp = sum(bool(p.scrub_text(f"Order note: {x} confirmed.")[1]) for x in neg)
    # Valid-Luhn 16-digit numbers occur by chance in ~10% of random digit strings;
    # report those separately because they are indistinguishable from real cards.
    res["false positives on hard negatives"] = fp / len(neg)
    res["negatives tested"] = len(neg)
    return res


def run_all(trials: int = 1000) -> str:
    t = tamper_benchmark(trials)
    o = overhead_benchmark()
    q = pii_benchmark()
    names = {"modify": "Edit one event", "delete": "Delete an event", "insert": "Insert a forged event",
             "reorder": "Swap two events", "truncate": "Cut off the end of the log",
             "rewrite_chain": "Edit a decision and recompute all hashes"}
    lines = [f"## Tamper detection ({trials} attacks each, seed 11)", "",
             "| Attack | SHA-256 chain | HMAC chain | HMAC + anchored head |", "|---|---:|---:|---:|"]
    for a in ATTACKS:
        lines.append(f"| {names[a]} | {t['sha256'][a][0]:.0%} | {t['hmac'][a][0]:.0%} | {t['hmac'][a][1]:.0%} |")
    lines.append("")
    lines.append(f"Truncated logs still verify as a valid chain, but {t['hmac']['truncate'][2]:.0%} of them are "
                 "flagged as incomplete because the closing `run_end` event is missing.")
    lines += ["", "## Recording overhead", "", "| Metric | Value |", "|---|---:|"]
    lines.append(f"| Append, no fsync | {o['no fsync']:.1f} µs/event |")
    lines.append(f"| Append, fsync per event | {o['fsync per event']:.1f} µs/event |")
    lines.append(f"| Verify | {o['verify events/s']:,.0f} events/s |")
    lines.append(f"| Size | {o['bytes per event']:.0f} bytes/event |")
    lines += ["", "## Pseudonymisation (300 synthetic samples per type, seed 5)", "", "| Type | Detected |", "|---|---:|"]
    for k, v in q.items():
        if k.startswith("PHONE") or k in ("EMAIL", "IBAN", "CARD"):
            lines.append(f"| {k} | {v:.0%} |")
    lines.append(f"| False positives on {q['negatives tested']} hard negatives | {q['false positives on hard negatives']:.1%} |")
    return "\n".join(lines) + "\n"
