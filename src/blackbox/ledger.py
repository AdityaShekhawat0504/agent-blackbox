"""Append-only, hash-chained event ledger.

Every event stores the hash of the event before it, so changing, deleting,
inserting or reordering any event breaks the chain from that point on.

Threat model, honestly stated:

* With a plain SHA-256 chain, anyone who can rewrite the *whole* file can also
  recompute every hash. The chain then only proves internal consistency.
* With an HMAC key (``key=...``) the chain can only be recomputed by someone
  who holds the key. Keep the key in a different system from the logs (a
  secrets manager, the compliance team's vault) and a full rewrite is caught.
* Deleting the *tail* of a log leaves a valid but shorter chain. The
  ``run_end`` event records the event count, and :meth:`Ledger.head` gives a
  short fingerprint you can anchor elsewhere (ticket, e-mail, database) to
  detect truncation of a finished run.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator

GENESIS = "0" * 64
SCHEMA_VERSION = 1


def canonical(obj) -> bytes:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


@dataclass
class Event:
    seq: int
    run_id: str
    ts: float
    kind: str  # run_start | llm_call | tool_call | decision | human | error | run_end
    payload: dict = field(default_factory=dict)
    prev: str = GENESIS
    hash: str = ""

    def body(self) -> dict:
        d = asdict(self)
        d.pop("hash")
        return d


def _digest(prev: str, body: dict, key: bytes | None) -> str:
    msg = prev.encode() + canonical(body)
    if key:
        return hmac.new(key, msg, hashlib.sha256).hexdigest()
    return hashlib.sha256(msg).hexdigest()


@dataclass
class Verification:
    ok: bool
    events: int
    head: str
    problem: str = ""
    at_seq: int | None = None
    complete: bool = True  # ends with run_end; False for crashed, running or truncated runs

    def __str__(self) -> str:
        if self.ok:
            tail = "" if self.complete else " (no run_end: still running, crashed or truncated)"
            return f"OK: {self.events} events, chain intact, head {self.head[:16]}{tail}"
        return f"TAMPERED at seq {self.at_seq}: {self.problem}"


class Ledger:
    """One JSONL file per run. Writes are append-only and flushed per event."""

    def __init__(self, path: str | Path, key: bytes | None = None, fsync: bool = False):
        self.path = Path(path)
        self.key = key
        self.fsync = fsync
        self._seq = 0
        self._prev = GENESIS
        self.run_id = self.path.stem
        if self.path.exists() and self.path.stat().st_size:
            last = None
            for last in self.read():
                pass
            if last is not None:
                self._seq, self._prev, self.run_id = last.seq + 1, last.hash, last.run_id

    # ---------------------------------------------------------------- write

    @classmethod
    def create(cls, folder: str | Path, key: bytes | None = None, run_id: str | None = None, **kw) -> "Ledger":
        folder = Path(folder)
        folder.mkdir(parents=True, exist_ok=True)
        run_id = run_id or time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8]
        led = cls(folder / f"{run_id}.jsonl", key=key, **kw)
        led.run_id = run_id
        return led

    def append(self, kind: str, payload: dict | None = None, ts: float | None = None) -> Event:
        ev = Event(
            seq=self._seq,
            run_id=self.run_id,
            ts=time.time() if ts is None else ts,
            kind=kind,
            payload=payload or {},
            prev=self._prev,
        )
        ev.hash = _digest(ev.prev, ev.body(), self.key)
        line = canonical(asdict(ev)).decode() + "\n"
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line)
            if self.fsync:
                fh.flush()
                os.fsync(fh.fileno())
        self._seq += 1
        self._prev = ev.hash
        return ev

    # ----------------------------------------------------------------- read

    def read(self) -> Iterator[Event]:
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield Event(**json.loads(line))

    def events(self) -> list[Event]:
        return list(self.read())

    @property
    def head(self) -> str:
        """Hash of the last event: a short fingerprint to anchor elsewhere."""
        return self._prev

    # --------------------------------------------------------------- verify

    def verify(self, expected_head: str | None = None) -> Verification:
        return verify_events(self._safe_read(), self.key, expected_head)

    def _safe_read(self) -> list[Event] | Exception:
        try:
            return self.events()
        except (json.JSONDecodeError, TypeError) as exc:
            return exc


def verify_events(
    events: list[Event] | Exception, key: bytes | None = None, expected_head: str | None = None
) -> Verification:
    if isinstance(events, Exception):
        return Verification(False, 0, "", f"unreadable line ({events.__class__.__name__})", 0)
    prev = GENESIS
    run_id = events[0].run_id if events else ""
    for i, ev in enumerate(events):
        if ev.seq != i:
            return Verification(False, i, prev, f"sequence gap: expected {i}, found {ev.seq}", i)
        if ev.run_id != run_id:
            return Verification(False, i, prev, "event from a different run", i)
        if ev.prev != prev:
            return Verification(False, i, prev, "link to previous event broken (deleted, inserted or reordered)", i)
        if _digest(ev.prev, ev.body(), key) != ev.hash:
            return Verification(False, i, prev, "content does not match its hash (modified)", i)
        prev = ev.hash
    if events and events[-1].kind == "run_end":
        declared = events[-1].payload.get("events")
        if declared is not None and declared != len(events) - 1:
            return Verification(False, len(events) - 1, prev, "run_end count does not match", len(events) - 1)
    if expected_head is not None and prev != expected_head:
        return Verification(False, len(events), prev, "head differs from anchored fingerprint (truncated?)", len(events))
    complete = bool(events) and events[-1].kind == "run_end"
    return Verification(True, len(events), prev, complete=complete)
