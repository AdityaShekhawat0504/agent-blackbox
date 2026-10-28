"""Record an agent run: every model call, tool call, decision and human action.

Usage::

    rec = Recorder("logs/", key=secret, pseudonymiser=Pseudonymiser(pii_key, "vault.json"),
                   agent="refund-agent", version="1.4.0")
    with rec.run(input={"message": msg}) as run:
        reply = run.llm(model="claude-x", messages=msgs, call=lambda: client.create(...))
        order = run.tool("lookup_order", lookup_order, order_id="A-1001")
        run.decision("refund", amount=49.0, reason="within 30 days")

The same ``run`` object replays a recorded run when a :class:`Cassette` is
passed: model calls return the recorded responses (and say whether the
request still matches), so an agent can be re-run deterministically after a
prompt or code change without calling a model at all.
"""

from __future__ import annotations

import hashlib
import platform
import time
import traceback
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable

from .ledger import Event, Ledger, canonical
from .privacy import Pseudonymiser


def request_hash(model: str, messages: Any, params: dict | None) -> str:
    return hashlib.sha256(canonical({"model": model, "messages": messages, "params": params or {}})).hexdigest()[:16]


class ReplayMismatch(RuntimeError):
    """Raised in strict replay when the agent asks for something the recording does not contain."""


class Cassette:
    """Recorded model responses and tool results of one run, served back in order."""

    def __init__(self, events: list[Event], strict: bool = False, replay_tools: bool = True):
        self.llm = [e for e in events if e.kind == "llm_call"]
        self.tools = [e for e in events if e.kind == "tool_call"]
        self.strict = strict
        self.replay_tools = replay_tools
        self._i_llm = 0
        self._i_tool = 0

    @classmethod
    def from_ledger(cls, path: str | Path, **kw) -> "Cassette":
        return cls(Ledger(path).events(), **kw)

    def next_llm(self, req_hash: str) -> tuple[Any, bool]:
        if self._i_llm >= len(self.llm):
            raise ReplayMismatch(f"agent made model call #{self._i_llm + 1}, recording has {len(self.llm)}")
        ev = self.llm[self._i_llm]
        self._i_llm += 1
        matches = ev.payload.get("request_hash") == req_hash
        if self.strict and not matches:
            raise ReplayMismatch(f"model call #{self._i_llm} request differs from the recording")
        return ev.payload.get("response"), matches

    def next_tool(self, name: str) -> tuple[Any, bool]:
        if self._i_tool >= len(self.tools):
            raise ReplayMismatch(f"agent made tool call #{self._i_tool + 1} ({name}), recording has {len(self.tools)}")
        ev = self.tools[self._i_tool]
        self._i_tool += 1
        same = ev.payload.get("tool") == name
        if self.strict and not same:
            raise ReplayMismatch(f"tool call #{self._i_tool}: agent called {name}, recording has {ev.payload.get('tool')}")
        return ev.payload.get("result"), same


class Run:
    def __init__(self, ledger: Ledger, scrub: Callable[[Any], Any], cassette: Cassette | None = None):
        self.ledger = ledger
        self._scrub = scrub
        self.cassette = cassette
        self.decision_value: str | None = None
        self.n = 0

    def _log(self, kind: str, payload: dict) -> Event:
        self.n += 1
        return self.ledger.append(kind, self._scrub(payload))

    # ------------------------------------------------------------------ calls

    def llm(self, model: str, messages: Any, call: Callable[[], Any] | None = None, params: dict | None = None,
            usage: Callable[[Any], dict] | None = None) -> Any:
        """Run (or replay) one model call and record request, response and latency."""
        scrubbed = self._scrub(messages)
        rh = request_hash(model, scrubbed, params)
        t0 = time.perf_counter()
        replayed, matches = False, None
        if self.cassette is not None:
            response, matches = self.cassette.next_llm(rh)
            replayed = True
        else:
            if call is None:
                raise ValueError("call is required when not replaying")
            response = call()
        latency = (time.perf_counter() - t0) * 1000
        payload = {
            "model": model,
            "params": params or {},
            "request_hash": rh,
            "messages": scrubbed,
            "response": response,
            "latency_ms": round(latency, 2),
        }
        if usage is not None and not replayed:
            payload["usage"] = usage(response)
        if replayed:
            payload["replayed"] = True
            payload["request_matches"] = matches
        self._log("llm_call", payload)
        return response

    def tool(self, name: str, fn: Callable[..., Any], **args) -> Any:
        """Run (or replay) a tool and record its arguments, result or error."""
        t0 = time.perf_counter()
        if self.cassette is not None and self.cassette.replay_tools:
            result, same = self.cassette.next_tool(name)
            self._log("tool_call", {"tool": name, "args": args, "result": result, "replayed": True,
                                    "matches_recording": same, "latency_ms": 0.0})
            return result
        try:
            result = fn(**args)
        except Exception as exc:  # recorded, then re-raised
            self._log("tool_call", {"tool": name, "args": args, "error": f"{type(exc).__name__}: {exc}",
                                    "latency_ms": round((time.perf_counter() - t0) * 1000, 2)})
            raise
        self._log("tool_call", {"tool": name, "args": args, "result": result,
                                "latency_ms": round((time.perf_counter() - t0) * 1000, 2)})
        return result

    def decision(self, outcome: str, **details) -> None:
        """The outcome the agent acted on (approve, refund, escalate, ...)."""
        self.decision_value = outcome
        self._log("decision", {"outcome": outcome, **details})

    def human(self, action: str, by: str, **details) -> None:
        """Human oversight: a person reviewed, approved, overrode or stopped the agent."""
        self._log("human", {"action": action, "by": by, **details})

    def note(self, text: str, **details) -> None:
        self._log("note", {"text": text, **details})


class Recorder:
    def __init__(self, folder: str | Path, key: bytes | None = None, pseudonymiser: Pseudonymiser | None = None,
                 agent: str = "agent", version: str = "0", fsync: bool = False, **meta):
        self.folder = Path(folder)
        self.key = key
        self.pseudo = pseudonymiser
        self.meta = {"agent": agent, "version": version, **meta}
        self.fsync = fsync
        self.last_run: Run | None = None

    def _scrub(self, obj):
        return self.pseudo.scrub(obj) if self.pseudo else obj

    @contextmanager
    def run(self, input: Any = None, run_id: str | None = None, cassette: Cassette | None = None, **tags):
        ledger = Ledger.create(self.folder, key=self.key, run_id=run_id, fsync=self.fsync)
        run = Run(ledger, self._scrub, cassette)
        self.last_run = run
        start = time.time()
        ledger.append("run_start", self._scrub({
            **self.meta,
            "tags": tags,
            "input": input,
            "replay": cassette is not None,
            "python": platform.python_version(),
            "host": platform.node(),
            "schema": 1,
        }))
        status, error = "ok", None
        try:
            yield run
        except Exception as exc:
            status, error = "error", f"{type(exc).__name__}: {exc}"
            ledger.append("error", self._scrub({"error": error, "trace": traceback.format_exc(limit=5)}))
            raise
        finally:
            if self.pseudo:
                self.pseudo.save()
            ledger.append("run_end", {
                "status": status,
                "decision": run.decision_value,
                "events": ledger._seq,  # events before this one
                "duration_s": round(time.time() - start, 4),
            })
