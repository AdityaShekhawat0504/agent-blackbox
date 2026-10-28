"""Behavioural regression tests for agents.

A scenario file lists inputs and what must (not) happen::

    [
      {"name": "small refund, delivered", "input": {...},
       "expect": {"decision": "refund",
                  "must_call": ["lookup_order", "check_policy"],
                  "must_call_before": [["check_policy", "issue_refund"]],
                  "must_not_call": ["escalate_to_human"]}}
    ]

Each scenario is run through the agent with a :class:`Recorder`, so every
failing test leaves a full, verifiable trace behind for debugging. When a
golden folder is given, each run is also diffed against the golden run of the
same scenario and a changed decision fails the test.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .diff import diff_runs, trajectory
from .ledger import Event, Ledger
from .recorder import Recorder, Run

Agent = Callable[[Any, Run], Any]


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


@dataclass
class ScenarioResult:
    name: str
    passed: bool
    failures: list[str] = field(default_factory=list)
    decision: str | None = None
    trace: str = ""

    def line(self) -> str:
        mark = "PASS" if self.passed else "FAIL"
        out = f"[{mark}] {self.name}  (decision: {self.decision})"
        for f in self.failures:
            out += f"\n         - {f}"
        return out


def check_expectations(events: list[Event], expect: dict) -> list[str]:
    steps = trajectory(events)
    tools = [s.split(":", 1)[1] for s in steps if s.startswith("tool:")]
    decision = next((e.payload.get("outcome") for e in reversed(events) if e.kind == "decision"), None)
    fails = []
    if "decision" in expect and decision != expect["decision"]:
        fails.append(f"decision was {decision!r}, expected {expect['decision']!r}")
    for t in expect.get("must_call", []):
        if t not in tools:
            fails.append(f"never called {t}")
    for t in expect.get("must_not_call", []):
        if t in tools:
            fails.append(f"called {t}, which it must not")
    for first, then in expect.get("must_call_before", []):
        if then in tools and (first not in tools or tools.index(first) > tools.index(then)):
            fails.append(f"called {then} without calling {first} first")
    if "max_tool_calls" in expect and len(tools) > expect["max_tool_calls"]:
        fails.append(f"{len(tools)} tool calls, limit {expect['max_tool_calls']}")
    return fails


def run_suite(agent: Agent, scenarios: list[dict], recorder: Recorder, golden: str | Path | None = None) -> list[ScenarioResult]:
    results = []
    for sc in scenarios:
        rid = slug(sc["name"])
        failures: list[str] = []
        try:
            with recorder.run(input=sc["input"], run_id=rid, scenario=sc["name"]) as run:
                agent(sc["input"], run)
        except Exception as exc:  # the trace already contains the error event
            failures.append(f"agent raised {type(exc).__name__}: {exc}")
        ledger = Ledger(recorder.folder / f"{rid}.jsonl", key=recorder.key)
        events = ledger.events()
        failures += check_expectations(events, sc.get("expect", {}))
        if golden is not None:
            gpath = Path(golden) / f"{rid}.jsonl"
            if gpath.exists():
                d = diff_runs(Ledger(gpath).events(), events)
                if d.decision_a != d.decision_b:
                    failures.append(f"decision changed vs golden: {d.decision_a} -> {d.decision_b}")
        decision = next((e.payload.get("outcome") for e in reversed(events) if e.kind == "decision"), None)
        results.append(ScenarioResult(sc["name"], not failures, failures, decision, str(ledger.path)))
    return results


def load_scenarios(path: str | Path) -> list[dict]:
    return json.loads(Path(path).read_text())
