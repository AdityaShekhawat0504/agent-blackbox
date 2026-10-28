"""Compare two recorded runs: where did the agent's behaviour diverge?"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field

from .ledger import Event, canonical


def trajectory(events: list[Event]) -> list[str]:
    """The behaviour of a run as a list of steps: tool calls and the decision."""
    steps = []
    for e in events:
        if e.kind == "tool_call":
            steps.append(f"tool:{e.payload.get('tool')}")
        elif e.kind == "decision":
            steps.append(f"decision:{e.payload.get('outcome')}")
        elif e.kind == "human":
            steps.append(f"human:{e.payload.get('action')}")
    return steps


def _decision(events: list[Event]) -> str | None:
    for e in reversed(events):
        if e.kind == "decision":
            return e.payload.get("outcome")
    return None


def _tool_args(events: list[Event]) -> list[tuple[str, bytes]]:
    return [(e.payload.get("tool"), canonical(e.payload.get("args", {}))) for e in events if e.kind == "tool_call"]


@dataclass
class RunDiff:
    a: list[str]
    b: list[str]
    decision_a: str | None
    decision_b: str | None
    similarity: float
    first_divergence: int | None  # index into the trajectory
    ops: list[tuple[str, list[str], list[str]]] = field(default_factory=list)
    args_changed: list[str] = field(default_factory=list)
    model_calls: tuple[int, int] = (0, 0)

    @property
    def same_behaviour(self) -> bool:
        return self.a == self.b and not self.args_changed

    def summary(self) -> str:
        lines = []
        if self.same_behaviour:
            lines.append("Same behaviour: identical tool sequence, arguments and decision.")
        else:
            if self.decision_a != self.decision_b:
                lines.append(f"DECISION CHANGED: {self.decision_a} -> {self.decision_b}")
            if self.first_divergence is not None:
                lines.append(f"First divergence at step {self.first_divergence + 1}.")
            for tag, x, y in self.ops:
                if tag == "delete":
                    lines.append(f"  - dropped   {', '.join(x)}")
                elif tag == "insert":
                    lines.append(f"  + added     {', '.join(y)}")
                elif tag == "replace":
                    lines.append(f"  ~ replaced  {', '.join(x)}  ->  {', '.join(y)}")
            for t in self.args_changed:
                lines.append(f"  ~ arguments changed for {t}")
        lines.append(f"Trajectory similarity {self.similarity:.2f}; model calls {self.model_calls[0]} -> {self.model_calls[1]}.")
        return "\n".join(lines)


def diff_runs(a: list[Event], b: list[Event]) -> RunDiff:
    ta, tb = trajectory(a), trajectory(b)
    sm = difflib.SequenceMatcher(a=ta, b=tb, autojunk=False)
    ops = [(tag, ta[i1:i2], tb[j1:j2]) for tag, i1, i2, j1, j2 in sm.get_opcodes() if tag != "equal"]
    first = None
    for i, (x, y) in enumerate(zip(ta, tb)):
        if x != y:
            first = i
            break
    if first is None and len(ta) != len(tb):
        first = min(len(ta), len(tb))

    args_changed = []
    aa, ab = _tool_args(a), _tool_args(b)
    for (na, xa), (nb, xb) in zip(aa, ab):
        if na == nb and xa != xb:
            args_changed.append(na)

    return RunDiff(
        a=ta,
        b=tb,
        decision_a=_decision(a),
        decision_b=_decision(b),
        similarity=sm.ratio() if (ta or tb) else 1.0,
        first_divergence=first,
        ops=ops,
        args_changed=args_changed,
        model_calls=(sum(e.kind == "llm_call" for e in a), sum(e.kind == "llm_call" for e in b)),
    )
