"""Audit summary over a folder of runs: what a reviewer or auditor asks for first.

Verifies every ledger, then reports the period covered, which agent and model
versions were active, what was decided, where humans intervened and what
failed. Mapped to the record-keeping duties in the EU AI Act (Art. 12) in the
README; this is engineering support for those duties, not legal advice.
"""

from __future__ import annotations

import datetime as dt
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .ledger import Ledger


@dataclass
class AuditReport:
    runs: int = 0
    verified: int = 0
    tampered: list[tuple[str, str]] = field(default_factory=list)
    first: float | None = None
    last: float | None = None
    agents: Counter = field(default_factory=Counter)
    models: Counter = field(default_factory=Counter)
    decisions: Counter = field(default_factory=Counter)
    human: list[tuple[str, str, str]] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    replays: int = 0
    pii_tokens: int = 0
    heads: dict[str, str] = field(default_factory=dict)

    def markdown(self) -> str:
        def ts(x):
            return dt.datetime.fromtimestamp(x, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if x else "n/a"

        lines = [
            "# Agent audit summary",
            "",
            f"- Period: {ts(self.first)} to {ts(self.last)}",
            f"- Runs: {self.runs} ({self.replays} replays)",
            f"- Integrity: {self.verified}/{self.runs} ledgers verified"
            + (f", **{len(self.tampered)} TAMPERED**" if self.tampered else ""),
            f"- Personal data: {self.pii_tokens} values pseudonymised before logging",
            "",
            "## Agent and model versions in use",
            "",
            "| Version | Runs |",
            "|---|---:|",
            *[f"| {k} | {v} |" for k, v in self.agents.most_common()],
            "",
            "| Model | Calls |",
            "|---|---:|",
            *[f"| {k} | {v} |" for k, v in self.models.most_common()],
            "",
            "## Decisions",
            "",
            "| Outcome | Runs |",
            "|---|---:|",
            *[f"| {k} | {v} |" for k, v in self.decisions.most_common()],
            "",
            f"## Human oversight ({len(self.human)} events)",
            "",
            *([f"- `{r}`: {a} by {b}" for r, a, b in self.human] or ["- none recorded"]),
            "",
            f"## Errors ({len(self.errors)})",
            "",
            *([f"- `{r}`: {e}" for r, e in self.errors] or ["- none"]),
        ]
        if self.tampered:
            lines += ["", "## Integrity failures", "", *[f"- `{r}`: {p}" for r, p in self.tampered]]
        lines += ["", "## Ledger fingerprints (anchor these elsewhere)", "", "| Run | Head |", "|---|---|"]
        lines += [f"| {r} | `{h[:24]}` |" for r, h in sorted(self.heads.items())]
        return "\n".join(lines) + "\n"


def audit(folder: str | Path, key: bytes | None = None) -> AuditReport:
    rep = AuditReport()
    for path in sorted(Path(folder).rglob("*.jsonl")):
        led = Ledger(path, key=key)
        rep.runs += 1
        v = led.verify()
        if v.ok:
            rep.verified += 1
        else:
            rep.tampered.append((path.stem, str(v)))
        events = led._safe_read()
        if isinstance(events, Exception):
            continue
        rep.heads[path.stem] = v.head
        for e in events:
            rep.first = e.ts if rep.first is None else min(rep.first, e.ts)
            rep.last = e.ts if rep.last is None else max(rep.last, e.ts)
            p = e.payload
            if e.kind == "run_start":
                rep.agents[f"{p.get('agent')} {p.get('version')}"] += 1
                rep.replays += bool(p.get("replay"))
            elif e.kind == "llm_call":
                rep.models[p.get("model")] += 1
            elif e.kind == "decision":
                rep.decisions[p.get("outcome")] += 1
            elif e.kind == "human":
                rep.human.append((path.stem, p.get("action"), p.get("by")))
            elif e.kind == "error":
                rep.errors.append((path.stem, p.get("error")))
        raw = path.read_text()
        rep.pii_tokens += len(set(re.findall(r"<[A-Z]+:[0-9a-f]{10}>", raw)))
    return rep
