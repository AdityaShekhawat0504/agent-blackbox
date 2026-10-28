"""Command line: blackbox verify | show | view | diff | replay | audit | erase | demo | bench."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .audit import audit
from .diff import diff_runs
from .ledger import Ledger
from .privacy import Pseudonymiser
from .viewer import render_run


def _key(args) -> bytes | None:
    k = getattr(args, "key", None) or os.environ.get("BLACKBOX_KEY")
    return k.encode() if k else None


def cmd_verify(args) -> int:
    bad = 0
    paths = sorted(Path(args.path).rglob("*.jsonl")) if Path(args.path).is_dir() else [Path(args.path)]
    for p in paths:
        v = Ledger(p, key=_key(args)).verify(expected_head=args.head)
        bad += not v.ok
        print(f"{p.name}: {v}")
    return 1 if bad else 0


def cmd_show(args) -> int:
    for e in Ledger(args.ledger).read():
        p = e.payload
        what = {
            "llm_call": lambda: f"{p.get('model')}  -> {json.dumps(p.get('response'))[:90]}",
            "tool_call": lambda: f"{p.get('tool')}({json.dumps(p.get('args'))[:60]}) -> {json.dumps(p.get('result', p.get('error')))[:60]}",
            "decision": lambda: f"{p.get('outcome')}",
            "run_start": lambda: f"{p.get('agent')} {p.get('version')}",
            "run_end": lambda: f"{p.get('status')}, decision {p.get('decision')}",
        }.get(e.kind, lambda: json.dumps(p)[:100])()
        print(f"{e.seq:>3}  {e.kind:<10} {what}")
    return 0


def cmd_view(args) -> int:
    led = Ledger(args.ledger, key=_key(args))
    out = Path(args.out or Path(args.ledger).with_suffix(".html"))
    out.write_text(render_run(led.events(), led.verify()), encoding="utf-8")
    print(f"wrote {out}")
    return 0


def cmd_diff(args) -> int:
    d = diff_runs(Ledger(args.a).events(), Ledger(args.b).events())
    print(d.summary())
    return 0 if d.same_behaviour else 1


def cmd_replay(args) -> int:
    from .demo import ScriptedModel, refund_agent
    from .recorder import Cassette, Recorder

    src = Ledger(args.ledger)
    start = src.events()[0].payload
    rec = Recorder(args.out, agent=start.get("agent", "agent"), version=f"{start.get('version')}+replay")
    with rec.run(input=start["input"], cassette=Cassette(src.events(), strict=False)) as run:
        refund_agent(start["input"], run, ScriptedModel("v1"))  # model is never called during replay
    new = Ledger(rec.last_run.ledger.path).events()
    changed = [e.seq for e in new if e.kind == "llm_call" and not e.payload.get("request_matches", True)]
    print(f"replayed into {rec.last_run.ledger.path}")
    print("all model requests identical to the recording" if not changed
          else f"{len(changed)} model request(s) differ from the recording (prompt or context changed)")
    print(diff_runs(src.events(), new).summary())
    return 0


def cmd_audit(args) -> int:
    md = audit(args.folder, key=_key(args)).markdown()
    if args.out:
        Path(args.out).write_text(md)
        print(f"wrote {args.out}")
    else:
        print(md)
    return 0


def cmd_erase(args) -> int:
    p = Pseudonymiser(b"", args.vault)
    n = p.erase(args.value)
    print(f"removed {n} vault entr{'y' if n == 1 else 'ies'}; ledgers are unchanged and still verify")
    return 0


def cmd_demo(args) -> int:
    from .demo import SCENARIOS, ScriptedModel, refund_agent
    from .recorder import Recorder
    from .regress import run_suite

    out = Path(args.out)
    pseudo = Pseudonymiser(b"demo-pii-key", out / "vault.json")
    rc = 0
    for version, golden in (("v1", None), ("v2", out / "v1")):
        rec = Recorder(out / version, key=_key(args), pseudonymiser=pseudo, agent="refund-agent",
                       version="1.0" if version == "v1" else "1.1-urgent-fastpath")
        print(f"\n== refund agent, model {version}")
        results = run_suite(lambda i, r, v=version: refund_agent(i, r, ScriptedModel(v)), SCENARIOS, rec, golden=golden)
        for r in results:
            print(r.line())
        failed = sum(not r.passed for r in results)
        print(f"{len(results) - failed}/{len(results)} scenarios passed")
        rc = rc or (1 if failed and version == "v1" else 0)
    print(f"\ntraces in {out}/v1 and {out}/v2, PII vault in {out}/vault.json")
    return rc


def cmd_bench(args) -> int:
    from .bench import run_all

    print(run_all(trials=args.trials))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="blackbox", description="Tamper-evident flight recorder for LLM agents.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("verify", help="verify one ledger or every ledger in a folder")
    s.add_argument("path")
    s.add_argument("--key", help="HMAC key (or BLACKBOX_KEY)")
    s.add_argument("--head", help="anchored head hash to compare against")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("show", help="print a run as a compact timeline")
    s.add_argument("ledger")
    s.set_defaults(fn=cmd_show)

    s = sub.add_parser("view", help="write an HTML timeline of a run")
    s.add_argument("ledger")
    s.add_argument("--out")
    s.add_argument("--key")
    s.set_defaults(fn=cmd_view)

    s = sub.add_parser("diff", help="compare the behaviour of two runs (exit 1 if different)")
    s.add_argument("a")
    s.add_argument("b")
    s.set_defaults(fn=cmd_diff)

    s = sub.add_parser("replay", help="re-run the demo agent against the recorded model outputs, no model calls")
    s.add_argument("ledger")
    s.add_argument("--out", default="replays")
    s.set_defaults(fn=cmd_replay)

    s = sub.add_parser("audit", help="audit summary over a folder of runs (markdown)")
    s.add_argument("folder")
    s.add_argument("--key")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_audit)

    s = sub.add_parser("erase", help="erase a person's data from the PII vault")
    s.add_argument("value", help="e-mail, IBAN, ... as originally seen")
    s.add_argument("--vault", required=True)
    s.set_defaults(fn=cmd_erase)

    s = sub.add_parser("demo", help="record the refund-agent demo and run its regression suite")
    s.add_argument("--out", default="demo-runs")
    s.add_argument("--key")
    s.set_defaults(fn=cmd_demo)

    s = sub.add_parser("bench", help="tamper, overhead and PII benchmarks")
    s.add_argument("--trials", type=int, default=1000)
    s.set_defaults(fn=cmd_bench)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
