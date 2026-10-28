import pytest

from blackbox.demo import SCENARIOS, ScriptedModel, refund_agent
from blackbox.diff import diff_runs, trajectory
from blackbox.ledger import Ledger
from blackbox.recorder import Cassette, Recorder, ReplayMismatch
from blackbox.regress import check_expectations, run_suite


def record(tmp_path, scenario, version="v1", run_id="r"):
    rec = Recorder(tmp_path, key=b"k", agent="refund-agent", version=version)
    with rec.run(input=scenario["input"], run_id=run_id) as run:
        refund_agent(scenario["input"], run, ScriptedModel(version))
    return Ledger(tmp_path / f"{run_id}.jsonl", key=b"k")


def test_run_is_fully_recorded(tmp_path):
    led = record(tmp_path, SCENARIOS[0])
    kinds = [e.kind for e in led.events()]
    assert kinds[0] == "run_start" and kinds[-1] == "run_end"
    assert kinds.count("tool_call") == 3 and "decision" in kinds
    assert led.verify().ok


def test_errors_are_recorded_and_chain_closes(tmp_path):
    rec = Recorder(tmp_path, key=b"k")
    with pytest.raises(ValueError):
        with rec.run(run_id="boom") as run:
            run.tool("explode", lambda: (_ for _ in ()).throw(ValueError("bad input")))
    led = Ledger(tmp_path / "boom.jsonl", key=b"k")
    kinds = [e.kind for e in led.events()]
    assert kinds[-2:] == ["error", "run_end"] and led.verify().ok
    assert led.events()[1].payload["error"].startswith("ValueError")


def test_replay_reproduces_run_without_model(tmp_path):
    original = record(tmp_path, SCENARIOS[2], run_id="orig")

    class NoModel(ScriptedModel):
        def __call__(self, messages):
            raise AssertionError("model must not be called during replay")

    rec = Recorder(tmp_path, key=b"k")
    with rec.run(input=SCENARIOS[2]["input"], run_id="replay", cassette=Cassette(original.events())) as run:
        refund_agent(SCENARIOS[2]["input"], run, NoModel())
    replayed = Ledger(tmp_path / "replay.jsonl", key=b"k").events()
    assert trajectory(replayed) == trajectory(original.events())
    assert all(e.payload["request_matches"] for e in replayed if e.kind == "llm_call")


def test_replay_flags_changed_prompt(tmp_path, monkeypatch):
    original = record(tmp_path, SCENARIOS[0], run_id="orig")
    import blackbox.demo as demo

    monkeypatch.setattr(demo, "SYSTEM_PROMPT", demo.SYSTEM_PROMPT + " Be concise.")
    rec = Recorder(tmp_path, key=b"k")
    with rec.run(input=SCENARIOS[0]["input"], run_id="replay", cassette=Cassette(original.events())) as run:
        demo.refund_agent(SCENARIOS[0]["input"], run)
    calls = [e for e in Ledger(tmp_path / "replay.jsonl").events() if e.kind == "llm_call"]
    assert calls and not any(e.payload["request_matches"] for e in calls)

    with pytest.raises(ReplayMismatch):
        with rec.run(input=SCENARIOS[0]["input"], run_id="strict", cassette=Cassette(original.events(), strict=True)) as run:
            demo.refund_agent(SCENARIOS[0]["input"], run)


def test_diff_finds_the_regression(tmp_path):
    sc = SCENARIOS[3]
    a = record(tmp_path, sc, "v1", "a").events()
    b = record(tmp_path, sc, "v2", "b").events()
    d = diff_runs(a, b)
    assert d.decision_a == "escalate" and d.decision_b == "refund"
    assert d.first_divergence == 1 and not d.same_behaviour
    assert diff_runs(a, a).same_behaviour


def test_suite_passes_v1_and_catches_v2(tmp_path):
    v1 = run_suite(lambda i, r: refund_agent(i, r, ScriptedModel("v1")), SCENARIOS, Recorder(tmp_path / "v1"))
    assert all(r.passed for r in v1)
    v2 = run_suite(lambda i, r: refund_agent(i, r, ScriptedModel("v2")), SCENARIOS, Recorder(tmp_path / "v2"),
                   golden=tmp_path / "v1")
    failed = {r.name for r in v2 if not r.passed}
    assert failed == {"urgent small refund", "urgent large refund still needs a human"}


def test_expectation_rules():
    from blackbox.ledger import Event

    ev = [Event(0, "r", 0, "tool_call", {"tool": "issue_refund"}), Event(1, "r", 0, "decision", {"outcome": "refund"})]
    fails = check_expectations(ev, {"decision": "deny", "must_call": ["check_policy"],
                                    "must_call_before": [["check_policy", "issue_refund"]], "max_tool_calls": 0})
    assert len(fails) == 4
