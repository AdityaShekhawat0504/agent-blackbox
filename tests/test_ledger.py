import json

import pytest

from blackbox.ledger import Event, Ledger, verify_events


@pytest.fixture
def ledger(tmp_path):
    led = Ledger.create(tmp_path, key=b"k", run_id="r1")
    led.append("run_start", {"agent": "a"})
    for i in range(5):
        led.append("tool_call", {"tool": "t", "args": {"i": i}, "result": i * 2})
    led.append("decision", {"outcome": "approve"})
    led.append("run_end", {"status": "ok", "events": 7})
    return led


def lines(led):
    return led.path.read_text().splitlines()


def write(led, ls):
    led.path.write_text("\n".join(ls) + "\n")


def test_intact_chain_verifies(ledger):
    v = ledger.verify()
    assert v.ok and v.events == 8 and v.complete
    assert v.head == ledger.head


def test_edit_is_detected(ledger):
    ls = lines(ledger)
    d = json.loads(ls[3])
    d["payload"]["result"] = 999
    ls[3] = json.dumps(d)
    write(ledger, ls)
    v = ledger.verify()
    assert not v.ok and v.at_seq == 3 and "modified" in v.problem


@pytest.mark.parametrize("mutate", ["delete", "swap", "duplicate"])
def test_structural_attacks_are_detected(ledger, mutate):
    ls = lines(ledger)
    if mutate == "delete":
        del ls[4]
    elif mutate == "swap":
        ls[2], ls[3] = ls[3], ls[2]
    else:
        ls.insert(3, ls[3])
    write(ledger, ls)
    assert not ledger.verify().ok


def test_wrong_key_fails(ledger):
    assert not Ledger(ledger.path, key=b"other").verify().ok
    assert not Ledger(ledger.path, key=None).verify().ok


def test_truncation_needs_anchor(ledger):
    head = ledger.head
    write(ledger, lines(ledger)[:4])
    v = Ledger(ledger.path, key=b"k").verify()
    assert v.ok and not v.complete  # chain itself is consistent, but the run never closed
    assert not Ledger(ledger.path, key=b"k").verify(expected_head=head).ok


def test_reopening_continues_the_chain(ledger):
    again = Ledger(ledger.path, key=b"k")
    again.append("note", {"text": "appended later"})
    assert again.verify().ok


def test_garbage_line_is_reported(ledger):
    with open(ledger.path, "a") as fh:
        fh.write("{not json\n")
    v = ledger.verify()
    assert not v.ok and "unreadable" in v.problem


def test_empty_event_list_is_ok():
    assert verify_events([]).ok


def test_event_roundtrip():
    e = Event(seq=0, run_id="x", ts=1.0, kind="note", payload={"ü": "ä"})
    assert e.body()["payload"] == {"ü": "ä"}
