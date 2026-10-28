from blackbox.ledger import Ledger
from blackbox.privacy import Pseudonymiser
from blackbox.recorder import Recorder


def test_detects_and_tokenises(tmp_path):
    p = Pseudonymiser(b"k", tmp_path / "vault.json")
    text, found = p.scrub_text("Mail lena@example.de, IBAN DE89 3704 0044 0532 0130 00, card 4111 1111 1111 1111, tel +49 151 23456789")
    assert sorted(found) == ["CARD", "EMAIL", "IBAN", "PHONE"]
    assert "lena@example.de" not in text and "<EMAIL:" in text
    assert p.reveal(text).startswith("Mail lena@example.de")


def test_rejects_checksum_failures():
    p = Pseudonymiser(b"k")
    _, found = p.scrub_text("order 4111 1111 1111 1112 and DE00 3704 0044 0532 0130 00 and ts 1730000000123")
    assert found == []


def test_tokens_are_stable_and_keyed():
    a, b = Pseudonymiser(b"k1"), Pseudonymiser(b"k2")
    assert a.token("EMAIL", "X@Y.de") == a.token("EMAIL", "x@y.de")
    assert a.token("EMAIL", "x@y.de") != b.token("EMAIL", "x@y.de")


def test_erasure_keeps_ledger_valid(tmp_path):
    vault = tmp_path / "vault.json"
    rec = Recorder(tmp_path / "runs", key=b"chain", pseudonymiser=Pseudonymiser(b"pii", vault))
    with rec.run(input={"message": "refund for anna@example.com"}, run_id="r") as run:
        run.decision("refund")
    led = Ledger(tmp_path / "runs" / "r.jsonl", key=b"chain")
    raw = led.path.read_text()
    assert "anna@example.com" not in raw

    p = Pseudonymiser(b"pii", vault)
    assert "anna@example.com" in p.reveal(raw)
    assert p.erase("anna@example.com") == 1
    assert "anna@example.com" not in Pseudonymiser(b"pii", vault).reveal(raw)
    assert led.verify().ok  # ledger untouched
