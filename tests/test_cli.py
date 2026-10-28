from blackbox.cli import main


def test_demo_verify_audit_view(tmp_path, capsys):
    out = tmp_path / "demo"
    assert main(["demo", "--out", str(out), "--key", "s"]) == 0
    assert main(["verify", str(out), "--key", "s"]) == 0
    assert main(["verify", str(out), "--key", "wrong"]) == 1
    assert main(["audit", str(out), "--key", "s", "--out", str(tmp_path / "audit.md")]) == 0
    md = (tmp_path / "audit.md").read_text()
    assert "14/14 ledgers verified" in md and "refund-agent 1.1-urgent-fastpath" in md
    run = out / "v2" / "urgent-large-refund-still-needs-a-human.jsonl"
    assert main(["view", str(run), "--key", "s", "--out", str(tmp_path / "r.html")]) == 0
    assert "chain verified" in (tmp_path / "r.html").read_text()
    assert main(["diff", str(out / "v1" / run.name), str(run)]) == 1
    assert "DECISION CHANGED" in capsys.readouterr().out


def test_erase_cli(tmp_path):
    main(["demo", "--out", str(tmp_path / "d")])
    assert main(["erase", "lena.maier@example.de", "--vault", str(tmp_path / "d" / "vault.json")]) == 0
    assert "lena.maier@example.de" not in (tmp_path / "d" / "vault.json").read_text()
