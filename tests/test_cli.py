"""CLI tests: exit codes and output formats."""

import json
from pathlib import Path

from delegationbench.cli import main

ROOT = Path(__file__).resolve().parent.parent
ATTACK = ROOT / "scenarios" / "attacks" / "attack-008-malicious-document.yaml"
BENIGN = ROOT / "scenarios" / "benign" / "benign-001-approved-payment.yaml"
SCENARIOS_DIR = ROOT / "scenarios"


def test_run_attack_exit_0(capsys):
    assert main(["run", str(ATTACK)]) == 0
    out = capsys.readouterr().out
    assert "FAIL: Cross-agent privilege escalation" in out
    assert "payment.execute" in out
    assert "reader -> payment" in out


def test_run_benign_exit_0(capsys):
    assert main(["run", str(BENIGN)]) == 0
    out = capsys.readouterr().out
    assert "PASS: No violation" in out


def test_run_directory_exit_0(capsys):
    n_scenarios = len(list(SCENARIOS_DIR.rglob("*.yaml")))
    assert main(["run", str(SCENARIOS_DIR)]) == 0
    out = capsys.readouterr().out
    assert "attack-008" in out
    assert "benign-001" in out
    assert f"{n_scenarios}/{n_scenarios} scenarios match expectations" in out


def test_json_format_is_valid_json(capsys):
    assert main(["run", str(ATTACK), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["scenario"]["id"] == "attack-008"
    assert report["verdict"] == "violation"
    assert set(report["kinds"]) >= {"V1", "V2"}
    assert report["expect_match"] is True
    assert isinstance(report["trace"], list) and report["trace"]


def test_missing_file_exit_2(capsys):
    assert main(["run", str(ROOT / "scenarios" / "nope.yaml")]) == 2
    assert "error" in capsys.readouterr().err


def test_invalid_scenario_exit_2(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("schema: 2\n")
    assert main(["run", str(bad)]) == 2
    assert "error" in capsys.readouterr().err


def test_expect_mismatch_exit_1(tmp_path, capsys):
    # Benign scenario body, but the contract demands a violation.
    mismatched = tmp_path / "mismatch.yaml"
    mismatched.write_text(BENIGN.read_text().replace(
        "expect:\n  verdict: clean",
        "expect:\n  verdict: violation\n  violation_kinds: [V2]"))
    assert main(["run", str(mismatched)]) == 1
    assert "MISMATCH" in capsys.readouterr().out


def test_directory_json_format(capsys):
    n_scenarios = len(list(SCENARIOS_DIR.rglob("*.yaml")))
    assert main(["run", str(SCENARIOS_DIR), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data) == {"metrics", "reports"}
    reports = data["reports"]
    assert isinstance(reports, list)
    ids = {r["scenario"]["id"] for r in reports}
    assert len(ids) == n_scenarios
    assert {"attack-008", "benign-001"} <= ids
    assert all(r["expect_match"] for r in reports)
    assert data["metrics"]["scenarios"] == n_scenarios
