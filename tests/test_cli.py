"""CLI tests: exit codes and output formats."""

import json

from delegationbench.cli import main
from delegationbench.corpus import corpus_path

SCENARIOS_DIR = corpus_path()
ATTACK = SCENARIOS_DIR / "attacks" / "attack-008-malicious-document.yaml"
BENIGN = SCENARIOS_DIR / "benign" / "benign-001-approved-payment.yaml"


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
    # Neither a local path nor the bundled corpus has this file.
    assert main(["run", "scenarios/nope.yaml"]) == 2
    assert "error" in capsys.readouterr().err


def test_bundled_corpus_fallback_directory(tmp_path, monkeypatch, capsys):
    """`run scenarios/` with no local scenarios/ resolves against the
    corpus bundled inside the package (wheel/sdist install context)."""
    monkeypatch.chdir(tmp_path)
    n_scenarios = len(list(SCENARIOS_DIR.rglob("*.yaml")))
    assert main(["run", "scenarios/"]) == 0
    captured = capsys.readouterr()
    assert "does not exist in the current directory" in captured.err
    assert "corpus bundled with the package" in captured.err
    assert f"{n_scenarios}/{n_scenarios} scenarios match expectations" \
        in captured.out
    # The footer must not let 75/75 be misread as a detection rate.
    assert (f"Corpus contract validation: {n_scenarios}/{n_scenarios} "
            "scenario contracts matched") in captured.out
    assert "not a" in captured.out and "detection rate" in captured.out


def test_bundled_corpus_fallback_single_file(tmp_path, monkeypatch, capsys):
    """Single-file resolution through the same bundled-corpus fallback."""
    monkeypatch.chdir(tmp_path)
    assert main(["run",
                 "scenarios/attacks/attack-008-malicious-document.yaml"]) == 0
    captured = capsys.readouterr()
    assert "does not exist in the current directory" in captured.err
    assert "corpus bundled with the package" in captured.err
    assert "FAIL: Cross-agent privilege escalation" in captured.out


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


def test_defense_does_not_hide_tampered_baseline_expect(tmp_path, capsys):
    """A defense pass must not mask a corrupted no-defense contract."""
    mismatched = tmp_path / "mismatch-under-defense.yaml"
    mismatched.write_text(ATTACK.read_text().replace(
        "expect:\n  verdict: violation",
        "expect:\n  verdict: clean"))
    assert main(["run", str(mismatched),
                 "--defense", "envelope"]) == 1
    out = capsys.readouterr().out
    assert "Baseline expect contract: MISMATCH" in out
    assert "Defense contract (contained expected): MATCH" in out
    assert "Combined expect contract: MISMATCH" in out


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


def test_cyclic_scenario_exit_2_clean_error(tmp_path, capsys):
    """Review FIX 6: a cyclic delegation scenario aborts with a clean
    EngineError message on stderr and exit code 2 — no traceback."""
    cyclic = tmp_path / "cyclic.yaml"
    cyclic.write_text("""
schema: 1
id: cyclic
name: cyclic-delegation
type: attack
description: A delegates to B, B delegates back to A
principal: user-123
grant:
  allowed_actions: [docs.read]
  max_delegation_depth: 9999
  ttl_seconds: null
resources:
  docs:
    d1: "PING"
agents:
  alpha:
    capabilities: [docs.read]
    rules:
      - match: 'PING'
        then:
          delegate: {agent: beta, task: "PING", actions: [docs.read], args: {}}
  beta:
    capabilities: [docs.read]
    rules:
      - match: 'PING'
        then:
          delegate: {agent: alpha, task: "PING", actions: [docs.read], args: {}}
task:
  agent: alpha
  read: [d1]
  description: "cycle"
""")
    assert main(["run", str(cyclic)]) == 2
    captured = capsys.readouterr()
    assert "chain budget" in captured.err
    assert "Traceback" not in captured.err


# -- errored files surface in machine reports (review FIX 1) --------------------


def _mixed_dir(tmp_path):
    """A directory with one valid and one broken scenario."""
    good = tmp_path / "good.yaml"
    good.write_text(BENIGN.read_text())
    broken = tmp_path / "broken-thing.yaml"
    broken.write_text("schema: 2\n")
    return tmp_path


def test_directory_junit_contains_error_testcase(tmp_path, capsys):
    """Directory mode: a broken file must appear as an <error> testcase
    (classname from the file name) — not silently dropped from the
    JUnit while the exit code says 2."""
    import xml.etree.ElementTree as ET
    assert main(["run", str(_mixed_dir(tmp_path)),
                 "--format", "junit"]) == 2
    root = ET.fromstring(capsys.readouterr().out)
    assert root.attrib["errors"] == "1"
    error_cases = [c for c in root.findall(".//testcase")
                   if c.find("error") is not None]
    assert len(error_cases) == 1
    assert error_cases[0].attrib["classname"] == "broken-thing"
    assert error_cases[0].find("error").attrib["type"] == "ScenarioError"


def test_directory_sarif_contains_load_error_result(tmp_path, capsys):
    assert main(["run", str(_mixed_dir(tmp_path)),
                 "--format", "sarif"]) == 2
    sarif = json.loads(capsys.readouterr().out)
    results = sarif["runs"][0]["results"]
    load_errors = [r for r in results
                   if r["ruleId"] == "scenario-load-error"]
    assert len(load_errors) == 1
    assert load_errors[0]["level"] == "error"
    assert load_errors[0]["locations"][0]["physicalLocation"][
        "artifactLocation"]["uri"].endswith("broken-thing.yaml")


def test_directory_json_lists_errors(tmp_path, capsys):
    assert main(["run", str(_mixed_dir(tmp_path)),
                 "--format", "json"]) == 2
    data = json.loads(capsys.readouterr().out)
    assert len(data["reports"]) == 1
    assert len(data["errors"]) == 1
    assert data["errors"][0]["file"].endswith("broken-thing.yaml")
    assert data["errors"][0]["type"] == "ScenarioError"


def test_benchmark_report_written_despite_directory_errors(tmp_path,
                                                           capsys):
    """--benchmark-report is written whenever any reports exist, even
    when some files errored (exit 2)."""
    out = tmp_path / "bench.json"
    assert main(["run", str(_mixed_dir(tmp_path)),
                 "--benchmark-report", str(out)]) == 2
    assert out.is_file()
    document = json.loads(out.read_text())
    assert len(document["reports"]) == 1


def test_benchmark_report_warns_when_nothing_ran(tmp_path, capsys):
    """Single-file error path: no reports exist, so the benchmark
    report is not written — but a clear warning is emitted."""
    broken = tmp_path / "broken.yaml"
    broken.write_text("schema: 2\n")
    out = tmp_path / "bench.json"
    assert main(["run", str(broken),
                 "--benchmark-report", str(out)]) == 2
    assert not out.exists()
    assert "benchmark report" in capsys.readouterr().err


def test_single_file_junit_error_testcase(tmp_path, capsys):
    """Single-file mode with --format junit on a broken file also
    emits the <error> testcase instead of nothing."""
    import xml.etree.ElementTree as ET
    broken = tmp_path / "broken-one.yaml"
    broken.write_text("schema: 2\n")
    assert main(["run", str(broken), "--format", "junit"]) == 2
    root = ET.fromstring(capsys.readouterr().out)
    assert root.attrib["errors"] == "1"
    case = root.findall(".//testcase")[0]
    assert case.attrib["classname"] == "broken-one"


def test_broken_pipe_exits_quietly(tmp_path, capsys, monkeypatch):
    """`--format json | head`: a closed stdout must exit with code 1
    and no traceback (standard SIGPIPE handling)."""
    class ClosedPipe:
        def write(self, *_args, **_kwargs):
            raise BrokenPipeError

        def flush(self):
            pass

    monkeypatch.setattr("sys.stdout", ClosedPipe())
    assert main(["run", str(ATTACK), "--format", "json"]) == 1
