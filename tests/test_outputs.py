import json
import xml.etree.ElementTree as ET

from delegationbench.outputs import (
    REPORT_SCHEMA,
    benchmark_document,
    reports_to_junit,
    reports_to_sarif,
    write_json,
)


def report(scenario_id="attack-001", *, verdict="violation",
           kinds=None, expect_match=True):
    return {
        "scenario": {
            "id": scenario_id,
            "name": "example",
            "type": "attack" if scenario_id.startswith("attack") else "benign",
            "description": "test",
        },
        "verdict": verdict,
        "kinds": kinds or (["V2"] if verdict == "violation" else []),
        "reasons": ["V2 confused deputy: example"]
        if verdict == "violation" else [],
        "unauthorized_actions": ["payment.execute"]
        if verdict == "violation" else [],
        "unauthorized_calls": 1 if verdict == "violation" else 0,
        "blocked": [],
        "blocked_calls": 0,
        "escalation_depth": 1,
        "delegation_path": ["reader", "payment"],
        "outcomes": None,
        "outcomes_met": None,
        "trace": [],
        "timing": {"virtual_seconds": 0},
        "expect": {"verdict": verdict},
        "expect_match": expect_match,
    }


def test_junit_marks_contract_mismatch_as_failure():
    xml = reports_to_junit([
        report(),
        report("benign-001", verdict="clean", expect_match=False),
    ])
    root = ET.fromstring(xml)
    assert root.attrib == {
        "name": "DelegationBench",
        "tests": "2",
        "failures": "1",
        "errors": "0",
        "skipped": "0",
    }
    assert len(root.findall(".//failure")) == 1


def test_sarif_has_rules_locations_and_stable_fingerprint():
    item = report(kinds=["V1", "V2"])
    first = reports_to_sarif(
        [item], {"attack-001": "scenarios/attacks/attack-001.yaml"})
    second = reports_to_sarif(
        [item], {"attack-001": "scenarios/attacks/attack-001.yaml"})
    run = first["runs"][0]
    assert first["version"] == "2.1.0"
    assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == {
        "V1", "V2", "V3", "V4", "V5", "V6", "V7",
    }
    assert len(run["results"]) == 2
    assert run["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"]["uri"] == "scenarios/attacks/attack-001.yaml"
    assert run["results"][0]["partialFingerprints"] == second["runs"][0][
        "results"][0]["partialFingerprints"]


def test_sarif_omits_clean_scenarios():
    sarif = reports_to_sarif([
        report("benign-001", verdict="clean"),
    ])
    assert sarif["runs"][0]["results"] == []


def test_benchmark_document_and_json_writer(tmp_path):
    document = benchmark_document(
        [report()],
        {"scenarios": 1},
        command=["delegationbench", "run", "scenarios/"],
        metadata={"model": "open-weight/example"},
        cwd=tmp_path,
    )
    assert document["schema"] == REPORT_SCHEMA
    assert document["metadata"]["model"] == "open-weight/example"
    assert document["git_commit"] is None
    output = write_json(document, tmp_path / "results.json")
    assert json.loads(output.read_text())["metrics"]["scenarios"] == 1
