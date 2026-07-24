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


def test_junit_marks_errored_files_as_errors():
    """A file that failed to load/run becomes an <error> testcase
    (classname from the file name) instead of vanishing from the suite,
    so a CI job archiving the JUnit sees the failure."""
    xml = reports_to_junit(
        [report()],
        errors=[{"file": "scenarios/attacks/broken-thing.yaml",
                 "error": "unsupported schema 2", "type": "ScenarioError"}])
    root = ET.fromstring(xml)
    assert root.attrib["tests"] == "2"
    assert root.attrib["errors"] == "1"
    assert root.attrib["failures"] == "0"
    cases = root.findall(".//testcase")
    error_case = next(c for c in cases if c.find("error") is not None)
    assert error_case.attrib["classname"] == "broken-thing"
    error = error_case.find("error")
    assert error.attrib["type"] == "ScenarioError"
    assert "unsupported schema 2" in error.attrib["message"]


def test_sarif_reports_errored_files_as_results():
    """Errored files surface as scenario-load-error results at level
    error; the rule is only declared when errors exist."""
    sarif = reports_to_sarif(
        [report()],
        errors=[{"file": "scenarios/broken.yaml",
                 "error": "invalid YAML", "type": "ScenarioError"}])
    run = sarif["runs"][0]
    load_errors = [r for r in run["results"]
                   if r["ruleId"] == "scenario-load-error"]
    assert len(load_errors) == 1
    assert load_errors[0]["level"] == "error"
    assert "ScenarioError" in load_errors[0]["message"]["text"]
    assert load_errors[0]["locations"][0]["physicalLocation"][
        "artifactLocation"]["uri"] == "scenarios/broken.yaml"
    assert any(rule["id"] == "scenario-load-error"
               for rule in run["tool"]["driver"]["rules"])
    # No errors -> no extra rule (rule set stays V1..V7).
    clean = reports_to_sarif([report()])
    assert {rule["id"] for rule in
            clean["runs"][0]["tool"]["driver"]["rules"]} == {
        "V1", "V2", "V3", "V4", "V5", "V6", "V7"}


def test_sarif_declares_taxonomies_once():
    """The run declares each taxonomy once and the driver references it."""
    sarif = reports_to_sarif([report()])
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert "taxa" not in driver
    taxa = run["taxonomies"]
    assert [t["name"] for t in taxa] == [
        "OWASP Agentic Top 10", "CWE", "MITRE ATLAS",
    ]
    supported = {
        (t["name"], t["guid"]) for t in driver["supportedTaxonomies"]
    }
    assert supported == {(t["name"], t["guid"]) for t in taxa}
    by_name = {t["name"]: t for t in taxa}
    assert {t["id"] for t in by_name["OWASP Agentic Top 10"]["taxa"]} == {
        "ASI03", "ASI07",
    }
    assert {t["id"] for t in by_name["CWE"]["taxa"]} == {
        "CWE-269", "CWE-290", "CWE-441", "CWE-863",
    }
    assert {t["id"] for t in by_name["MITRE ATLAS"]["taxa"]} == {
        "AML.T0051.001",
    }
    assert by_name["CWE"]["informationUri"] == "https://cwe.mitre.org"


EXPECTED_TAXONOMY = {
    "V1": {"ASI03", "CWE-269", "CWE-863"},
    "V2": {"ASI03", "CWE-441", "AML.T0051.001"},
    "V3": {"ASI07", "CWE-269"},
    "V4": {"ASI07", "CWE-863"},
    "V5": {"ASI07", "CWE-863"},
    "V6": {"ASI07", "CWE-863", "AML.T0051.001"},
    "V7": {"ASI03", "CWE-290"},
}


def test_sarif_rules_map_to_taxonomies():
    """Each violation rule carries the expected taxonomy ids both as
    relationships and as human-readable tags."""
    sarif = reports_to_sarif([report()])
    rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    for kind, taxon_ids in EXPECTED_TAXONOMY.items():
        rule = rules[kind]
        related = {rel["target"]["id"] for rel in rule["relationships"]}
        assert related == taxon_ids
        tags = set(rule["properties"]["tags"])
        assert taxon_ids <= tags
        assert "security" in tags
        assert rule["fullDescription"]["text"]


def test_sarif_relationships_reference_declared_taxa():
    """No rule references a taxon that the driver does not declare, and
    the scenario-load-error rule stays untagged (not a security
    finding)."""
    sarif = reports_to_sarif(
        [report()],
        errors=[{"file": "scenarios/broken.yaml",
                 "error": "invalid YAML", "type": "ScenarioError"}])
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    declared = {
        (taxon["id"], taxonomy["name"])
        for taxonomy in run["taxonomies"]
        for taxon in taxonomy["taxa"]
    }
    rules = {r["id"]: r for r in driver["rules"]}
    for kind in EXPECTED_TAXONOMY:
        for rel in rules[kind]["relationships"]:
            target = (rel["target"]["id"],
                      rel["target"]["toolComponent"]["name"])
            assert target in declared
    load_error = rules["scenario-load-error"]
    assert "relationships" not in load_error
    assert "tags" not in load_error.get("properties", {})


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
