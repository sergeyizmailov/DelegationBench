"""Production report formats for CI and benchmark publication.

The core report remains a plain JSON-compatible dictionary.  This module
turns a collection of those reports into JUnit XML, GitHub-compatible
SARIF 2.1.0, or a versioned benchmark bundle without changing oracle
semantics.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import __version__
from .oracle import ALL_KINDS

REPORT_SCHEMA = "delegationbench.report/v1"

_RULE_DESCRIPTIONS = {
    "V1": "Authority expansion across a delegation edge",
    "V2": "Confused-deputy tool execution outside effective authority",
    "V3": "Delegation depth violation",
    "V4": "Expired or replayed delegation authority",
    "V5": "Origin, identity, or task-attribution loss",
    "V6": "Authority widening through child-result content",
    "V7": "Principal substitution across a delegation chain",
}


def _report_ok(report: dict) -> bool:
    return report.get("expect_match") is not False


def reports_to_junit(reports: Iterable[dict],
                     suite_name: str = "DelegationBench",
                     errors: Iterable[dict] = ()) -> str:
    """Return JUnit XML for a set of scenario reports.

    ``errors`` carries per-file load/run failures (dicts with ``file``,
    ``error`` and ``type`` keys): each becomes an ``<error>`` testcase
    whose classname derives from the file name, so a CI job archiving
    the JUnit sees the failure instead of an all-green suite that
    silently dropped the broken file.
    """
    reports = list(reports)
    errors = list(errors)
    failures = sum(not _report_ok(report) for report in reports)
    suite = ET.Element(
        "testsuite",
        name=suite_name,
        tests=str(len(reports) + len(errors)),
        failures=str(failures),
        errors=str(len(errors)),
        skipped="0",
    )
    for report in reports:
        scenario = report["scenario"]
        case = ET.SubElement(
            suite,
            "testcase",
            classname=f"delegationbench.{scenario['type']}",
            name=scenario["id"],
        )
        if not _report_ok(report):
            failure = ET.SubElement(
                case,
                "failure",
                type="DelegationBenchMismatch",
                message=(
                    f"expected contract did not match: "
                    f"{report.get('verdict')}"
                ),
            )
            failure.text = "\n".join(report.get("reasons") or [])
        output = ET.SubElement(case, "system-out")
        output.text = json.dumps(report, sort_keys=True)
    for err in errors:
        stem = Path(str(err.get("file", "unknown"))).stem
        case = ET.SubElement(suite, "testcase", classname=stem,
                             name=f"{stem} (load/run error)")
        error = ET.SubElement(
            case, "error",
            type=str(err.get("type", "ScenarioError")),
            message=str(err.get("error", "")))
        error.text = str(err.get("error", ""))
    ET.indent(suite)
    return ET.tostring(suite, encoding="unicode", xml_declaration=True)


def _fingerprint(report: dict, kind: str) -> str:
    scenario = report["scenario"]
    value = "\0".join([
        scenario["id"],
        kind,
        ",".join(report.get("unauthorized_actions") or []),
    ])
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def reports_to_sarif(reports: Iterable[dict],
                     paths: dict[str, str] | None = None,
                     errors: Iterable[dict] = ()) -> dict:
    """Return GitHub-compatible SARIF 2.1.0.

    One result is emitted per violation kind. Clean expected scenarios do
    not become alerts. Stable fingerprints prevent duplicate alerts across
    repeated CI runs. Per-file load/run failures (``errors``, same shape
    as in :func:`reports_to_junit`) become ``scenario-load-error``
    results at level ``error``, so a broken scenario file surfaces in
    code scanning instead of vanishing from the report.
    """
    paths = paths or {}
    errors = list(errors)
    results: list[dict[str, Any]] = []
    for report in reports:
        if report.get("verdict") != "violation":
            continue
        scenario = report["scenario"]
        uri = paths.get(scenario["id"], f"scenarios/{scenario['id']}.yaml")
        for kind in report.get("kinds") or []:
            matching = [
                reason for reason in report.get("reasons") or []
                if reason.startswith(kind)
            ]
            message = matching[0] if matching else _RULE_DESCRIPTIONS[kind]
            results.append({
                "ruleId": kind,
                "level": "error",
                "message": {"text": message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [{
                        "fullyQualifiedName": scenario["id"],
                        "kind": "scenario",
                    }],
                }],
                "partialFingerprints": {
                    "delegationbench/v1": _fingerprint(report, kind),
                },
                "properties": {
                    "scenarioType": scenario["type"],
                    "unauthorizedActions": (
                        report.get("unauthorized_actions") or []
                    ),
                    "delegationPath": report.get("delegation_path") or [],
                },
            })
    for err in errors:
        uri = str(err.get("file", "unknown"))
        message = (f"{err.get('type', 'Error')}: "
                   f"{err.get('error', '')}")
        results.append({
            "ruleId": "scenario-load-error",
            "level": "error",
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1},
                },
            }],
            "partialFingerprints": {
                "delegationbench/v1": hashlib.sha256(
                    f"{uri}\0{message}".encode("utf-8")).hexdigest(),
            },
        })
    rules = [{
        "id": kind,
        "name": f"DelegationBench-{kind}",
        "shortDescription": {"text": _RULE_DESCRIPTIONS[kind]},
        "helpUri": (
            "https://github.com/sergeyizmailov/DelegationBench/"
            "blob/main/THREAT_MODEL.md"
        ),
        "defaultConfiguration": {"level": "error"},
    } for kind in ALL_KINDS]
    if errors:
        rules.append({
            "id": "scenario-load-error",
            "name": "DelegationBench-scenario-load-error",
            "shortDescription": {
                "text": "Scenario file failed to load or run",
            },
            "helpUri": (
                "https://github.com/sergeyizmailov/DelegationBench"
            ),
            "defaultConfiguration": {"level": "error"},
        })
    return {
        "$schema": (
            "https://json.schemastore.org/sarif-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "DelegationBench",
                    "semanticVersion": __version__,
                    "informationUri": (
                        "https://github.com/sergeyizmailov/DelegationBench"
                    ),
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }


def _git_commit(cwd: Path) -> str | None:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def benchmark_document(reports: list[dict], metrics: dict, *,
                       command: list[str],
                       metadata: dict | None = None,
                       cwd: Path | None = None) -> dict:
    """Build a self-describing, versioned benchmark result document."""
    cwd = cwd or Path.cwd()
    return {
        "schema": REPORT_SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "delegationbench_version": __version__,
        "git_commit": _git_commit(cwd),
        "command": command,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "metadata": dict(metadata or {}),
        "metrics": metrics,
        "reports": reports,
    }


def write_json(data: Any, path: str | Path) -> Path:
    """Write canonical pretty JSON and return the resolved output path."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return target


def write_text(data: str, path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(data.rstrip() + "\n", encoding="utf-8")
    return target
