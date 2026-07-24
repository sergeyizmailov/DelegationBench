"""DelegationBench command-line interface.

    delegationbench run <scenario.yaml> [--format terminal|json|junit|sarif]
    delegationbench run <directory>     # run all *.yaml / *.yml recursively
    delegationbench fuzz <seed.yaml>    # fuzz a seed scenario
                                        # (--budget, --seed, --defense,
                                        #  --out, --minimize)
    delegationbench validate-adapter <trace.json>  # lint a recorded
                                        # adapter trace (--scenario,
                                        # --strict, --format)

Exit codes: 0 = actual verdict matches the scenario's baseline expect contract
and, with a defense active, the derived defense outcome; 1 = mismatch; 2 =
usage, scenario, or configuration errors.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .actions import resolve_actions
from .agents import EngineError
from .corpus import resolve_scenario_path
from .defense import EnvelopeGuard, SigningKeyError, signing_key_from_env
from .fuzzer import render_campaign_summary, run_campaign
from .oracle import evaluate
from .outputs import (benchmark_document, reports_to_junit,
                      reports_to_sarif, write_json, write_text)
from .report import (build_report, compute_metrics, render_metrics,
                     render_summary_table, render_terminal)
from .runner import run_scenario
from .scenario import ScenarioError, load_scenario
from .tools import ToolError
from .trace import RunLimitExceeded
from .tracelint import (ERROR as LINT_ERROR, TraceLintError,
                        lint_trace, load_trace_document,
                        render_findings)

EXIT_MATCH = 0
EXIT_MISMATCH = 1
EXIT_ERROR = 2


def _make_defense(name: str, *,
                  signing_key: bytes | None = None) -> EnvelopeGuard | None:
    if name == "none":
        return None
    if name == "envelope-sign":
        if signing_key is None:
            signing_key = signing_key_from_env()
        return EnvelopeGuard(signing_key=signing_key)
    return EnvelopeGuard()


def _grant(scn) -> dict:
    return {
        "allowed_actions": scn.grant.allowed_actions,
        "max_delegation_depth": scn.grant.max_delegation_depth,
        "principal": scn.principal,
    }


def _run_one(path: Path, defense: str,
             signing_key: bytes | None = None) -> dict:
    """Load, run, judge, and build a report for one scenario file."""
    scn = load_scenario(path)
    defense_impl = _make_defense(defense, signing_key=signing_key)
    baseline_expect_match = None
    if defense != "none":
        baseline_result = run_scenario(scn)
        baseline_verdict = evaluate(baseline_result.trace, _grant(scn))
        baseline_report = build_report(baseline_result, baseline_verdict)
        baseline_expect_match = baseline_report["expect_match"]

    result = run_scenario(
        scn,
        defense=defense_impl,
    )
    verdict = evaluate(result.trace, _grant(scn))
    return build_report(
        result,
        verdict,
        defense=defense,
        baseline_expect_match=baseline_expect_match,
    )


def _emit(data, *, output: str | None, text: bool = False) -> None:
    if output:
        path = write_text(data, output) if text else write_json(data, output)
        print(f"Wrote {path}", file=sys.stderr)
    elif text:
        print(data)
    else:
        print(json.dumps(data, indent=2, sort_keys=True))


def _machine_output(args: argparse.Namespace, reports: list[dict],
                    metrics: dict, paths: dict[str, str],
                    errors: list[dict] = ()):
    if args.format == "json":
        data = {"metrics": metrics, "reports": reports}
        if errors:
            # Errored files must not vanish from machine output either.
            data["errors"] = errors
        return data, False
    if args.format == "junit":
        detail = getattr(args, "junit_detail", "full")
        return reports_to_junit(reports, errors=errors, detail=detail), True
    if args.format == "sarif":
        return reports_to_sarif(reports, paths, errors=errors), False
    return None, False


def _write_benchmark_report(args: argparse.Namespace, reports: list[dict],
                            metrics: dict) -> None:
    if not args.benchmark_report:
        return
    if not reports:
        print(f"warning: no scenario reports; benchmark report "
              f"{args.benchmark_report} not written", file=sys.stderr)
        return
    document = benchmark_document(
        reports,
        metrics,
        command=["delegationbench", "run", args.path,
                 "--defense", args.defense],
        metadata={"defense": args.defense, "source": args.path},
    )
    path = write_json(document, args.benchmark_report)
    print(f"Wrote versioned benchmark report {path}", file=sys.stderr)


def _resolve_or_error(arg: str) -> Path | None:
    """Resolve a CLI path, falling back to the bundled corpus."""
    target, from_bundle = resolve_scenario_path(arg)
    if target is not None and from_bundle:
        print(f"note: '{arg}' does not exist in the current directory; "
              f"running the DelegationBench corpus bundled with the "
              f"package ({target}). Pass a path to your own scenarios to "
              f"evaluate those instead.", file=sys.stderr)
    return target


def _cmd_run(args: argparse.Namespace) -> int:
    target = _resolve_or_error(args.path)
    if target is None:
        print(f"error: no such file or directory: {args.path}",
              file=sys.stderr)
        return EXIT_ERROR

    signing_key = None
    if args.defense == "envelope-sign":
        try:
            signing_key = signing_key_from_env()
        except SigningKeyError as e:
            print(f"error: {e}", file=sys.stderr)
            return EXIT_ERROR

    if target.is_dir():
        files = sorted(p for p in target.rglob("*")
                       if p.suffix in (".yaml", ".yml"))
        if not files:
            print(f"error: no scenario files under {target}",
                  file=sys.stderr)
            return EXIT_ERROR
        reports: list[dict] = []
        paths: dict[str, str] = {}
        rows: list[dict] = []
        errors: list[dict] = []
        for f in files:
            try:
                report = _run_one(f, args.defense, signing_key)
            except (ScenarioError, ToolError, RunLimitExceeded,
                    EngineError) as e:
                print(f"error: {e}", file=sys.stderr)
                # Errored files must surface in machine reports (JUnit
                # <error> testcase, SARIF scenario-load-error result,
                # JSON "errors" list) — a CI job archiving the report
                # must see the failure, not an all-green suite.
                errors.append({"file": str(f), "error": str(e),
                               "type": type(e).__name__})
                continue
            reports.append(report)
            paths[report["scenario"]["id"]] = str(f)
            expected = (report["expect"]["verdict"]
                        if report["expect"] else "any")
            ok = bool(report["expect_match"])
            rows.append({"id": report["scenario"]["id"],
                         "expected": expected,
                         "actual": report["verdict"],
                         "outcome": report.get("defense_outcome", "-"),
                         "ok": ok})
        metrics = compute_metrics(reports)
        machine, is_text = _machine_output(args, reports, metrics, paths,
                                           errors)
        if machine is not None:
            _emit(machine, output=args.output, text=is_text)
        else:
            rendered = (
                render_summary_table(
                    rows, show_defense=args.defense != "none")
                + "\n\n" + render_metrics(metrics)
            )
            matched = sum(r["ok"] for r in rows)
            rendered += (
                f"\n\nCorpus contract validation: {matched}/{len(rows)} "
                "scenario contracts matched. This is a deterministic "
                "contract check of declared expectations, not a "
                "real-model detection rate. Unauthorized-action metrics "
                "distinguish attempted from executed violations (see "
                "above).")
            _emit(rendered, output=args.output, text=True)
        _write_benchmark_report(args, reports, metrics)
        if errors:
            return EXIT_ERROR
        return EXIT_MATCH if all(r["ok"] for r in rows) else EXIT_MISMATCH

    try:
        report = _run_one(target, args.defense, signing_key)
    except (ScenarioError, ToolError, RunLimitExceeded,
            EngineError) as e:
        print(f"error: {e}", file=sys.stderr)
        errors = [{"file": str(target), "error": str(e),
                   "type": type(e).__name__}]
        machine, is_text = _machine_output(args, [], {}, {}, errors)
        if machine is not None:
            _emit(machine, output=args.output, text=is_text)
        _write_benchmark_report(args, [], {})
        return EXIT_ERROR
    reports = [report]
    metrics = compute_metrics(reports)
    machine, is_text = _machine_output(
        args, reports, metrics, {report["scenario"]["id"]: str(target)})
    if machine is not None:
        # Preserve the historical single-file JSON shape.
        if args.format == "json":
            machine = report
        _emit(machine, output=args.output, text=is_text)
    else:
        _emit(render_terminal(report, scenario_path=str(target)),
              output=args.output, text=True)
    _write_benchmark_report(args, reports, metrics)
    if report["expect_match"] is False:
        return EXIT_MISMATCH
    return EXIT_MATCH


def _cmd_fuzz(args: argparse.Namespace) -> int:
    seed = _resolve_or_error(args.path)
    if seed is None or not seed.is_file():
        print(f"error: no such file: {args.path}", file=sys.stderr)
        return EXIT_ERROR
    try:
        report = run_campaign(seed, budget=args.budget, seed=args.seed,
                              defense=args.defense, out=args.out,
                              minimize=args.minimize)
    except ScenarioError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    print(render_campaign_summary(report))
    print(f"Campaign report: {Path(args.out) / 'campaign.json'}")
    if args.fail_on_bypass and report["counts"]["bypass"]:
        # CI gating: any defense-bypass finding fails the job.
        return EXIT_MISMATCH
    return EXIT_MATCH


def _cmd_validate_adapter(args: argparse.Namespace) -> int:
    """Lint a recorded adapter trace; fail on ambiguous traces.

    Exit 2: unreadable input or scenario errors. Exit 1: any
    error-severity finding, or any finding at all under --strict.
    """
    try:
        doc = load_trace_document(args.trace)
    except TraceLintError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR

    actions: frozenset[str] = frozenset()
    root_principal = ""
    if args.scenario:
        scenario_path = _resolve_or_error(args.scenario)
        if scenario_path is None:
            print(f"error: no such file: {args.scenario}",
                  file=sys.stderr)
            return EXIT_ERROR
        try:
            scn = load_scenario(scenario_path)
        except ScenarioError as e:
            print(f"error: {e}", file=sys.stderr)
            return EXIT_ERROR
        actions = resolve_actions(scn.actions) | scn.grant.allowed_actions
        root_principal = scn.principal

    findings = lint_trace(doc, actions=actions,
                          root_principal=root_principal)
    errors = sum(f.severity == LINT_ERROR for f in findings)
    if args.format == "json":
        payload = {
            "trace": str(args.trace),
            "strict": bool(args.strict),
            "errors": errors,
            "warnings": len(findings) - errors,
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_findings(findings, str(args.trace)))
    if errors or (args.strict and findings):
        return EXIT_MISMATCH
    return EXIT_MATCH


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="delegationbench",
        description="Detect privilege escalation across AI-agent "
                    "delegation chains.")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run a scenario file or a directory "
                                     "of scenarios")
    run.add_argument("path", help="scenario .yaml file or directory")
    run.add_argument("--format", choices=("terminal", "json", "junit",
                                         "sarif"),
                     default="terminal")
    run.add_argument("--output",
                     help="write primary output to this file instead of stdout")
    run.add_argument(
        "--benchmark-report",
        help="also write a self-describing versioned JSON benchmark report",
    )
    run.add_argument(
        "--junit-detail", choices=("summary", "failures", "full"),
        default="full",
        help="how much detail JUnit system-out carries: 'full' embeds the "
             "complete JSON report per testcase (default, historical "
             "behavior), 'failures' embeds it only for mismatched "
             "scenarios, 'summary' omits system-out entirely. Full "
             "per-scenario traces stay available via --format json")
    run.add_argument("--defense", choices=("none", "envelope",
                                           "envelope-sign"),
                     default="none",
                     help="reference defense enforced at the tool "
                          "boundary: 'envelope' checks delegation "
                          "envelopes; 'envelope-sign' also requires HMAC "
                          "signatures (DELEGATIONBENCH_KEY is required)")
    run.set_defaults(func=_cmd_run)

    fuzz = sub.add_parser("fuzz", help="mutate a seed scenario and hunt for "
                                       "defense bypasses and oracle "
                                       "divergences")
    fuzz.add_argument("path", help="seed scenario .yaml file")
    fuzz.add_argument("--budget", type=int, default=200,
                      help="number of mutants to generate (default: 200)")
    fuzz.add_argument("--seed", type=int, default=1,
                      help="random seed; same seed + budget = identical "
                           "findings (default: 1)")
    fuzz.add_argument("--defense", choices=("none", "envelope"),
                      default="envelope",
                      help="defense active during the campaign: 'envelope' "
                           "hunts defense bypasses, 'none' hunts oracle "
                           "divergences (default: envelope)")
    fuzz.add_argument("--out", default="fuzz-output",
                      help="output directory (default: fuzz-output/)")
    fuzz.add_argument("--minimize", action=argparse.BooleanOptionalAction,
                      default=True,
                      help="minimize findings and emit regression scenarios "
                           "(default: on; disable with --no-minimize)")
    fuzz.add_argument("--fail-on-bypass", action="store_true",
                      help="exit 1 when the campaign finds any defense "
                           "bypass (for CI gating; default: exit 0 "
                           "regardless of findings)")
    fuzz.set_defaults(func=_cmd_fuzz)

    lint = sub.add_parser(
        "validate-adapter",
        help="lint a recorded adapter trace for misconfiguration "
             "(missing mappings, broken delegation links, dropped "
             "principals) before the oracle judges it")
    lint.add_argument("trace",
                      help="trace JSON file (the shape produced by "
                           "Trace.to_json() / adapter build_trace())")
    lint.add_argument("--scenario",
                      help="optional scenario .yaml: checks tool actions "
                           "against its action vocabulary and principal "
                           "against its grant")
    lint.add_argument("--strict", action="store_true",
                      help="fail on warnings too, not only errors "
                           "(ambiguous or incomplete traces fail)")
    lint.add_argument("--format", choices=("terminal", "json"),
                      default="terminal")
    lint.set_defaults(func=_cmd_validate_adapter)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        # stdout's reader went away (e.g. `--format json | head`):
        # exit quietly with code 1, no traceback. Redirecting stdout to
        # devnull prevents the interpreter's shutdown flush from
        # re-raising and printing "Exception ignored ...".
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except (AttributeError, OSError, ValueError):
            pass
        return EXIT_MISMATCH


if __name__ == "__main__":
    sys.exit(main())
