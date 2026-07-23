"""DelegationBench command-line interface.

    delegationbench run <scenario.yaml> [--format terminal|json] [--defense none|envelope|envelope-sign]
    delegationbench run <directory>     # run all *.yaml / *.yml recursively
    delegationbench fuzz <seed.yaml>    # fuzz a seed scenario (--budget, --seed, --defense, --out, --minimize)

Exit codes: 0 = actual verdict matches the scenario's expect contract
(with a defense active: the derived defense outcome), 1 = mismatch,
2 = usage or scenario errors.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .defense import EnvelopeGuard, signing_key_from_env
from .fuzzer import render_campaign_summary, run_campaign
from .oracle import evaluate
from .report import (build_report, compute_metrics, render_metrics,
                     render_summary_table, render_terminal)
from .runner import run_scenario
from .scenario import ScenarioError, load_scenario
from .tools import ToolError
from .trace import RunLimitExceeded

EXIT_MATCH = 0
EXIT_MISMATCH = 1
EXIT_ERROR = 2


def _make_defense(name: str) -> EnvelopeGuard | None:
    if name == "none":
        return None
    if name == "envelope-sign":
        return EnvelopeGuard(signing_key=signing_key_from_env())
    return EnvelopeGuard()


def _run_one(path: Path, defense: str) -> dict:
    """Load, run, judge, and build a report for one scenario file."""
    scn = load_scenario(path)
    result = run_scenario(scn, defense=_make_defense(defense))
    verdict = evaluate(result.trace, {
        "allowed_actions": scn.grant.allowed_actions,
        "max_delegation_depth": scn.grant.max_delegation_depth,
        "principal": scn.principal,
    })
    return build_report(result, verdict, defense=defense)


def _cmd_run(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"error: no such file or directory: {target}", file=sys.stderr)
        return EXIT_ERROR

    if target.is_dir():
        files = sorted(p for p in target.rglob("*")
                       if p.suffix in (".yaml", ".yml"))
        if not files:
            print(f"error: no scenario files under {target}",
                  file=sys.stderr)
            return EXIT_ERROR
        reports: list[dict] = []
        rows: list[dict] = []
        had_error = False
        for f in files:
            try:
                report = _run_one(f, args.defense)
            except (ScenarioError, ToolError, RunLimitExceeded) as e:
                print(f"error: {e}", file=sys.stderr)
                had_error = True
                continue
            reports.append(report)
            expected = (report["expect"]["verdict"]
                        if report["expect"] else "any")
            ok = bool(report["expect_match"])
            rows.append({"id": report["scenario"]["id"],
                         "expected": expected,
                         "actual": report["verdict"],
                         "outcome": report.get("defense_outcome", "-"),
                         "ok": ok})
        metrics = compute_metrics(reports)
        if args.format == "json":
            print(json.dumps({"metrics": metrics, "reports": reports},
                             indent=2, sort_keys=True))
        else:
            print(render_summary_table(rows,
                                       show_defense=args.defense != "none"))
            print()
            print(render_metrics(metrics))
        if had_error:
            return EXIT_ERROR
        return EXIT_MATCH if all(r["ok"] for r in rows) else EXIT_MISMATCH

    try:
        report = _run_one(target, args.defense)
    except (ScenarioError, ToolError, RunLimitExceeded) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_terminal(report, scenario_path=str(target)))
    if report["expect_match"] is False:
        return EXIT_MISMATCH
    return EXIT_MATCH


def _cmd_fuzz(args: argparse.Namespace) -> int:
    seed = Path(args.path)
    if not seed.is_file():
        print(f"error: no such file: {seed}", file=sys.stderr)
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
    run.add_argument("--format", choices=("terminal", "json"),
                     default="terminal")
    run.add_argument("--defense", choices=("none", "envelope",
                                           "envelope-sign"),
                     default="none",
                     help="reference defense enforced at the tool "
                          "boundary: 'envelope' checks delegation "
                          "envelopes; 'envelope-sign' also requires HMAC "
                          "signatures (key from DELEGATIONBENCH_KEY, "
                          "insecure default if unset)")
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
    fuzz.set_defaults(func=_cmd_fuzz)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
