# Contributing to DelegationBench

Thanks for your interest. DelegationBench is an open security testbed — the most
valuable contributions are new attack scenarios, framework adapters, and honest
bug reports.

## Ground rules

- Everything is deterministic: no network calls and no LLM judges in the oracle,
  runner, or defense. Randomness only through a seeded PRNG.
- Dependencies stay minimal (runtime: PyYAML only). Discuss before adding one.
- Python ≥ 3.10, stdlib-first style.

## Development setup

```bash
pip install -e . pytest
python -m pytest tests/ -q
delegationbench run scenarios/
delegationbench run scenarios/ --defense envelope
```

All three must pass before you open a PR. CI runs the same checks.

## Adding a scenario (the best first contribution)

1. Read [THREAT_MODEL.md](THREAT_MODEL.md) — your scenario must test authority
   propagation across a delegation chain, not generic prompt injection.
2. Copy the closest existing scenario under
   `src/delegationbench/scenarios/attacks/` or
   `src/delegationbench/scenarios/benign/` and follow its structure.
3. Every attack needs a complete `expect` block that the oracle actually
   produces — run it, don't guess.
4. Every attack needs a benign lookalike (existing or new) so defenses cannot
   win by blocking everything.
5. Verify: `delegationbench run scenarios/` exits 0.

## Reporting bugs

Open an issue with the bug report template: scenario/seed, expected vs actual
verdict, and the trace (`--format json`).

## Security issues

Do NOT open a public issue. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree your contributions are licensed under Apache-2.0.
