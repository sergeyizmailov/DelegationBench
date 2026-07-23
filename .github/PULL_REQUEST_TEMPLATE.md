## What and why

<!-- Link the issue. One paragraph: what changes and why. -->

## Checklist

- [ ] `python -m pytest tests/ -q` passes
- [ ] `delegationbench run scenarios/` passes (all expect contracts)
- [ ] `delegationbench run scenarios/ --defense envelope` passes (attacks contained, benign clean)
- [ ] New behavior is covered by tests
- [ ] Determinism preserved (no network / no LLM in oracle, runner, or defense)
- [ ] For scenarios: attack has a benign lookalike; `expect` block verified against actual oracle output
- [ ] Docs updated (README / THREAT_MODEL.md / module docstrings) if behavior changed
