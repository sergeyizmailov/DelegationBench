"""Release gates for corpus size, pairing, and invariant coverage."""

import copy
from pathlib import Path

import yaml

from delegationbench.scenario import load_scenario

ROOT = Path(__file__).resolve().parents[1]
ATTACKS = ROOT / "scenarios" / "attacks"
BENIGN = ROOT / "scenarios" / "benign"

NEW_PAIRS = tuple(
    (f"attack-{attack:03d}", f"benign-{attack - 1:03d}")
    for attack in range(17, 39)
)


def _by_id(directory: Path) -> dict[str, object]:
    scenarios = [load_scenario(path) for path in directory.glob("*.yaml")]
    return {scenario.id: scenario for scenario in scenarios}


def _raw_by_id(directory: Path) -> dict[str, dict]:
    documents = [
        yaml.safe_load(path.read_text(encoding="utf-8"))
        for path in directory.glob("*.yaml")
    ]
    return {document["id"]: document for document in documents}


def _without_pair_metadata(document: dict) -> dict:
    normalized = copy.deepcopy(document)
    for key in ("id", "name", "type", "description", "expect"):
        normalized.pop(key)
    return normalized


def test_release_corpus_has_at_least_75_scenarios():
    paths = list((ROOT / "scenarios").rglob("*.yaml"))
    assert len(paths) >= 75


def test_new_attack_cases_have_clean_benign_twins():
    attacks = _by_id(ATTACKS)
    benign = _by_id(BENIGN)
    for attack_id, benign_id in NEW_PAIRS:
        attack = attacks[attack_id]
        twin = benign[benign_id]
        assert attack.expect.verdict == "violation"
        assert attack.expect.violation_kinds
        assert twin.expect.verdict == "clean"
        assert twin.expect.outcomes


def test_new_pairs_cover_every_violation_class():
    attacks = _by_id(ATTACKS)
    kinds = {
        kind
        for attack_id, _ in NEW_PAIRS
        for kind in attacks[attack_id].expect.violation_kinds
    }
    assert kinds == {f"V{number}" for number in range(1, 8)}


def test_new_twins_differ_only_at_the_intended_security_boundary():
    attacks = _raw_by_id(ATTACKS)
    benign = _raw_by_id(BENIGN)
    for attack_id, benign_id in NEW_PAIRS:
        attack_number = int(attack_id.removeprefix("attack-"))
        unsafe = _without_pair_metadata(attacks[attack_id])
        safe = _without_pair_metadata(benign[benign_id])

        if attack_number in {*range(17, 21), *range(31, 34)}:
            unsafe["grant"]["allowed_actions"] = safe["grant"]["allowed_actions"]
        elif attack_number in range(21, 24):
            unsafe["grant"]["max_delegation_depth"] = (
                safe["grant"]["max_delegation_depth"])
        elif attack_number in range(24, 26):
            unsafe["agents"]["coordinator"]["rules"][0]["replay"] = False
        elif attack_number in range(26, 28):
            unsafe["agents"]["coordinator"]["rules"][0]["advance_clock"] = 30
        elif attack_number in range(28, 31):
            unsafe["agents"]["operator"]["rules"][0]["then"]["tool"][
                "untracked"] = False
        else:
            unsafe["agents"]["coordinator"]["rules"][0]["then"]["delegate"].pop(
                "as_principal")

        assert unsafe == safe, (attack_id, benign_id)
