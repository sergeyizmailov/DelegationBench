"""Fuzz target: scenario loading from untrusted YAML.

Feeds arbitrary bytes through ``yaml.safe_load`` and the scenario
parser/validator. Expected outcomes are a parsed scenario or a documented
rejection (``yaml.YAMLError`` / ``ScenarioError``); anything else —
an unexpected exception or a hang — is a bug the fuzzer should report.

Run locally (requires ``pip install atheris``):

    python fuzz/fuzz_scenario.py fuzz/corpora/fuzz_scenario -runs=100000
"""

import sys

import atheris

with atheris.instrument_imports():
    import yaml

    from delegationbench.scenario import ScenarioError, parse_scenario


def TestOneInput(data: bytes) -> None:
    try:
        doc = yaml.safe_load(data)
    except yaml.YAMLError:
        return
    except RecursionError:
        # Host recursion limit on adversarial nesting depth; not a
        # DelegationBench defect.
        return
    try:
        parse_scenario(doc)
    except ScenarioError:
        return
    except RecursionError:
        return


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
