"""Acceptance tests for the proof / refutation engine (``docs/architecture.md`` §24).

After detection, every taint flow gets a ``Verdict``: ``REFUTED`` when a guard that
dominates the sink validates every tainted origin of the argument (string constraints
such as ``isdigit()``, membership in a constant allowlist, equality with a constant) or
when the sink is unreachable by constant propagation; ``HOTSPOT`` when a dominating guard
tests the value without proving it safe; ``VULNERABILITY`` otherwise. Detectors drop
refuted flows and lower the confidence of hotspots.

Expected to remain red until ``coretrace_python.findings.refutation`` exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.analysis import AnalysisManager
from coretrace_python.findings import Confidence
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import (
    SecurityModelAnalysis,
    SecurityModelRegistry,
    Sink,
    Source,
    TaintAnalysis,
    TaintKind,
)

try:
    from coretrace_python.findings.refutation import (
        RefutationAnalysis,
        Status,
        Verdict,
        Verdicts,
    )
except ImportError as error:  # pragma: no cover - red until refutation lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_refutation() -> None:
    if MISSING is not None:
        pytest.fail(f"refutation engine is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "plugins"

MODELS = (
    Source(SymbolId("python.builtins.input"), "stdin"),
    Source(SymbolId("python.flask.request.args"), "http"),
    Sink(SymbolId("python.os.system"), TaintKind.COMMAND),
    Sink(SymbolId("python.db.execute"), TaintKind.SQL),
)

PRELUDE = "import os\nimport db\nfrom flask import request\n\n"


def verdicts(body: str) -> Verdicts:
    module = build_hir(SourceManager().add_source("proof.py", PRELUDE + body))
    manager = AnalysisManager(module)
    manager.register(*engine.ALL_ANALYSES)
    registry = SecurityModelRegistry()
    registry.register(*MODELS)
    manager.provide(SecurityModelAnalysis, registry.freeze())
    function = next(s for s in module.body if isinstance(s, nodes.Function))
    return manager.get(RefutationAnalysis, function)


def only(result: Verdicts) -> Verdict:
    (verdict,) = result.all()
    return verdict


# --------------------------------------------------------------------------- the §24 example


def test_isdigit_guard_before_the_sink_refutes_the_flow() -> None:
    verdict = only(
        verdicts(
            "def run():\n"
            "    value = request.args['id']\n"
            "    if not value.isdigit():\n"
            "        return\n"
            "    db.execute(value)\n"
        )
    )

    assert isinstance(verdict, Verdict)
    assert verdict.status is Status.REFUTED
    assert "isdigit" in verdict.evidence
    assert verdict.flow.location.start_line == 9


def test_guard_on_the_wrong_branch_does_not_refute() -> None:
    verdict = only(
        verdicts(
            "def run():\n"
            "    value = request.args['id']\n"
            "    if value.isdigit():\n"
            "        return\n"
            "    db.execute(value)\n"
        )
    )
    assert verdict.status is Status.VULNERABILITY


def test_unguarded_flow_is_a_vulnerability() -> None:
    verdict = only(verdicts("def run():\n    os.system(input())\n"))
    assert verdict.status is Status.VULNERABILITY
    assert verdict.evidence == "no guard on the path to the sink"


# --------------------------------------------------------------------------- guard shapes


def test_validator_on_the_positive_branch() -> None:
    verdict = only(
        verdicts(
            "def run():\n    value = input()\n    if value.isalnum():\n        os.system(value)\n"
        )
    )
    assert verdict.status is Status.REFUTED


def test_constant_allowlist_membership_refutes() -> None:
    positive = only(
        verdicts("def run():\n    cmd = input()\n    if cmd in ('ls', 'pwd'):\n        os.system(cmd)\n")
    )
    negative = only(
        verdicts("def run():\n    cmd = input()\n    if cmd not in ('ls', 'pwd'):\n        return\n    os.system(cmd)\n")
    )

    assert positive.status is Status.REFUTED
    assert "allowlist" in positive.evidence
    assert negative.status is Status.REFUTED


def test_equality_with_a_constant_refutes() -> None:
    verdict = only(verdicts("def run():\n    cmd = input()\n    if cmd == 'ls':\n        os.system(cmd)\n"))
    assert verdict.status is Status.REFUTED


def test_non_validating_guards_make_a_hotspot() -> None:
    truthy = only(verdicts("def run():\n    cmd = input()\n    if cmd:\n        os.system(cmd)\n"))
    length = only(
        verdicts("def run():\n    cmd = input()\n    if len(cmd) < 10:\n        os.system(cmd)\n")
    )
    unknown = only(
        verdicts("def run():\n    cmd = input()\n    if cmd in allowed():\n        os.system(cmd)\n")
    )

    assert truthy.status is Status.HOTSPOT
    assert length.status is Status.HOTSPOT
    assert unknown.status is Status.HOTSPOT
    assert "guard" in truthy.evidence


def test_guards_on_unrelated_values_are_ignored() -> None:
    verdict = only(
        verdicts("def run(flag):\n    cmd = input()\n    if flag.isdigit():\n        os.system(cmd)\n")
    )
    assert verdict.status is Status.VULNERABILITY


def test_validated_value_stays_validated_through_string_building() -> None:
    verdict = only(
        verdicts(
            "def run():\n"
            "    name = request.args['name']\n"
            "    if not name.isdigit():\n"
            "        return\n"
            "    db.execute('SELECT * FROM t WHERE id = ' + name)\n"
        )
    )
    assert verdict.status is Status.REFUTED


def test_every_tainted_origin_must_be_validated() -> None:
    verdict = only(
        verdicts(
            "def run():\n"
            "    a = input()\n"
            "    b = input()\n"
            "    if not a.isdigit():\n"
            "        return\n"
            "    os.system(a + b)\n"
        )
    )
    assert verdict.status is Status.VULNERABILITY


def test_boolean_combinations() -> None:
    both = only(
        verdicts("def run(other):\n    cmd = input()\n    if cmd.isdigit() and other:\n        os.system(cmd)\n")
    )
    either = only(
        verdicts("def run(other):\n    cmd = input()\n    if cmd.isdigit() or other:\n        os.system(cmd)\n")
    )
    negated_or = only(
        verdicts(
            "def run(other):\n    cmd = input()\n    if not (cmd.isdigit() or other):\n        return\n    os.system(cmd)\n"
        )
    )

    assert both.status is Status.REFUTED
    assert either.status is Status.HOTSPOT
    assert negated_or.status is Status.HOTSPOT


def test_unreachable_sinks_are_refuted_by_constant_propagation() -> None:
    verdict = only(verdicts("def run():\n    cmd = input()\n    if False:\n        os.system(cmd)\n"))
    assert verdict.status is Status.REFUTED
    assert "unreachable" in verdict.evidence


def test_guard_inside_a_loop_still_dominates_the_sink() -> None:
    verdict = only(
        verdicts(
            "def run(items):\n"
            "    for item in items:\n"
            "        cmd = input()\n"
            "        if cmd.isdigit():\n"
            "            os.system(cmd)\n"
        )
    )
    assert verdict.status is Status.REFUTED


# --------------------------------------------------------------------------- wiring


def test_refutation_is_a_function_analysis_over_taint_and_dominance() -> None:
    from coretrace_python.abstract import ConstantPropagation
    from coretrace_python.cfg import DominanceAnalysis

    assert RefutationAnalysis.name == "findings.refutation"
    assert {TaintAnalysis, DominanceAnalysis, ConstantPropagation} <= RefutationAnalysis.requires
    result = verdicts("def run():\n    os.system(input())\n    os.system('ls')\n")
    assert len(result.all()) == 1
    assert result.verdict(result.all()[0].flow) is result.all()[0]


def test_detectors_drop_refuted_flows_and_downgrade_hotspots() -> None:
    findings = engine.check(
        SourceManager().add_source(
            "app.py",
            "import os\n\n"
            "def proven():\n    os.system(input())\n\n"
            "def checked():\n    cmd = input()\n    if cmd:\n        os.system(cmd)\n\n"
            "def safe():\n    cmd = input()\n    if cmd.isdigit():\n        os.system(cmd)\n",
        ),
        [PLUGINS],
    )

    assert [(f.function, f.confidence) for f in findings] == [
        ("proven", Confidence.HIGH),
        ("checked", Confidence.MEDIUM),
    ]
    assert findings[0].metadata["verdict"] == "vulnerability"
    assert findings[1].metadata["verdict"] == "hotspot"
    assert "guard" in findings[1].metadata["evidence"]
