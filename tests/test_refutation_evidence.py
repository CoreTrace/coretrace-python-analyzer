"""Acceptance tests for the remaining evidence of the proof engine (``docs/architecture.md``
§24, §25 plugins/proof; roadmap issue #32).

- Numeric ranges: ``abstract.ranges`` keeps an interval for every value proven numeric
  (numeric constants, arithmetic on numbers, ``int()``, ``len()`` and friends), refined
  on the branches of comparisons and widened over loops. A tainted origin whose every
  dependence path to the sink argument goes through a numeric value cannot inject.
- Validators: a ``Validator`` model names a callable whose truth proves one of its
  arguments safe, so ``re.fullmatch`` and framework validators refute like ``isdigit()``.
- Authorization: an ``AuthorizationGuard`` model names a decorator or a condition that
  restricts who reaches the sink; a flow behind one is a hotspot, not a vulnerability.

Plugins contribute both models through ``Plugin.models``, the same way they contribute
sources and sinks: that is the plugin extension point for refutation evidence.

Expected to remain red until ``abstract.ranges``, ``Validator`` and ``AuthorizationGuard``
exist and the refutation engine consumes them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.analysis import AnalysisManager
from coretrace_python.findings import Confidence
from coretrace_python.findings.refutation import RefutationAnalysis, Status, Verdict, Verdicts
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.ir.model import Call, Symbol
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import (
    SecurityModelAnalysis,
    SecurityModelRegistry,
    Sink,
    Source,
    TaintKind,
)

try:
    from coretrace_python.abstract import Interval, RangeAnalysis
    from coretrace_python.taint import AuthorizationGuard, Validator
except ImportError as error:  # pragma: no cover - red until the evidence lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_evidence() -> None:
    if MISSING is not None:
        pytest.fail(f"refutation evidence is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "plugins"

OS_SYSTEM = Sink(SymbolId("python.os.system"), TaintKind.COMMAND)
STDIN = Source(SymbolId("python.builtins.input"), "stdin")
LOGIN = SymbolId("python.flask_login.current_user.is_authenticated")
LOGIN_REQUIRED = SymbolId("python.flask_login.login_required")

PRELUDE = "import os\nimport re\nfrom flask_login import current_user, login_required\n\n"


def manager_for(body: str, *models: object) -> AnalysisManager:
    module = build_hir(SourceManager().add_source("proof.py", PRELUDE + body))
    manager = AnalysisManager(module)
    manager.register(*engine.ALL_ANALYSES)
    registry = SecurityModelRegistry()
    registry.register(STDIN, OS_SYSTEM, *models)  # type: ignore[arg-type]
    manager.provide(SecurityModelAnalysis, registry.freeze())
    return manager


def first_function(manager: AnalysisManager) -> nodes.Function:
    return next(s for s in manager.module.body if isinstance(s, nodes.Function))


def verdict(body: str, *models: object) -> Verdict:
    manager = manager_for(body, *models)
    result: Verdicts = manager.get(RefutationAnalysis, first_function(manager))
    (found,) = result.all()
    return found


def ranges_at_sink(body: str):  # type: ignore[no-untyped-def]
    """The intervals in the block calling ``os.system``, keyed by argument position."""

    manager = manager_for(body)
    function = first_function(manager)
    ssa = manager.get(SSAAnalysis, function)
    facts = manager.get(RangeAnalysis, function)
    defs = {i.result: i for block in ssa.blocks for i in block.instructions if i.result}
    for block in ssa.blocks:
        for instruction in block.instructions:
            callee = defs.get(instruction.callee) if isinstance(instruction, Call) else None
            if isinstance(callee, Symbol) and callee.symbol_id == OS_SYSTEM.symbol:
                at = facts.at(block.id)
                return [at.get(argument) for argument in instruction.arguments]
    raise AssertionError("no call to os.system")


# --------------------------------------------------------------------------- ranges


def test_intervals_join_and_widen() -> None:
    assert Interval(0, 5).join(Interval(3, 9)) == Interval(0, 9)
    assert Interval(0, 5).widen(Interval(0, 6)) == Interval(0, float("inf"))
    assert Interval(0, 5).widen(Interval(-1, 5)) == Interval(float("-inf"), 5)
    assert Interval(0, 5).widen(Interval(1, 4)) == Interval(0, 5)
    assert str(Interval(0, float("inf"))) == "[0, inf]"


def test_numeric_constants_and_arithmetic_have_ranges() -> None:
    assert ranges_at_sink("def f():\n    n = 2 + 3 * 4\n    os.system(n, n - 20, -n)\n") == [
        Interval(14, 14),
        Interval(-6, -6),
        Interval(-14, -14),
    ]


def test_conversions_and_lengths_are_numeric() -> None:
    low, length, raw = ranges_at_sink(
        "def f(x):\n    os.system(int(x), len(x), x)\n"
    )
    assert low == Interval(float("-inf"), float("inf"))
    assert length == Interval(0, float("inf"))
    assert raw is None


def test_branches_refine_ranges_on_each_side() -> None:
    then_side = ranges_at_sink("def f(x):\n    n = int(x)\n    if n < 10:\n        os.system(n)\n")
    else_side = ranges_at_sink("def f(x):\n    n = int(x)\n    if n < 10:\n        pass\n    else:\n        os.system(n)\n")
    chained = ranges_at_sink("def f(x):\n    n = int(x)\n    if 0 < n <= 100:\n        os.system(n)\n")

    assert then_side == [Interval(float("-inf"), 10)]
    assert else_side == [Interval(10, float("inf"))]
    assert chained == [Interval(0, 100)]


def test_loops_terminate_by_widening() -> None:
    (counter,) = ranges_at_sink(
        "def f(x):\n    i = 0\n    while i < len(x):\n        i = i + 1\n    os.system(i)\n"
    )
    assert counter == Interval(0, float("inf"))


def test_range_analysis_is_a_function_analysis_over_ssa() -> None:
    from coretrace_python.cfg import CFGAnalysis

    assert RangeAnalysis.name == "abstract.ranges"
    assert {SSAAnalysis, CFGAnalysis} <= RangeAnalysis.requires
    assert RangeAnalysis in engine.ALL_ANALYSES


# --------------------------------------------------------------------------- numeric evidence


def test_numeric_values_cannot_inject() -> None:
    found = verdict("def f():\n    n = int(input())\n    os.system('sleep ' + str(n))\n")

    assert found.status is Status.REFUTED
    assert "numeric" in found.evidence


def test_ranges_show_in_the_evidence() -> None:
    found = verdict(
        "def f():\n    n = int(input())\n    if 0 <= n < 60:\n        os.system('sleep ' + str(n))\n"
    )
    assert found.status is Status.REFUTED
    assert "[0, 60]" in found.evidence


def test_a_numeric_path_does_not_cover_a_raw_one() -> None:
    found = verdict("def f():\n    x = input()\n    os.system(x + str(int(x)))\n")
    assert found.status is Status.VULNERABILITY


def test_a_bounded_length_proves_nothing_about_the_string() -> None:
    found = verdict("def f():\n    x = input()\n    if len(x) < 5:\n        os.system(x)\n")
    assert found.status is Status.HOTSPOT


# --------------------------------------------------------------------------- validators


FULLMATCH = Validator(SymbolId("python.re.fullmatch"), argument=1) if MISSING is None else None


def test_validators_and_authorization_guards_are_indexed_in_the_model_table() -> None:
    guard = AuthorizationGuard(LOGIN, "login")
    registry = SecurityModelRegistry()
    registry.register(FULLMATCH, guard, Sink(LOGIN, TaintKind.HTML))
    table = registry.freeze()

    assert table.validator(FULLMATCH.symbol) == FULLMATCH
    assert table.validator(LOGIN) is None
    assert table.authorization(LOGIN) == guard
    assert table.authorization(FULLMATCH.symbol) is None
    assert table.validators == (FULLMATCH,)
    assert table.authorizations == (guard,)
    assert Validator(LOGIN).argument == 0
    extended = table.extended(Sink(SymbolId("python.x"), TaintKind.ADVISORY))
    assert extended.validators == (FULLMATCH,) and extended.authorizations == (guard,)


def test_a_true_validator_refutes_the_argument_it_validates() -> None:
    found = verdict(
        "def f():\n    x = input()\n    if re.fullmatch('[a-z]+', x):\n        os.system(x)\n",
        FULLMATCH,
    )
    assert found.status is Status.REFUTED
    assert found.evidence == "validated by python.re.fullmatch"


def test_a_validator_only_proves_its_declared_argument() -> None:
    found = verdict(
        "def f():\n    x = input()\n    if re.fullmatch(x, 'abc'):\n        os.system(x)\n",
        FULLMATCH,
    )
    assert found.status is Status.HOTSPOT


def test_validators_on_the_wrong_branch_prove_nothing() -> None:
    found = verdict(
        "def f():\n    x = input()\n    if not re.fullmatch('[a-z]+', x):\n        os.system(x)\n",
        FULLMATCH,
    )
    assert found.status is Status.VULNERABILITY


def test_compiled_pattern_validators_resolve_through_derived_symbols() -> None:
    found = verdict(
        "def f():\n    x = input()\n    pattern = re.compile('[a-z]+')\n"
        "    if pattern.fullmatch(x):\n        os.system(x)\n",
        Validator(SymbolId("python.re.compile.fullmatch")),
    )
    assert found.status is Status.REFUTED


# --------------------------------------------------------------------------- authorization


def test_a_dominating_authorization_condition_makes_a_hotspot() -> None:
    found = verdict(
        "def f():\n    if current_user.is_authenticated:\n        os.system(input())\n",
        AuthorizationGuard(LOGIN, "login"),
    )
    assert found.status is Status.HOTSPOT
    assert found.evidence == "behind authorization (login) at line 6"


def test_an_early_return_on_missing_authorization_counts() -> None:
    found = verdict(
        "def f():\n    if not current_user.is_authenticated:\n        return\n    os.system(input())\n",
        AuthorizationGuard(LOGIN, "login"),
    )
    assert found.status is Status.HOTSPOT


def test_an_authorization_decorator_counts() -> None:
    found = verdict(
        "@login_required\ndef f():\n    os.system(input())\n",
        AuthorizationGuard(LOGIN_REQUIRED, "login"),
    )
    assert found.status is Status.HOTSPOT
    assert found.evidence == "behind authorization (login) by decorator"


def test_without_the_model_the_same_code_is_a_vulnerability() -> None:
    found = verdict("def f():\n    if current_user.is_authenticated:\n        os.system(input())\n")
    assert found.status is Status.VULNERABILITY


def test_authorization_does_not_override_a_refutation() -> None:
    found = verdict(
        "@login_required\ndef f():\n    x = input()\n    if x.isdigit():\n        os.system(x)\n",
        AuthorizationGuard(LOGIN_REQUIRED, "login"),
    )
    assert found.status is Status.REFUTED


# --------------------------------------------------------------------------- plugins


def test_any_plugin_contributes_refutation_models() -> None:
    class Evidence(ModelPlugin):
        name = "evidence"
        models = (FULLMATCH, AuthorizationGuard(LOGIN, "login"))

    table = engine.plugin_models([Evidence()])

    assert table.validators == (FULLMATCH,)
    assert table.authorizations == (AuthorizationGuard(LOGIN, "login"),)


def test_shipped_models_refute_fullmatch_and_flag_login_required_routes() -> None:
    findings = engine.check(
        SourceManager().add_source(
            "app.py",
            "import os\nimport re\nfrom flask import Flask, request\nfrom flask_login import login_required\n\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/ping')\n"
            "def ping():\n"
            "    host = request.args['host']\n"
            "    if re.fullmatch(r'[a-z.]+', host):\n"
            "        os.system('ping ' + host)\n\n"
            "@app.route('/admin')\n"
            "@login_required\n"
            "def admin():\n"
            "    os.system(request.args['cmd'])\n",
        ),
        [PLUGINS],
    )

    assert [(f.function, f.confidence) for f in findings] == [("admin", Confidence.MEDIUM)]
    assert findings[0].metadata["evidence"] == "behind authorization (login) by decorator"


def test_shipped_django_login_required_view_is_a_hotspot() -> None:
    findings = engine.check(
        SourceManager().add_source(
            "views.py",
            "import os\nfrom django.contrib.auth.decorators import login_required\n\n"
            "@login_required\n"
            "def run(request):\n"
            "    os.system(request.GET['cmd'])\n",
        ),
        [PLUGINS],
    )
    assert [(f.rule_id, f.confidence) for f in findings] == [("command-injection", Confidence.MEDIUM)]
