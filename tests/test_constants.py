"""Acceptance tests for abstract values and constant propagation (§18, §38 Phase 4).

``AbstractValue`` records what is known about one SSA value: its constant (a flat
lattice), its possible types and its truthiness. ``ConstantPropagation`` is the first
client of the data-flow solver: a forward problem over the SSA form that folds pure
operations on constants, joins at phis over executable edges only, and prunes the
branches a constant condition never takes.

Expected to remain red until ``coretrace_python.abstract`` exists.
"""

from __future__ import annotations

import pytest

from coretrace_python.analysis import AnalysisManager
from coretrace_python.cfg import BlockId, CFGAnalysis, DominanceAnalysis
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.ir.lowering import PyIRAnalysis
from coretrace_python.ir.model import FunctionIR, Phi, Return
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.semantic import SEMANTIC_ANALYSES
from coretrace_python.source import SourceManager

try:
    from coretrace_python.abstract import (
        AbstractValue,
        ConstantFacts,
        ConstantPropagation,
        Truth,
    )
    from coretrace_python.dataflow import BOTTOM, TOP
except ImportError as error:  # pragma: no cover - red until abstract values land
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_abstract() -> None:
    if MISSING is not None:
        pytest.fail(f"abstract values are not implemented yet: {MISSING}")


def analyze(source_text: str) -> tuple[FunctionIR, ConstantFacts]:
    module = build_hir(SourceManager().add_source("const.py", source_text))
    manager = AnalysisManager(module)
    manager.register(
        *SEMANTIC_ANALYSES,
        CFGAnalysis,
        DominanceAnalysis,
        PyIRAnalysis,
        SSAAnalysis,
        ConstantPropagation,
    )
    function = next(s for s in module.body if isinstance(s, nodes.Function))
    return manager.get(SSAAnalysis, function), manager.get(ConstantPropagation, function)


def returned(function: FunctionIR, facts: ConstantFacts, block: str = "entry") -> AbstractValue:
    terminator = next(b for b in function.blocks if b.id == BlockId(block)).terminator
    assert isinstance(terminator, Return) and terminator.value is not None
    return facts.value(terminator.value)


# --------------------------------------------------------------------------- abstract values


def test_abstract_value_of_a_constant() -> None:
    value = AbstractValue.of(3)

    assert value.constant == 3
    assert value.types == frozenset({"int"})
    assert value.truthiness is Truth.TRUE
    assert AbstractValue.of(0).truthiness is Truth.FALSE
    assert AbstractValue.of("").truthiness is Truth.FALSE
    assert AbstractValue.of(None).types == frozenset({"NoneType"})


def test_unknown_abstract_value() -> None:
    value = AbstractValue.unknown()

    assert value.constant is TOP
    assert value.types is None
    assert value.truthiness is Truth.UNKNOWN
    assert AbstractValue.bottom().constant is BOTTOM


def test_join_keeps_agreement_and_widens_disagreement() -> None:
    assert AbstractValue.of(1).join(AbstractValue.of(1)) == AbstractValue.of(1)
    joined = AbstractValue.of(1).join(AbstractValue.of(2))
    assert joined.constant is TOP
    assert joined.types == frozenset({"int"})
    assert joined.truthiness is Truth.UNKNOWN
    assert AbstractValue.of(1).join(AbstractValue.of("a")).types == frozenset({"int", "str"})
    assert AbstractValue.of(1).join(AbstractValue.unknown()).types is None
    assert AbstractValue.bottom().join(AbstractValue.of(1)) == AbstractValue.of(1)


def test_truthiness_survives_a_lost_constant_when_types_agree() -> None:
    joined = AbstractValue.of(1).join(AbstractValue.of(2))
    assert joined.truthiness is Truth.UNKNOWN
    known_truthy = AbstractValue.of(1).join(AbstractValue.of(True))
    assert known_truthy.truthiness is Truth.UNKNOWN


def test_abstract_values_are_immutable() -> None:
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        AbstractValue.of(1).constant = 2  # type: ignore[misc]


# --------------------------------------------------------------------------- folding


def test_constants_propagate_through_pure_operations() -> None:
    function, facts = analyze("def f():\n    x = 1\n    y = x + 2\n    return y * 3\n")
    assert returned(function, facts).constant == 9


@pytest.mark.parametrize(
    "expression, expected",
    [
        ("2 - 5", -3),
        ("7 // 2", 3),
        ("7 % 3", 1),
        ("6 / 3", 2.0),
        ("'a' + 'b'", "ab"),
        ("3 < 4", True),
        ("'x' == 'x'", True),
        ("None is None", True),
        ("not 0", True),
        ("-4", -4),
        ("6 & 3", 2),
        ("6 | 3", 7),
    ],
)
def test_folds_arithmetic_comparisons_and_unary_operators(expression: str, expected: object) -> None:
    function, facts = analyze(f"def f():\n    return {expression}\n")
    value = returned(function, facts)
    assert value.constant == expected
    assert type(value.constant) is type(expected)


@pytest.mark.parametrize("expression", ["1 / 0", "2 ** 100", "1 << 3", "'a' * 3"])
def test_unsafe_or_unbounded_operations_are_not_folded(expression: str) -> None:
    function, facts = analyze(f"def f():\n    return {expression}\n")
    assert returned(function, facts).constant is TOP


def test_parameters_globals_and_calls_are_unknown() -> None:
    function, facts = analyze("def f(a):\n    b = a + 1\n    c = g(b)\n    return c\n")
    assert facts.value(function.parameters[0]).constant is TOP
    assert returned(function, facts).constant is TOP
    assert returned(function, facts).types is None


def test_types_are_tracked_without_constants() -> None:
    function, facts = analyze("def f(c):\n    if c:\n        x = 1\n    else:\n        x = 2\n    return x\n")
    value = returned(function, facts, "merge_1")

    assert value.constant is TOP
    assert value.types == frozenset({"int"})


# --------------------------------------------------------------------------- control flow


def test_phi_of_equal_constants_stays_constant() -> None:
    function, facts = analyze("def f(c):\n    if c:\n        x = 1\n    else:\n        x = 1\n    return x\n")
    assert returned(function, facts, "merge_1").constant == 1


def test_constant_condition_prunes_the_dead_branch() -> None:
    function, facts = analyze(
        "def f():\n    if True:\n        x = 1\n    else:\n        x = 2\n    return x\n"
    )
    merge = next(b for b in function.blocks if b.id == BlockId("merge_1"))
    phi = merge.instructions[0]
    assert isinstance(phi, Phi)

    assert facts.reachable(BlockId("then_1"))
    assert not facts.reachable(BlockId("else_1"))
    assert facts.value(phi.result).constant == 1


def test_computed_constant_condition_also_prunes() -> None:
    function, facts = analyze(
        "def f():\n    debug = 1 > 2\n    if debug:\n        x = 'dev'\n    else:\n        x = 'prod'\n    return x\n"
    )
    assert returned(function, facts, "merge_1").constant == "prod"
    assert not facts.reachable(BlockId("then_1"))


def test_loop_counter_is_not_constant_but_keeps_its_type() -> None:
    function, facts = analyze("def f():\n    n = 0\n    while n < 10:\n        n = n + 1\n    return n\n")
    value = returned(function, facts, "exit_1")

    assert value.constant is TOP
    assert value.types == frozenset({"int"})


def test_loop_invariant_stays_constant() -> None:
    function, facts = analyze(
        "def f(items):\n    limit = 10\n    for item in items:\n        use(item, limit)\n    return limit\n"
    )
    assert returned(function, facts, "exit_1").constant == 10


def test_values_in_unreached_blocks_have_no_facts() -> None:
    function, facts = analyze("def f():\n    if False:\n        x = 1\n        return x\n    return 0\n")

    assert not facts.reachable(BlockId("then_1"))
    then_block = next(b for b in function.blocks if b.id == BlockId("then_1"))
    assert facts.value(then_block.instructions[0].result).constant is BOTTOM


# --------------------------------------------------------------------------- analysis wiring


def test_constant_propagation_is_declared_through_the_manager() -> None:
    assert ConstantPropagation.name == "abstract.constants"
    assert {SSAAnalysis, CFGAnalysis} <= ConstantPropagation.requires
    function, facts = analyze("def f():\n    return 1\n")
    assert isinstance(facts, ConstantFacts)
    assert facts.reachable(function.entry)
