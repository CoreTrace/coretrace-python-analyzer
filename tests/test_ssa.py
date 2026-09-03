"""Acceptance tests for SSA construction and def-use chains (``docs/architecture.md`` §7).

``SSAAnalysis`` derives a new immutable ``FunctionIR`` from the non-SSA PyIR: locals
disappear, every value is defined exactly once, merges get ``Phi`` instructions, a
``for_next`` terminator defines the loop variable, and a local read before any
definition on some path reads an explicit ``Undefined`` value. Values are renumbered
densely in block order. ``DefUseAnalysis`` indexes definitions and uses over that IR.

Expected to remain red until ``coretrace_python.ir.ssa`` and ``coretrace_python.ir.defuse``
exist.
"""

from __future__ import annotations

import pytest

from coretrace_python.analysis import AnalysisManager
from coretrace_python.cfg import BlockId, CFGAnalysis
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.ir.lowering import PyIRAnalysis
from coretrace_python.ir.model import (
    Branch,
    Call,
    ForNext,
    FunctionIR,
    Global,
    LoadLocal,
    Return,
    StoreLocal,
    Value,
)
from coretrace_python.semantic import SEMANTIC_ANALYSES
from coretrace_python.source import SourceManager

try:
    from coretrace_python.cfg.dominance import DominanceAnalysis
    from coretrace_python.ir.defuse import Definition, DefUse, DefUseAnalysis, Use
    from coretrace_python.ir.model import Phi, Undefined
    from coretrace_python.ir.ssa import SSAAnalysis, to_ssa
except ImportError as error:  # pragma: no cover - red until SSA lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_ssa() -> None:
    if MISSING is not None:
        pytest.fail(f"SSA is not implemented yet: {MISSING}")


DOC_EXAMPLE = "def f(a, b, cond):\n    x = a\n    if cond:\n        x = b\n    use(x)\n"


def analyses(source_text: str) -> tuple[AnalysisManager, nodes.Function]:
    module = build_hir(SourceManager().add_source("ssa.py", source_text))
    manager = AnalysisManager(module)
    manager.register(
        *SEMANTIC_ANALYSES,
        CFGAnalysis,
        DominanceAnalysis,
        PyIRAnalysis,
        SSAAnalysis,
        DefUseAnalysis,
    )
    return manager, next(s for s in module.body if isinstance(s, nodes.Function))


def ssa(source_text: str) -> FunctionIR:
    manager, target = analyses(source_text)
    return manager.get(SSAAnalysis, target)


def block(function: FunctionIR, name: str):  # type: ignore[no-untyped-def]
    return next(b for b in function.blocks if b.id == BlockId(name))


def defined_values(function: FunctionIR) -> list[Value]:
    values = list(function.parameters)
    for basic_block in function.blocks:
        for instruction in basic_block.instructions:
            if instruction.result is not None:
                values.append(instruction.result)
        if isinstance(basic_block.terminator, ForNext) and basic_block.terminator.result:
            values.append(basic_block.terminator.result)
    return values


# --------------------------------------------------------------------------- the §7 example


def test_doc_example_merges_with_one_phi() -> None:
    function = ssa(DOC_EXAMPLE)
    merge = block(function, "merge_1")

    phi = merge.instructions[0]
    assert isinstance(phi, Phi)
    assert phi.name == "x"
    assert phi.incoming == (
        (function.parameters[0], BlockId("entry")),
        (function.parameters[1], BlockId("then_1")),
    )
    call = merge.instructions[2]
    assert isinstance(call, Call)
    assert call.arguments == (phi.result,)


def test_ssa_has_no_locals_and_defines_each_value_once() -> None:
    function = ssa(DOC_EXAMPLE)

    for basic_block in function.blocks:
        assert not any(isinstance(i, LoadLocal | StoreLocal) for i in basic_block.instructions)
    values = defined_values(function)
    assert len(values) == len(set(values))


def test_values_are_renumbered_densely_in_block_order() -> None:
    function = ssa(DOC_EXAMPLE)
    assert [value.id for value in defined_values(function)] == list(range(6))


def test_trivial_stores_do_not_create_instructions() -> None:
    # ``x = a`` needs no copy: the local simply refers to the parameter value.
    function = ssa(DOC_EXAMPLE)
    assert block(function, "entry").instructions == ()
    assert block(function, "then_1").instructions == ()


# --------------------------------------------------------------------------- loops


def test_loop_header_phi_takes_the_back_edge_value() -> None:
    function = ssa("def f(n):\n    while n > 0:\n        n = n - 1\n    return n\n")
    header = block(function, "loop_1")
    body = block(function, "body_1")

    phi = header.instructions[0]
    assert isinstance(phi, Phi)
    assert phi.name == "n"
    assert phi.incoming[0] == (function.parameters[0], BlockId("entry"))
    assert phi.incoming[1] == (body.instructions[-1].result, BlockId("body_1"))
    assert isinstance(header.terminator, Branch)
    exit_block = block(function, "exit_1")
    assert isinstance(exit_block.terminator, Return)
    assert exit_block.terminator.value == phi.result


def test_for_next_defines_the_loop_variable() -> None:
    function = ssa(
        "def f(items):\n    total = 0\n    for item in items:\n        total = total + item\n    return total\n"
    )
    header = block(function, "loop_1")
    body = block(function, "body_1")

    assert isinstance(header.terminator, ForNext)
    assert header.terminator.result is not None
    assert header.terminator.target == "item"
    add = body.instructions[0]
    assert add.operands() == (header.instructions[0].result, header.terminator.result)  # type: ignore[union-attr]


def test_loop_variable_after_the_loop_is_a_phi_at_the_header() -> None:
    function = ssa("def f(items):\n    for item in items:\n        pass\n    return item\n")
    header = block(function, "loop_1")
    exit_block = block(function, "exit_1")

    phi = header.instructions[0]
    assert isinstance(phi, Phi)
    assert phi.name == "item"
    assert isinstance(header.terminator, ForNext)
    assert phi.incoming[1] == (header.terminator.result, BlockId("body_1"))
    assert isinstance(exit_block.terminator, Return)
    assert exit_block.terminator.value == phi.result


# --------------------------------------------------------------------------- undefined


def test_possibly_unassigned_local_reads_an_explicit_undefined_value() -> None:
    function = ssa("def f(c):\n    if c:\n        x = 1\n    return x\n")
    entry = block(function, "entry")
    merge = block(function, "merge_1")

    undefined = entry.instructions[0]
    assert isinstance(undefined, Undefined)
    assert undefined.name == "x"
    phi = merge.instructions[0]
    assert isinstance(phi, Phi)
    assert phi.incoming == (
        (undefined.result, BlockId("entry")),
        (block(function, "then_1").instructions[0].result, BlockId("then_1")),
    )


def test_undefined_is_only_introduced_when_needed() -> None:
    function = ssa(DOC_EXAMPLE)
    assert not any(isinstance(i, Undefined) for b in function.blocks for i in b.instructions)


# --------------------------------------------------------------------------- invariants


def test_phi_incoming_edges_match_the_predecessors() -> None:
    manager, target = analyses(
        "def f(items, flag):\n"
        "    x = 0\n"
        "    for item in items:\n"
        "        if flag:\n"
        "            continue\n"
        "        x = x + item\n"
        "    return x\n"
    )
    cfg = manager.get(CFGAnalysis, target)
    function = manager.get(SSAAnalysis, target)

    for basic_block in function.blocks:
        for instruction in basic_block.instructions:
            if isinstance(instruction, Phi):
                assert tuple(b for _, b in instruction.incoming) == cfg.predecessors(basic_block.id)


def test_ssa_is_a_derived_immutable_ir() -> None:
    manager, target = analyses(DOC_EXAMPLE)

    original = manager.get(PyIRAnalysis, target)
    derived = manager.get(SSAAnalysis, target)

    assert derived is not original
    assert any(isinstance(i, StoreLocal) for b in original.blocks for i in b.instructions)
    assert manager.get(SSAAnalysis, target) is derived
    assert SSAAnalysis.name == "ir.ssa"
    assert {PyIRAnalysis, DominanceAnalysis} <= SSAAnalysis.requires


def test_to_ssa_is_a_pure_function() -> None:
    manager, target = analyses(DOC_EXAMPLE)
    pyir = manager.get(PyIRAnalysis, target)
    dominance = manager.get(DominanceAnalysis, target)

    assert to_ssa(pyir, dominance) == to_ssa(pyir, dominance)


# --------------------------------------------------------------------------- def-use


def test_def_use_indexes_definitions_and_uses() -> None:
    manager, target = analyses(DOC_EXAMPLE)
    function = manager.get(SSAAnalysis, target)
    chains = manager.get(DefUseAnalysis, target)
    merge = block(function, "merge_1")
    phi, callee, call = merge.instructions

    assert isinstance(chains, DefUse)
    assert chains.definition(function.parameters[2]) == Definition(None, None)
    assert chains.definition(phi.result) == Definition(BlockId("merge_1"), 0)
    assert chains.uses(function.parameters[2]) == (Use(BlockId("entry"), None),)
    assert chains.uses(function.parameters[0]) == (Use(BlockId("merge_1"), 0),)
    assert chains.uses(phi.result) == (Use(BlockId("merge_1"), 2),)
    assert chains.uses(call.result) == ()
    assert isinstance(callee, Global)


def test_def_use_records_terminator_definitions() -> None:
    manager, target = analyses("def f(items):\n    for item in items:\n        use(item)\n    return 0\n")
    function = manager.get(SSAAnalysis, target)
    chains = manager.get(DefUseAnalysis, target)
    header = block(function, "loop_1")
    assert isinstance(header.terminator, ForNext)
    assert header.terminator.result is not None

    assert chains.definition(header.terminator.result) == Definition(BlockId("loop_1"), None)
    assert chains.uses(header.terminator.result) == (Use(BlockId("body_1"), 1),)
    assert DefUseAnalysis.name == "ir.defuse"
    assert SSAAnalysis in DefUseAnalysis.requires
