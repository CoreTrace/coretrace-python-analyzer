"""Acceptance tests for PyIR over the control-flow graph (``docs/architecture.md`` §6).

PyIR mirrors the CFG: one immutable block per CFG block, in CFG order, each ending in
an explicit terminator (``Branch``, ``Jump``, ``Return``, ``Raise`` or ``ForNext``).
Values are numbered once per function, so a value defined in a dominating block can
be used in later blocks. Parameters that are never reassigned stay plain values;
reassigned ones are stored to a local at entry so every block reads the same slot.

The multi-block cases are expected to remain red until lowering consumes
``CFGAnalysis`` and the IR model carries terminators.
"""

from __future__ import annotations

import dataclasses

import pytest

from coretrace_python.analysis import AnalysisManager
from coretrace_python.cfg import CFGAnalysis
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.ir.lowering import PyIRAnalysis, lower_module
from coretrace_python.ir.model import BasicBlock, BinaryOp, FunctionIR, LoadLocal, StoreLocal
from coretrace_python.semantic import SEMANTIC_ANALYSES
from coretrace_python.source import SourceManager

try:
    from coretrace_python.ir.model import Branch, ForNext, GetIter, Jump, Raise, Return
except ImportError as error:  # pragma: no cover - red until terminators exist
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_terminators() -> None:
    if MISSING is not None:
        pytest.fail(f"PyIR terminators are not implemented yet: {MISSING}")


def lower(source_text: str) -> FunctionIR:
    module = lower_module(build_hir(SourceManager().add_source("ir.py", source_text)))
    return module.functions[0]


def block_ids(function: FunctionIR) -> list[str]:
    return [str(block.id) for block in function.blocks]


def test_lowering_preserves_locations() -> None:
    function = lower("def add(a, b):\n    return a + b\n")
    entry = function.blocks[0]

    assert isinstance(entry.instructions[0], BinaryOp)
    assert entry.instructions[0].location.start_line == 2
    assert isinstance(entry.terminator, Return)
    assert entry.terminator.location.source_id.value == "ir.py"


def test_blocks_follow_the_cfg_and_are_immutable() -> None:
    function = lower("def f(a):\n    if a:\n        return 1\n    return 0\n")

    assert str(function.entry) == "entry"
    assert block_ids(function) == ["entry", "then_1", "merge_1"]
    entry = function.blocks[0]
    assert isinstance(entry, BasicBlock)
    assert isinstance(entry.instructions, tuple)
    assert isinstance(entry.terminator, Branch)
    assert str(entry.terminator.then_block) == "then_1"
    assert str(entry.terminator.else_block) == "merge_1"
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.terminator = entry.terminator  # type: ignore[misc]


def test_values_are_numbered_once_per_function() -> None:
    function = lower("def f(a):\n    x = a + 1\n    if x:\n        y = x + 1\n    return x\n")
    ids = [
        instruction.result.id
        for block in function.blocks
        for instruction in block.instructions
        if instruction.result is not None
    ]

    assert ids == sorted(ids)
    assert len(ids) == len(set(ids))


def test_reassigned_parameters_are_stored_at_entry() -> None:
    function = lower("def f(n, limit):\n    while n < limit:\n        n = n + 1\n    return n\n")
    entry = function.blocks[0]

    assert isinstance(entry.instructions[0], StoreLocal)
    assert entry.instructions[0].name == "n"
    assert entry.instructions[0].value == function.parameters[0]
    assert all(
        not (isinstance(i, StoreLocal) and i.name == "limit")
        for block in function.blocks
        for i in block.instructions
    )
    header = function.blocks[1]
    assert isinstance(header.instructions[0], LoadLocal)
    assert header.instructions[0].name == "n"


def test_for_loops_take_the_iterator_before_the_header() -> None:
    function = lower("def f(items):\n    for item in items:\n        pass\n    return item\n")
    entry, header = function.blocks[0], function.blocks[1]

    assert isinstance(entry.instructions[-1], GetIter)
    assert entry.instructions[-1].iterable == function.parameters[0]
    assert isinstance(entry.terminator, Jump)
    assert header.instructions == ()
    assert isinstance(header.terminator, ForNext)
    assert header.terminator.iterator == entry.instructions[-1].result
    assert header.terminator.target == "item"
    assert str(header.terminator.body) == "body_1"
    assert str(header.terminator.exit) == "exit_1"


def test_raise_lowers_to_a_terminator() -> None:
    function = lower("def f(a):\n    raise ValueError(a)\n")
    entry = function.blocks[0]

    assert isinstance(entry.terminator, Raise)
    assert entry.terminator.exception == entry.instructions[-1].result


def test_pyir_requires_the_cfg() -> None:
    module = build_hir(SourceManager().add_source("ir.py", "def f():\n    pass\n"))
    manager = AnalysisManager(module)
    manager.register(*SEMANTIC_ANALYSES, CFGAnalysis, PyIRAnalysis)
    function = next(s for s in module.body if isinstance(s, nodes.Function))

    assert CFGAnalysis in PyIRAnalysis.requires
    manager.get(PyIRAnalysis, function)
    assert manager.is_cached(CFGAnalysis, function)
