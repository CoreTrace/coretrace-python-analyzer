"""Acceptance tests for control-flow graphs (``docs/architecture.md`` §5).

Each function becomes a graph of basic blocks. A block holds straight-line PyHIR
statements and ends in exactly one explicit terminator: ``Branch``, ``Jump``,
``Return``, ``Raise`` or ``ForEach`` (Python's iteration protocol kept explicit rather
than encoded as a generic switch). The graph exposes predecessors, successors,
reachability and back edges, and validates its own integrity.

Expected to remain red until ``coretrace_python.cfg`` exists and PyHIR represents
``if``, ``while``, ``for``, ``break``, ``continue`` and ``raise``.
"""

from __future__ import annotations

import dataclasses

import pytest

from coretrace_python.analysis import AnalysisManager
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.source import SourceManager

try:
    from coretrace_python.cfg import (
        CFG,
        BasicBlock,
        BlockId,
        Branch,
        CFGAnalysis,
        CFGError,
        ForEach,
        Jump,
        Raise,
        Return,
        build_cfg,
    )
except ImportError as error:  # pragma: no cover - red until the CFG lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_cfg() -> None:
    if MISSING is not None:
        pytest.fail(f"control-flow graphs are not implemented yet: {MISSING}")


def function(source_text: str) -> nodes.Function:
    module = build_hir(SourceManager().add_source("flow.py", source_text))
    for statement in module.body:
        if isinstance(statement, nodes.Function):
            return statement
    raise AssertionError("no function in source")


def cfg_for(source_text: str) -> CFG:
    return build_cfg(function(source_text))


def only(cfg: CFG, block_id: BlockId) -> BlockId:
    successors = cfg.successors(block_id)
    assert len(successors) == 1, successors
    return successors[0]


def assigned_names(block: BasicBlock) -> list[str]:
    return [s.target.identifier for s in block.statements if isinstance(s, nodes.Assign)]


# --------------------------------------------------------------------------- straight line


def test_straight_line_function_is_one_block() -> None:
    cfg = cfg_for("def f(a):\n    x = a\n    y = x\n    return y\n")
    entry = cfg.block(cfg.entry)

    assert len(cfg.blocks) == 1
    assert assigned_names(entry) == ["x", "y"]
    assert isinstance(entry.terminator, Return)
    assert isinstance(entry.terminator.value, nodes.Name)
    assert cfg.successors(cfg.entry) == ()
    assert cfg.predecessors(cfg.entry) == ()


def test_falling_off_the_end_returns_none() -> None:
    cfg = cfg_for("def f():\n    x = 1\n")
    terminator = cfg.block(cfg.entry).terminator

    assert isinstance(terminator, Return)
    assert terminator.value is None


def test_terminator_carries_the_span_of_its_statement() -> None:
    cfg = cfg_for("def f(a):\n    x = a\n    return x\n")
    assert cfg.block(cfg.entry).terminator.span.start_line == 3


# --------------------------------------------------------------------------- branches


def test_if_else_joins_at_a_merge_block() -> None:
    cfg = cfg_for(
        "def f(safe, x):\n"
        "    if safe:\n"
        "        x = sanitize(x)\n"
        "    else:\n"
        "        x = 0\n"
        "    sink(x)\n"
    )
    entry = cfg.block(cfg.entry)
    assert isinstance(entry.terminator, Branch)
    assert isinstance(entry.terminator.condition, nodes.Name)
    then_id, else_id = entry.terminator.then_block, entry.terminator.else_block
    assert cfg.successors(cfg.entry) == (then_id, else_id)

    then_block, else_block = cfg.block(then_id), cfg.block(else_id)
    assert assigned_names(then_block) == ["x"]
    assert assigned_names(else_block) == ["x"]
    assert isinstance(then_block.terminator, Jump)
    assert isinstance(else_block.terminator, Jump)
    merge_id = then_block.terminator.target
    assert else_block.terminator.target == merge_id
    assert cfg.predecessors(merge_id) == (then_id, else_id)

    merge = cfg.block(merge_id)
    assert len(merge.statements) == 1
    assert isinstance(merge.terminator, Return)
    assert len(cfg.blocks) == 4


def test_if_without_else_branches_straight_to_the_merge() -> None:
    # The example of §5: ``if safe: x = sanitize(x)`` then ``sink(x)``.
    cfg = cfg_for("def f(safe, x):\n    if safe:\n        x = sanitize(x)\n    sink(x)\n")
    entry = cfg.block(cfg.entry)
    assert isinstance(entry.terminator, Branch)

    then_block = cfg.block(entry.terminator.then_block)
    assert isinstance(then_block.terminator, Jump)
    assert then_block.terminator.target == entry.terminator.else_block
    # Predecessors follow block order: the entry block is finished before the then block.
    assert cfg.predecessors(entry.terminator.else_block) == (
        cfg.entry,
        entry.terminator.then_block,
    )
    assert len(cfg.blocks) == 3


def test_elif_chains_nest_branches() -> None:
    cfg = cfg_for(
        "def f(a):\n"
        "    if a == 1:\n"
        "        return 1\n"
        "    elif a == 2:\n"
        "        return 2\n"
        "    return 0\n"
    )
    first = cfg.block(cfg.entry).terminator
    assert isinstance(first, Branch)
    second = cfg.block(first.else_block).terminator
    assert isinstance(second, Branch)
    assert isinstance(cfg.block(first.then_block).terminator, Return)
    assert isinstance(cfg.block(second.then_block).terminator, Return)
    assert isinstance(cfg.block(second.else_block).terminator, Return)


def test_early_return_leaves_one_predecessor_at_the_merge() -> None:
    cfg = cfg_for(
        "def f(value):\n"
        "    if not value.isdigit():\n"
        "        return None\n"
        "    sink(value)\n"
        "    return value\n"
    )
    branch = cfg.block(cfg.entry).terminator
    assert isinstance(branch, Branch)
    assert isinstance(cfg.block(branch.then_block).terminator, Return)
    assert cfg.successors(branch.then_block) == ()
    assert cfg.predecessors(branch.else_block) == (cfg.entry,)


# --------------------------------------------------------------------------- loops


def test_while_loop_has_a_header_with_a_back_edge() -> None:
    cfg = cfg_for("def f(n):\n    while n > 0:\n        n = n - 1\n    return n\n")
    entry = cfg.block(cfg.entry)
    assert isinstance(entry.terminator, Jump)
    header_id = entry.terminator.target

    header = cfg.block(header_id)
    assert header.statements == ()
    assert isinstance(header.terminator, Branch)
    body_id, exit_id = header.terminator.then_block, header.terminator.else_block

    body = cfg.block(body_id)
    assert assigned_names(body) == ["n"]
    assert isinstance(body.terminator, Jump)
    assert body.terminator.target == header_id
    assert cfg.predecessors(header_id) == (cfg.entry, body_id)
    assert cfg.back_edges() == frozenset({(body_id, header_id)})
    assert isinstance(cfg.block(exit_id).terminator, Return)


def test_for_loop_keeps_the_iteration_protocol_explicit() -> None:
    cfg = cfg_for("def f(items):\n    total = 0\n    for item in items:\n        total = total + item\n    return total\n")
    entry = cfg.block(cfg.entry)
    assert assigned_names(entry) == ["total"]
    assert isinstance(entry.terminator, Jump)
    header = cfg.block(entry.terminator.target)

    assert isinstance(header.terminator, ForEach)
    assert header.terminator.target.identifier == "item"
    assert isinstance(header.terminator.iterable, nodes.Name)
    body = cfg.block(header.terminator.body)
    assert assigned_names(body) == ["total"]
    assert isinstance(body.terminator, Jump)
    assert body.terminator.target == entry.terminator.target
    assert cfg.back_edges() == frozenset({(header.terminator.body, entry.terminator.target)})
    assert isinstance(cfg.block(header.terminator.exit).terminator, Return)


def test_break_jumps_to_the_loop_exit() -> None:
    cfg = cfg_for(
        "def f(items):\n"
        "    for item in items:\n"
        "        if item:\n"
        "            break\n"
        "    return 1\n"
    )
    header = cfg.block(only(cfg, cfg.entry))
    assert isinstance(header.terminator, ForEach)
    body = cfg.block(header.terminator.body)
    assert isinstance(body.terminator, Branch)
    break_block = cfg.block(body.terminator.then_block)

    assert break_block.statements == ()
    assert isinstance(break_block.terminator, Jump)
    assert break_block.terminator.target == header.terminator.exit
    assert set(cfg.predecessors(header.terminator.exit)) == {
        only(cfg, cfg.entry),
        body.terminator.then_block,
    }


def test_continue_jumps_to_the_loop_header() -> None:
    cfg = cfg_for(
        "def f(n):\n"
        "    while n:\n"
        "        if n == 3:\n"
        "            continue\n"
        "        n = n - 1\n"
        "    return n\n"
    )
    header_id = only(cfg, cfg.entry)
    body = cfg.block(cfg.block(header_id).terminator.then_block)  # type: ignore[union-attr]
    assert isinstance(body.terminator, Branch)
    continue_block = cfg.block(body.terminator.then_block)

    assert isinstance(continue_block.terminator, Jump)
    assert continue_block.terminator.target == header_id
    assert (body.terminator.then_block, header_id) in cfg.back_edges()


@pytest.mark.parametrize(
    "statement, location",
    [("break", "flow.py:2:5"), ("continue", "flow.py:2:5")],
)
def test_loop_control_outside_a_loop_is_an_error(statement: str, location: str) -> None:
    with pytest.raises(CFGError, match=rf"{location}: .*{statement}.*outside"):
        cfg_for(f"def f():\n    {statement}\n")


# --------------------------------------------------------------------------- raise and reachability


def test_raise_terminates_a_block_and_makes_the_rest_unreachable() -> None:
    cfg = cfg_for(
        "def f(a):\n"
        "    if a:\n"
        "        raise ValueError(a)\n"
        "        x = 1\n"
        "    return a\n"
    )
    branch = cfg.block(cfg.entry).terminator
    assert isinstance(branch, Branch)
    raising = cfg.block(branch.then_block)
    assert isinstance(raising.terminator, Raise)
    assert isinstance(raising.terminator.exception, nodes.Call)
    assert cfg.successors(branch.then_block) == ()

    unreachable = [b for b in cfg.blocks.values() if assigned_names(b) == ["x"]]
    assert len(unreachable) == 1
    assert unreachable[0].id not in cfg.reachable()
    assert cfg.entry in cfg.reachable()
    assert branch.else_block in cfg.reachable()


def test_bare_raise_has_no_exception_expression() -> None:
    cfg = cfg_for("def f():\n    raise\n")
    terminator = cfg.block(cfg.entry).terminator
    assert isinstance(terminator, Raise)
    assert terminator.exception is None


def test_code_after_return_is_kept_but_unreachable() -> None:
    cfg = cfg_for("def f():\n    return 1\n    x = 2\n")
    assert len(cfg.blocks) == 2
    assert cfg.reachable() == frozenset({cfg.entry})


# --------------------------------------------------------------------------- graph shape


def test_predecessors_and_successors_mirror_each_other() -> None:
    cfg = cfg_for(
        "def f(items, flag):\n"
        "    for item in items:\n"
        "        if flag:\n"
        "            continue\n"
        "        while item:\n"
        "            item = item - 1\n"
        "    return 0\n"
    )
    for block_id in cfg.blocks:
        for successor in cfg.successors(block_id):
            assert block_id in cfg.predecessors(successor)
        for predecessor in cfg.predecessors(block_id):
            assert block_id in cfg.successors(predecessor)


def test_block_order_starts_at_entry_and_is_deterministic() -> None:
    source_text = "def f(a):\n    if a:\n        a = 1\n    while a:\n        a = a - 1\n    return a\n"
    first, second = cfg_for(source_text), cfg_for(source_text)

    assert next(iter(first.blocks)) == first.entry
    assert first == second
    assert list(first.blocks) == list(second.blocks)


def test_nested_definitions_stay_inside_their_block() -> None:
    cfg = cfg_for("def f():\n    def g():\n        return 1\n    class C:\n        pass\n    return g\n")
    entry = cfg.block(cfg.entry)

    assert len(cfg.blocks) == 1
    assert [type(s).__name__ for s in entry.statements] == ["Function", "Class"]


def test_graphs_are_immutable() -> None:
    cfg = cfg_for("def f():\n    return 1\n")
    with pytest.raises(dataclasses.FrozenInstanceError):
        cfg.entry = BlockId("other")  # type: ignore[misc]
    with pytest.raises(TypeError):
        cfg.blocks[BlockId("other")] = cfg.block(cfg.entry)  # type: ignore[index]


def test_terminators_must_target_existing_blocks() -> None:
    entry = BlockId("entry")
    span = function("def f():\n    pass\n").span
    block = BasicBlock(entry, (), Jump(BlockId("missing"), span))

    with pytest.raises(CFGError, match="missing"):
        CFG(entry, {entry: block})


# --------------------------------------------------------------------------- analysis


def test_cfg_is_a_function_analysis() -> None:
    module = build_hir(
        SourceManager().add_source(
            "flow.py", "def a(x):\n    if x:\n        return 1\n    return 0\n\ndef b():\n    pass\n"
        )
    )
    manager = AnalysisManager(module)
    manager.register(CFGAnalysis)
    a, b = (s for s in module.body if isinstance(s, nodes.Function))

    cfg = manager.get(CFGAnalysis, a)

    assert CFGAnalysis.name == "cfg.function"
    assert isinstance(cfg, CFG)
    assert len(cfg.blocks) == 3
    assert manager.is_cached(CFGAnalysis, b) is False
