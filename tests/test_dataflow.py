"""Acceptance tests for the generic data-flow framework (``docs/architecture.md`` §37).

``dataflow.lattice`` gives the lattice vocabulary (``BOTTOM``, ``TOP``, ``FlatLattice``).
``dataflow.solver`` runs a worklist over a CFG in either direction. A problem receives,
for each block, the states arriving on its executable incoming edges and returns the
states it sends along outgoing edges; edges it does not return are pruned, which is how
constant branches remove paths.

Expected to remain red until ``coretrace_python.dataflow`` exists.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

import pytest

from coretrace_python.cfg import CFG, BlockId, build_cfg
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.source import SourceManager

try:
    from coretrace_python.dataflow import (
        BOTTOM,
        ENTRY,
        TOP,
        DataflowProblem,
        Direction,
        FlatLattice,
        Solution,
        solve,
    )
except ImportError as error:  # pragma: no cover - red until the framework lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_dataflow() -> None:
    if MISSING is not None:
        pytest.fail(f"data-flow framework is not implemented yet: {MISSING}")


def cfg_for(source_text: str) -> CFG:
    module = build_hir(SourceManager().add_source("flow.py", source_text))
    return build_cfg(next(s for s in module.body if isinstance(s, nodes.Function)))


def b(name: str) -> BlockId:
    return BlockId(name)


IF_ELSE = "def f(c):\n    if c:\n        x = 1\n    else:\n        x = 2\n    return x\n"
WHILE = "def f(n):\n    while n:\n        n = n - 1\n    return n\n"
EARLY_RETURN = "def f(a):\n    if a:\n        return 1\n    return 0\n"


# --------------------------------------------------------------------------- lattice


def test_flat_lattice_joins_equal_elements_and_tops_different_ones() -> None:
    lattice: FlatLattice[int] = FlatLattice()

    assert lattice.join(BOTTOM, 1) == 1
    assert lattice.join(1, BOTTOM) == 1
    assert lattice.join(1, 1) == 1
    assert lattice.join(1, 2) is TOP
    assert lattice.join(TOP, 1) is TOP
    assert lattice.join(BOTTOM, BOTTOM) is BOTTOM


def test_flat_lattice_partial_order() -> None:
    lattice: FlatLattice[str] = FlatLattice()

    assert lattice.leq(BOTTOM, "a")
    assert lattice.leq("a", "a")
    assert lattice.leq("a", TOP)
    assert not lattice.leq("a", "b")
    assert not lattice.leq(TOP, "a")
    assert lattice.bottom is BOTTOM
    assert lattice.top is TOP


def test_lattice_elements_distinguish_types() -> None:
    lattice: FlatLattice[object] = FlatLattice()

    assert lattice.join(1, True) is TOP
    assert lattice.join(0, False) is TOP
    assert lattice.join(1.0, 1) is TOP


# --------------------------------------------------------------------------- solver


if MISSING is None:

    class Reaching(DataflowProblem[frozenset[BlockId]]):
        """Forward: which blocks lie on some path to each block."""

        direction: ClassVar[Direction] = Direction.FORWARD

        def initial(self) -> frozenset[BlockId]:
            return frozenset()

        def join(self, a: frozenset[BlockId], b: frozenset[BlockId]) -> frozenset[BlockId]:
            return a | b

        def flow(
            self,
            cfg: CFG,
            block: BlockId,
            incoming: Mapping[BlockId, frozenset[BlockId]],
        ) -> Mapping[BlockId, frozenset[BlockId]]:
            state = frozenset().union(*incoming.values()) | {block}
            return {successor: state for successor in cfg.successors(block)}

    class Exiting(DataflowProblem[frozenset[BlockId]]):
        """Backward: which blocks can be reached from each block."""

        direction: ClassVar[Direction] = Direction.BACKWARD

        def initial(self) -> frozenset[BlockId]:
            return frozenset()

        def join(self, a: frozenset[BlockId], b: frozenset[BlockId]) -> frozenset[BlockId]:
            return a | b

        def flow(
            self,
            cfg: CFG,
            block: BlockId,
            incoming: Mapping[BlockId, frozenset[BlockId]],
        ) -> Mapping[BlockId, frozenset[BlockId]]:
            state = frozenset().union(*incoming.values()) | {block}
            return {predecessor: state for predecessor in cfg.predecessors(block)}

    class PruneElse(Reaching):
        """Forward, but never follows the else edge of the entry branch."""

        def flow(
            self,
            cfg: CFG,
            block: BlockId,
            incoming: Mapping[BlockId, frozenset[BlockId]],
        ) -> Mapping[BlockId, frozenset[BlockId]]:
            out = dict(super().flow(cfg, block, incoming))
            if block == cfg.entry:
                out.pop(b("else_1"))
            return out

    class Counting(Reaching):
        visits: ClassVar[list[BlockId]] = []

        def flow(
            self,
            cfg: CFG,
            block: BlockId,
            incoming: Mapping[BlockId, frozenset[BlockId]],
        ) -> Mapping[BlockId, frozenset[BlockId]]:
            Counting.visits.append(block)
            return super().flow(cfg, block, incoming)


def test_forward_problem_reaches_a_fixpoint() -> None:
    solution = solve(Reaching(), cfg_for(IF_ELSE))

    assert isinstance(solution, Solution)
    assert solution.incoming(b("entry")) == {ENTRY: frozenset()}
    assert solution.state(b("then_1")) == frozenset({b("entry")})
    assert solution.state(b("merge_1")) == frozenset({b("entry"), b("then_1"), b("else_1")})
    assert solution.edge(b("then_1"), b("merge_1")) == frozenset({b("entry"), b("then_1")})


def test_backward_problem_starts_from_the_exits() -> None:
    solution = solve(Exiting(), cfg_for(EARLY_RETURN))

    assert solution.incoming(b("then_1")) == {ENTRY: frozenset()}
    assert solution.incoming(b("merge_1")) == {ENTRY: frozenset()}
    assert solution.state(b("entry")) == frozenset({b("then_1"), b("merge_1")})


def test_loops_converge() -> None:
    solution = solve(Reaching(), cfg_for(WHILE))

    assert solution.state(b("loop_1")) == frozenset({b("entry"), b("loop_1"), b("body_1")})
    assert solution.state(b("exit_1")) == frozenset({b("entry"), b("loop_1"), b("body_1")})


def test_pruned_edges_make_blocks_unreached() -> None:
    solution = solve(PruneElse(), cfg_for(IF_ELSE))

    assert solution.reached(b("then_1"))
    assert not solution.reached(b("else_1"))
    assert solution.incoming(b("else_1")) == {}
    assert solution.state(b("merge_1")) == frozenset({b("entry"), b("then_1")})
    assert solution.incoming(b("merge_1")) == {
        b("then_1"): frozenset({b("entry"), b("then_1")}),
    }


def test_unreachable_code_is_never_visited() -> None:
    Counting.visits = []
    solve(Counting(), cfg_for("def f():\n    return 1\n    x = 2\n"))

    assert Counting.visits == [b("entry")]


def test_blocks_are_revisited_only_when_their_inputs_change() -> None:
    Counting.visits = []
    solve(Counting(), cfg_for(IF_ELSE))

    assert Counting.visits == [b("entry"), b("then_1"), b("else_1"), b("merge_1")]


def test_solutions_are_immutable() -> None:
    solution = solve(Reaching(), cfg_for(IF_ELSE))
    with pytest.raises(TypeError):
        solution.incoming(b("merge_1"))[b("x")] = frozenset()  # type: ignore[index]
