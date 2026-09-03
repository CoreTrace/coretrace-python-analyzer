"""Worklist solver over control-flow graphs (architecture §37 dataflow/worklist, solver).

A problem sees, for each block, the states arriving on its executable incoming edges
(keyed by the block they come from, or ``ENTRY`` for the initial state) and returns the
states it sends along outgoing edges. Edges a problem does not return are pruned: the
blocks behind them stay unreached unless another edge reaches them.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from enum import Enum
from types import MappingProxyType
from typing import ClassVar, Generic, TypeVar

from coretrace_python.cfg import CFG, BlockId

S = TypeVar("S")

ENTRY = BlockId("<entry>")


class Direction(Enum):
    FORWARD = "forward"
    BACKWARD = "backward"


class DataflowProblem(ABC, Generic[S]):
    direction: ClassVar[Direction] = Direction.FORWARD

    @abstractmethod
    def initial(self) -> S:
        """State entering the entry block (forward) or leaving the exits (backward)."""

    @abstractmethod
    def join(self, a: S, b: S) -> S:
        """Combine the states of two incoming edges."""

    @abstractmethod
    def flow(self, cfg: CFG, block: BlockId, incoming: Mapping[BlockId, S]) -> Mapping[BlockId, S]:
        """States sent to the next blocks in the flow direction; omitted edges are pruned."""


class Solution(Generic[S]):
    def __init__(self, problem: DataflowProblem[S], edges: Mapping[BlockId, Mapping[BlockId, S]]):
        self._problem = problem
        self._incoming: Mapping[BlockId, Mapping[BlockId, S]] = MappingProxyType(
            {block: MappingProxyType(dict(found)) for block, found in edges.items()}
        )

    def incoming(self, block: BlockId) -> Mapping[BlockId, S]:
        return self._incoming.get(block, MappingProxyType({}))

    def reached(self, block: BlockId) -> bool:
        return bool(self._incoming.get(block))

    def state(self, block: BlockId) -> S:
        """Join of every state arriving at ``block``; raises for an unreached block."""

        states = list(self.incoming(block).values())
        if not states:
            raise KeyError(block)
        result = states[0]
        for other in states[1:]:
            result = self._problem.join(result, other)
        return result

    def edge(self, source: BlockId, target: BlockId) -> S:
        return self._incoming[target][source]


def solve(problem: DataflowProblem[S], cfg: CFG) -> Solution[S]:
    forward = problem.direction is Direction.FORWARD
    order = {block: position for position, block in enumerate(cfg.blocks)}
    if forward:
        starts = [cfg.entry]
    else:
        starts = [b for b in cfg.blocks if b in cfg.reachable() and not cfg.successors(b)]

    incoming: dict[BlockId, dict[BlockId, S]] = {start: {ENTRY: problem.initial()} for start in starts}
    worklist = list(starts)
    queued = set(starts)
    while worklist:
        worklist.sort(key=lambda block: order[block], reverse=True)
        block = worklist.pop()
        queued.discard(block)
        for target, state in problem.flow(cfg, block, MappingProxyType(incoming[block])).items():
            edges = incoming.setdefault(target, {})
            if block in edges and edges[block] == state:
                continue
            edges[block] = state
            if target not in queued:
                worklist.append(target)
                queued.add(target)
    return Solution(problem, incoming)
