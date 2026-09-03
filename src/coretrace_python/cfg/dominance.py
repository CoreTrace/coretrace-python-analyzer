"""Dominance and post-dominance over control-flow graphs (architecture §5).

Both trees come from the same iterative algorithm (Cooper, Harvey and Kennedy) run on
the forward graph from the entry, or on the reversed graph from a virtual ``EXIT``
that follows every returning or raising block. The post-dominance frontier is the
control-dependence relation.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.analysis import AnalysisContext, AnyAnalysis, FunctionAnalysis
from coretrace_python.cfg.builder import CFGAnalysis
from coretrace_python.cfg.model import CFG, BlockId
from coretrace_python.hir import nodes

EXIT = BlockId("<exit>")


@dataclass(frozen=True)
class DominatorTree:
    root: BlockId
    blocks: tuple[BlockId, ...]
    _idom: Mapping[BlockId, BlockId | None]
    _children: Mapping[BlockId, tuple[BlockId, ...]]
    _frontier: Mapping[BlockId, frozenset[BlockId]]
    _depth: Mapping[BlockId, int] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        depth: dict[BlockId, int] = {}
        for block in self.blocks:
            parent = self._idom[block]
            depth[block] = 0 if parent is None else depth[parent] + 1
        object.__setattr__(self, "_depth", MappingProxyType(depth))

    def idom(self, block: BlockId) -> BlockId | None:
        return self._idom[block]

    def children(self, block: BlockId) -> tuple[BlockId, ...]:
        return self._children[block]

    def frontier(self, block: BlockId) -> frozenset[BlockId]:
        return self._frontier[block]

    def dominates(self, dominator: BlockId, block: BlockId) -> bool:
        if dominator not in self._idom or block not in self._idom:
            return False
        current: BlockId | None = block
        while current is not None and self._depth[current] >= self._depth[dominator]:
            if current == dominator:
                return True
            current = self._idom[current]
        return False

    def iterated_frontier(self, blocks: Iterable[BlockId]) -> frozenset[BlockId]:
        result: set[BlockId] = set()
        pending = list(blocks)
        while pending:
            for candidate in self._frontier[pending.pop()]:
                if candidate not in result:
                    result.add(candidate)
                    pending.append(candidate)
        return frozenset(result)


def _build(
    root: BlockId,
    successors: Callable[[BlockId], tuple[BlockId, ...]],
    order: Callable[[BlockId], int],
) -> DominatorTree:
    # Reverse postorder over the reachable nodes.
    postorder: list[BlockId] = []
    seen: set[BlockId] = set()

    def visit(node: BlockId) -> None:
        seen.add(node)
        for successor in successors(node):
            if successor not in seen:
                visit(successor)
        postorder.append(node)

    visit(root)
    rpo = list(reversed(postorder))
    index = {node: position for position, node in enumerate(rpo)}
    predecessors: dict[BlockId, list[BlockId]] = {node: [] for node in rpo}
    for node in rpo:
        for successor in successors(node):
            predecessors[successor].append(node)

    idom: dict[BlockId, BlockId | None] = {root: None}

    def intersect(a: BlockId, b: BlockId) -> BlockId:
        while a != b:
            while index[a] > index[b]:
                a = idom[a]  # type: ignore[assignment]
            while index[b] > index[a]:
                b = idom[b]  # type: ignore[assignment]
        return a

    changed = True
    while changed:
        changed = False
        for node in rpo[1:]:
            candidates = [p for p in predecessors[node] if p in idom]
            new_idom = candidates[0]
            for other in candidates[1:]:
                new_idom = intersect(other, new_idom)
            if idom.get(node) != new_idom:
                idom[node] = new_idom
                changed = True

    children: dict[BlockId, list[BlockId]] = {node: [] for node in rpo}
    for node in sorted(rpo, key=order):
        parent = idom[node]
        if parent is not None:
            children[parent].append(node)

    frontier: dict[BlockId, set[BlockId]] = {node: set() for node in rpo}
    for node in rpo:
        if node == root or len(predecessors[node]) < 2:
            continue
        for predecessor in predecessors[node]:
            runner: BlockId | None = predecessor
            while runner is not None and runner != idom[node]:
                frontier[runner].add(node)
                runner = idom[runner]

    preorder: list[BlockId] = []

    def walk(node: BlockId) -> None:
        preorder.append(node)
        for child in children[node]:
            walk(child)

    walk(root)
    return DominatorTree(
        root=root,
        blocks=tuple(preorder),
        _idom=MappingProxyType(dict(idom)),
        _children=MappingProxyType({k: tuple(v) for k, v in children.items()}),
        _frontier=MappingProxyType({k: frozenset(v) for k, v in frontier.items()}),
    )


def dominator_tree(cfg: CFG) -> DominatorTree:
    order = {block_id: position for position, block_id in enumerate(cfg.blocks)}
    return _build(cfg.entry, cfg.successors, lambda block: order[block])


def post_dominator_tree(cfg: CFG) -> DominatorTree:
    reachable = cfg.reachable()
    order = {block_id: position for position, block_id in enumerate(cfg.blocks)}
    order[EXIT] = -1
    leaves = tuple(b for b in cfg.blocks if b in reachable and not cfg.successors(b))

    def reversed_successors(block: BlockId) -> tuple[BlockId, ...]:
        if block == EXIT:
            return leaves
        return tuple(p for p in cfg.predecessors(block) if p in reachable)

    return _build(EXIT, reversed_successors, lambda block: order[block])


class DominanceAnalysis(FunctionAnalysis[DominatorTree]):
    name: ClassVar[str] = "cfg.dominance"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({CFGAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> DominatorTree:
        return dominator_tree(ctx.get(CFGAnalysis, function))


class PostDominanceAnalysis(FunctionAnalysis[DominatorTree]):
    name: ClassVar[str] = "cfg.post_dominance"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({CFGAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> DominatorTree:
        return post_dominator_tree(ctx.get(CFGAnalysis, function))
