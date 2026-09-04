"""Control-flow graph model (architecture §5).

A block holds straight-line PyHIR statements and ends in exactly one terminator.
Python's iteration protocol stays explicit as ``ForEach`` instead of being encoded as
a generic switch; the CFG must remain semantically faithful to Python.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TypeAlias

from coretrace_python.hir import nodes
from coretrace_python.source import SourceSpan


class CFGError(Exception):
    """A malformed graph or a control statement used outside its construct."""


@dataclass(frozen=True, order=True)
class BlockId:
    value: str

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Branch:
    condition: nodes.Expression
    then_block: BlockId
    else_block: BlockId
    span: SourceSpan


@dataclass(frozen=True)
class Jump:
    target: BlockId
    span: SourceSpan


@dataclass(frozen=True)
class Return:
    value: nodes.Expression | None
    span: SourceSpan


@dataclass(frozen=True)
class Raise:
    exception: nodes.Expression | None
    span: SourceSpan


@dataclass(frozen=True)
class ForEach:
    """Bind the next item of ``iterable`` to ``target`` and enter ``body``, or ``exit``."""

    target: nodes.Name
    iterable: nodes.Expression
    body: BlockId
    exit: BlockId
    span: SourceSpan


Terminator: TypeAlias = Branch | Jump | Return | Raise | ForEach


def targets(terminator: Terminator) -> tuple[BlockId, ...]:
    if isinstance(terminator, Branch):
        return (terminator.then_block, terminator.else_block)
    if isinstance(terminator, Jump):
        return (terminator.target,)
    if isinstance(terminator, ForEach):
        return (terminator.body, terminator.exit)
    return ()


@dataclass(frozen=True)
class BasicBlock:
    id: BlockId
    statements: tuple[nodes.Statement, ...]
    terminator: Terminator
    exception_targets: tuple[BlockId, ...] = ()
    """Handler blocks control may reach if a statement of this block raises."""


@dataclass(frozen=True)
class CFG:
    entry: BlockId
    blocks: Mapping[BlockId, BasicBlock]
    _successors: Mapping[BlockId, tuple[BlockId, ...]] = field(
        init=False, repr=False, compare=False
    )
    _predecessors: Mapping[BlockId, tuple[BlockId, ...]] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        blocks = MappingProxyType(dict(self.blocks))
        if self.entry not in blocks:
            raise CFGError(f"entry block {self.entry} does not exist")
        predecessors: dict[BlockId, list[BlockId]] = {block_id: [] for block_id in blocks}
        successors: dict[BlockId, tuple[BlockId, ...]] = {}
        for block_id, block in blocks.items():
            if block.id != block_id:
                raise CFGError(f"block {block.id} is stored under {block_id}")
            found = list(targets(block.terminator))
            found.extend(t for t in block.exception_targets if t not in found)
            successors[block_id] = tuple(found)
            for target in successors[block_id]:
                if target not in blocks:
                    raise CFGError(f"block {block_id} targets unknown block {target}")
                predecessors[target].append(block_id)
        object.__setattr__(self, "blocks", blocks)
        object.__setattr__(self, "_successors", MappingProxyType(successors))
        object.__setattr__(
            self,
            "_predecessors",
            MappingProxyType({k: tuple(v) for k, v in predecessors.items()}),
        )

    def block(self, block_id: BlockId) -> BasicBlock:
        return self.blocks[block_id]

    def successors(self, block_id: BlockId) -> tuple[BlockId, ...]:
        return self._successors[block_id]

    def predecessors(self, block_id: BlockId) -> tuple[BlockId, ...]:
        return self._predecessors[block_id]

    def reachable(self) -> frozenset[BlockId]:
        seen: set[BlockId] = set()
        pending = [self.entry]
        while pending:
            block_id = pending.pop()
            if block_id not in seen:
                seen.add(block_id)
                pending.extend(self.successors(block_id))
        return frozenset(seen)

    def back_edges(self) -> frozenset[tuple[BlockId, BlockId]]:
        """Edges whose target is on the depth-first path from the entry to their source."""

        found: set[tuple[BlockId, BlockId]] = set()
        on_path: set[BlockId] = set()
        finished: set[BlockId] = set()

        def visit(block_id: BlockId) -> None:
            on_path.add(block_id)
            for successor in self.successors(block_id):
                if successor in on_path:
                    found.add((block_id, successor))
                elif successor not in finished:
                    visit(successor)
            on_path.remove(block_id)
            finished.add(block_id)

        visit(self.entry)
        return frozenset(found)
