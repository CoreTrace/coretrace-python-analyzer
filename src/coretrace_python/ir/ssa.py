"""SSA construction (architecture §7).

``to_ssa`` derives a new immutable ``FunctionIR`` from the non-SSA PyIR of a function:
local loads and stores disappear, merges get ``Phi`` instructions placed on the iterated
dominance frontier of the definitions and pruned by liveness, a ``for_next`` terminator
defines the loop variable, and a local read before any definition on some path reads
an explicit ``Undefined`` value created once in the entry block. Only reachable blocks
are kept, and values are renumbered densely in block order.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import ClassVar

from coretrace_python.analysis import AnalysisContext, AnyAnalysis, FunctionAnalysis
from coretrace_python.cfg import BlockId
from coretrace_python.cfg.dominance import DominanceAnalysis, DominatorTree
from coretrace_python.hir import nodes
from coretrace_python.ir.lowering import PyIRAnalysis
from coretrace_python.ir.model import (
    BasicBlock,
    Branch,
    ForNext,
    FunctionIR,
    Instruction,
    Jump,
    LoadLocal,
    Phi,
    StoreLocal,
    Terminator,
    Undefined,
    Value,
    substitute,
)


class _Renamer:
    def __init__(self, function: FunctionIR, tree: DominatorTree) -> None:
        self.function = function
        self.tree = tree
        self.blocks = {block.id: block for block in function.blocks if block.id in tree.blocks}
        self.next_id = max((v.id for v in _all_values(function)), default=-1) + 1
        self.stacks: dict[str, list[Value]] = {}
        self.aliases: dict[Value, Value] = {}
        self.undefined: dict[str, Undefined] = {}
        self.phis: dict[BlockId, dict[str, Phi]] = {}
        self.instructions: dict[BlockId, list[Instruction]] = {}
        self.terminators: dict[BlockId, Terminator] = {}
        self.predecessors: dict[BlockId, list[BlockId]] = {b: [] for b in self.blocks}
        for block in self.blocks.values():
            for successor in _targets(block.terminator):
                self.predecessors[successor].append(block.id)
        self.loop_variables: dict[BlockId, tuple[str, BlockId]] = {}
        for block in self.blocks.values():
            if isinstance(block.terminator, ForNext):
                self.loop_variables[block.terminator.body] = (block.terminator.target, block.id)

    # ------------------------------------------------------------------ helpers

    def new_value(self) -> Value:
        value = Value(self.next_id)
        self.next_id += 1
        return value

    def current(self, name: str) -> Value:
        stack = self.stacks.get(name)
        if stack:
            return stack[-1]
        if name not in self.undefined:
            self.undefined[name] = Undefined(self.new_value(), self.function.location, name)
        return self.undefined[name].result

    def resolve(self, value: Value) -> Value:
        return self.aliases.get(value, value)

    # ------------------------------------------------------------------ phi placement

    def place_phis(self) -> None:
        definitions: dict[str, set[BlockId]] = {}
        for block in self.blocks.values():
            for instruction in block.instructions:
                if isinstance(instruction, StoreLocal):
                    definitions.setdefault(instruction.name, set()).add(block.id)
            if isinstance(block.terminator, ForNext):
                definitions.setdefault(block.terminator.target, set()).add(block.terminator.body)
        live_in = _live_in(self.blocks, self.predecessors, self.loop_variables)
        for name, blocks in definitions.items():
            for block_id in sorted(self.tree.iterated_frontier(blocks), key=self.order):
                if name in live_in[block_id]:
                    self.phis.setdefault(block_id, {})[name] = Phi(
                        self.new_value(), self.blocks[block_id].terminator.location, name, ()
                    )

    def order(self, block_id: BlockId) -> int:
        return self.tree.blocks.index(block_id)

    # ------------------------------------------------------------------ renaming

    def rename(self, block_id: BlockId) -> None:
        pushed: list[str] = []

        def push(name: str, value: Value) -> None:
            self.stacks.setdefault(name, []).append(value)
            pushed.append(name)

        if block_id in self.loop_variables:
            name, header = self.loop_variables[block_id]
            header_terminator = self.terminators[header]
            assert isinstance(header_terminator, ForNext) and header_terminator.result is not None
            push(name, header_terminator.result)
        for name, phi in self.phis.get(block_id, {}).items():
            push(name, phi.result)

        kept: list[Instruction] = []
        for instruction in self.blocks[block_id].instructions:
            if isinstance(instruction, LoadLocal):
                self.aliases[instruction.result] = self.current(instruction.name)
            elif isinstance(instruction, StoreLocal):
                push(instruction.name, self.resolve(instruction.value))
            else:
                kept.append(substitute(instruction, self.resolve))
        self.instructions[block_id] = kept

        terminator = substitute(self.blocks[block_id].terminator, self.resolve)
        if isinstance(terminator, ForNext):
            terminator = replace(terminator, result=self.new_value())
        self.terminators[block_id] = terminator

        for successor in _targets(terminator):
            for name, phi in self.phis.get(successor, {}).items():
                incoming = (*phi.incoming, (self.current(name), block_id))
                self.phis[successor][name] = replace(phi, incoming=incoming)

        for child in self.tree.children(block_id):
            self.rename(child)
        for name in reversed(pushed):
            self.stacks[name].pop()

    # ------------------------------------------------------------------ assembly

    def build(self) -> FunctionIR:
        self.place_phis()
        self.rename(self.tree.root)
        blocks: list[BasicBlock] = []
        for block in self.function.blocks:
            if block.id not in self.blocks:
                continue
            instructions: list[Instruction] = []
            if block.id == self.function.entry:
                instructions.extend(self.undefined.values())
            instructions.extend(self.ordered_phis(block.id))
            instructions.extend(self.instructions[block.id])
            blocks.append(BasicBlock(block.id, tuple(instructions), self.terminators[block.id]))
        return _renumber(replace(self.function, blocks=tuple(blocks)))

    def ordered_phis(self, block_id: BlockId) -> list[Phi]:
        phis = self.phis.get(block_id, {})
        ordered_incoming = []
        for phi in phis.values():
            by_block = {b: v for v, b in phi.incoming}
            incoming = tuple((by_block[p], p) for p in self.predecessors[block_id])
            ordered_incoming.append(replace(phi, incoming=incoming))
        return ordered_incoming


def _targets(terminator: Terminator) -> tuple[BlockId, ...]:
    if isinstance(terminator, Branch):
        return (terminator.then_block, terminator.else_block)
    if isinstance(terminator, Jump):
        return (terminator.target,)
    if isinstance(terminator, ForNext):
        return (terminator.body, terminator.exit)
    return ()


def _all_values(function: FunctionIR) -> list[Value]:
    values = list(function.parameters)
    for block in function.blocks:
        for instruction in block.instructions:
            if instruction.result is not None:
                values.append(instruction.result)
    return values


def _live_in(
    blocks: Mapping[BlockId, BasicBlock],
    predecessors: Mapping[BlockId, list[BlockId]],
    loop_variables: Mapping[BlockId, tuple[str, BlockId]],
) -> dict[BlockId, frozenset[str]]:
    """Backward liveness of local names over the non-SSA blocks."""

    uses: dict[BlockId, set[str]] = {}
    defs: dict[BlockId, set[str]] = {}
    for block_id, block in blocks.items():
        used: set[str] = set()
        defined: set[str] = set()
        if block_id in loop_variables:
            defined.add(loop_variables[block_id][0])
        for instruction in block.instructions:
            if isinstance(instruction, LoadLocal) and instruction.name not in defined:
                used.add(instruction.name)
            elif isinstance(instruction, StoreLocal):
                defined.add(instruction.name)
        uses[block_id], defs[block_id] = used, defined

    successors: dict[BlockId, list[BlockId]] = {b: [] for b in blocks}
    for block_id, preds in predecessors.items():
        for predecessor in preds:
            successors[predecessor].append(block_id)

    live_in: dict[BlockId, frozenset[str]] = {b: frozenset() for b in blocks}
    changed = True
    while changed:
        changed = False
        for block_id in blocks:
            live_out: set[str] = set()
            for successor in successors[block_id]:
                live_out |= live_in[successor]
            new = frozenset(uses[block_id] | (live_out - defs[block_id]))
            if new != live_in[block_id]:
                live_in[block_id] = new
                changed = True
    return live_in


def _renumber(function: FunctionIR) -> FunctionIR:
    mapping: dict[Value, Value] = {}

    def fresh(value: Value) -> None:
        mapping[value] = Value(len(mapping))

    for parameter in function.parameters:
        fresh(parameter)
    for block in function.blocks:
        for instruction in block.instructions:
            if instruction.result is not None:
                fresh(instruction.result)
        if isinstance(block.terminator, ForNext) and block.terminator.result is not None:
            fresh(block.terminator.result)

    def renamed(value: Value) -> Value:
        return mapping[value]

    blocks = tuple(
        BasicBlock(
            block.id,
            tuple(substitute(i, renamed, include_result=True) for i in block.instructions),
            substitute(block.terminator, renamed, include_result=True),
        )
        for block in function.blocks
    )
    return replace(
        function, parameters=tuple(renamed(p) for p in function.parameters), blocks=blocks
    )


def to_ssa(function: FunctionIR, dominance: DominatorTree) -> FunctionIR:
    return _Renamer(function, dominance).build()


class SSAAnalysis(FunctionAnalysis[FunctionIR]):
    """SSA form of a function, derived from its PyIR and dominator tree."""

    name: ClassVar[str] = "ir.ssa"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({PyIRAnalysis, DominanceAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> FunctionIR:
        return to_ssa(ctx.get(PyIRAnalysis, function), ctx.get(DominanceAnalysis, function))
