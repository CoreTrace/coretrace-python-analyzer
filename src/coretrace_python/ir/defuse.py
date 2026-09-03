"""Def-use and use-def chains over SSA values (architecture §7)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.analysis import AnalysisContext, AnyAnalysis, FunctionAnalysis
from coretrace_python.cfg import BlockId
from coretrace_python.hir import nodes
from coretrace_python.ir.model import ForNext, FunctionIR, Value
from coretrace_python.ir.ssa import SSAAnalysis


@dataclass(frozen=True)
class Definition:
    """Where a value is defined: a parameter (no block), an instruction, or a terminator."""

    block: BlockId | None
    index: int | None


@dataclass(frozen=True)
class Use:
    """Where a value is used: an instruction index, or ``None`` for the terminator."""

    block: BlockId
    index: int | None


class DefUse:
    def __init__(
        self,
        definitions: Mapping[Value, Definition],
        uses: Mapping[Value, tuple[Use, ...]],
    ) -> None:
        self._definitions = MappingProxyType(dict(definitions))
        self._uses = MappingProxyType(dict(uses))

    def definition(self, value: Value) -> Definition:
        return self._definitions[value]

    def uses(self, value: Value) -> tuple[Use, ...]:
        return self._uses.get(value, ())


def def_use(function: FunctionIR) -> DefUse:
    definitions: dict[Value, Definition] = {}
    uses: dict[Value, list[Use]] = {}
    for parameter in function.parameters:
        definitions[parameter] = Definition(None, None)
    for block in function.blocks:
        for index, instruction in enumerate(block.instructions):
            if instruction.result is not None:
                definitions[instruction.result] = Definition(block.id, index)
            for operand in instruction.operands():
                uses.setdefault(operand, []).append(Use(block.id, index))
        terminator = block.terminator
        if isinstance(terminator, ForNext) and terminator.result is not None:
            definitions[terminator.result] = Definition(block.id, None)
        for operand in terminator.operands():
            uses.setdefault(operand, []).append(Use(block.id, None))
    return DefUse(definitions, {value: tuple(found) for value, found in uses.items()})


class DefUseAnalysis(FunctionAnalysis[DefUse]):
    name: ClassVar[str] = "ir.defuse"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({SSAAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> DefUse:
        return def_use(ctx.get(SSAAnalysis, function))
