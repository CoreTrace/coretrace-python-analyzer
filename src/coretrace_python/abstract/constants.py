"""Constant propagation: the reference client of the data-flow solver (§18, §38)."""

from __future__ import annotations

import operator
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Any, ClassVar

from coretrace_python.abstract.values import AbstractValue, Truth
from coretrace_python.analysis import AnalysisContext, AnyAnalysis, FunctionAnalysis
from coretrace_python.cfg import CFG, BlockId, CFGAnalysis
from coretrace_python.dataflow import BOTTOM, TOP, DataflowProblem, Direction, solve
from coretrace_python.hir import nodes
from coretrace_python.ir.model import (
    BasicBlock,
    BinaryOp,
    Branch,
    Compare,
    Constant,
    ForNext,
    FunctionIR,
    Instruction,
    Jump,
    Phi,
    UnaryOp,
    Value,
)
from coretrace_python.ir.ssa import SSAAnalysis

State = Mapping[Value, AbstractValue]

_SAFE_TYPES = (int, float, bool, str, bytes, type(None))
_NUMERIC = frozenset({"int", "float", "bool"})

_BINARY: Mapping[str, Callable[..., Any]] = {
    "add": operator.add,
    "sub": operator.sub,
    "mul": operator.mul,
    "div": operator.truediv,
    "floor_div": operator.floordiv,
    "mod": operator.mod,
    "bit_or": operator.or_,
    "bit_xor": operator.xor,
    "bit_and": operator.and_,
}
_COMPARE: Mapping[str, Callable[..., Any]] = {
    "eq": operator.eq,
    "not_eq": operator.ne,
    "lt": operator.lt,
    "lt_eq": operator.le,
    "gt": operator.gt,
    "gt_eq": operator.ge,
    "is": operator.is_,
    "is_not": operator.is_not,
    "in": lambda a, b: a in b,
    "not_in": lambda a, b: a not in b,
}
_UNARY: Mapping[str, Callable[..., Any]] = {
    "neg": operator.neg,
    "pos": operator.pos,
    "invert": operator.invert,
}


class ConstantFacts:
    def __init__(self, values: Mapping[Value, AbstractValue], reachable: frozenset[BlockId]):
        self._values = MappingProxyType(dict(values))
        self._reachable = reachable

    def value(self, value: Value) -> AbstractValue:
        return self._values.get(value, AbstractValue.bottom())

    def reachable(self, block: BlockId) -> bool:
        return block in self._reachable


class _ConstantProblem(DataflowProblem[State]):
    direction: ClassVar[Direction] = Direction.FORWARD

    def __init__(self, function: FunctionIR) -> None:
        self.function = function
        self.blocks = {block.id: block for block in function.blocks}

    def initial(self) -> State:
        return MappingProxyType({p: AbstractValue.unknown() for p in self.function.parameters})

    def join(self, a: State, b: State) -> State:
        merged = dict(a)
        for value, fact in b.items():
            merged[value] = merged[value].join(fact) if value in merged else fact
        return MappingProxyType(merged)

    def evaluate(self, block: BasicBlock, incoming: Mapping[BlockId, State]) -> State:
        """State after ``block`` given the states on its executable incoming edges."""

        states = list(incoming.values())
        state = dict(states[0])
        for other in states[1:]:
            state = dict(self.join(state, other))
        for instruction in block.instructions:
            if instruction.result is None:
                continue
            state[instruction.result] = (
                self.phi(instruction, incoming)
                if isinstance(instruction, Phi)
                else self.instruction(instruction, state)
            )
        if isinstance(block.terminator, ForNext) and block.terminator.result is not None:
            state[block.terminator.result] = AbstractValue.unknown()
        return MappingProxyType(state)

    def flow(self, cfg: CFG, block_id: BlockId, incoming: Mapping[BlockId, State]) -> Mapping[BlockId, State]:
        block = self.blocks[block_id]
        state = self.evaluate(block, incoming)
        terminator = block.terminator
        if isinstance(terminator, Branch):
            truth = state[terminator.condition].truthiness
            targets = {
                Truth.TRUE: (terminator.then_block,),
                Truth.FALSE: (terminator.else_block,),
                Truth.UNKNOWN: (terminator.then_block, terminator.else_block),
            }[truth]
            return {target: state for target in targets}
        if isinstance(terminator, Jump):
            return {terminator.target: state}
        if isinstance(terminator, ForNext):
            return {terminator.body: state, terminator.exit: state}
        return {}

    # ------------------------------------------------------------------ transfer

    def phi(self, phi: Phi, incoming: Mapping[BlockId, State]) -> AbstractValue:
        result = AbstractValue.bottom()
        for value, predecessor in phi.incoming:
            if predecessor in incoming:
                result = result.join(incoming[predecessor].get(value, AbstractValue.unknown()))
        return result

    def instruction(self, instruction: Instruction, state: Mapping[Value, AbstractValue]) -> AbstractValue:
        if isinstance(instruction, Constant):
            return AbstractValue.of(instruction.value)
        if isinstance(instruction, BinaryOp):
            return self.binary(instruction, state[instruction.left], state[instruction.right])
        if isinstance(instruction, Compare):
            return self.fold(_COMPARE[instruction.operator], state[instruction.left], state[instruction.right])
        if isinstance(instruction, UnaryOp):
            return self.unary(instruction, state[instruction.operand])
        return AbstractValue.unknown()

    def binary(self, op: BinaryOp, left: AbstractValue, right: AbstractValue) -> AbstractValue:
        folder = _BINARY.get(op.operator)
        if folder is not None:
            numeric_only = op.operator == "mul"
            folded = self.fold(folder, left, right, numeric_only=numeric_only)
            if folded.constant is not TOP:
                return folded
        return AbstractValue.unknown(self.result_types(op.operator, left, right))

    @staticmethod
    def result_types(operator_name: str, left: AbstractValue, right: AbstractValue) -> frozenset[str] | None:
        if left.types is None or right.types is None:
            return None
        if left.types <= _NUMERIC and right.types <= _NUMERIC:
            if operator_name == "div" or "float" in left.types | right.types:
                return frozenset({"float"})
            if operator_name in _BINARY:
                return frozenset({"int"})
        if operator_name == "add" and left.types == right.types == frozenset({"str"}):
            return frozenset({"str"})
        return None

    def unary(self, op: UnaryOp, operand: AbstractValue) -> AbstractValue:
        if op.operator == "not":
            if operand.truthiness is Truth.UNKNOWN:
                return AbstractValue.unknown(frozenset({"bool"}))
            return AbstractValue.of(operand.truthiness is Truth.FALSE)
        folder = _UNARY.get(op.operator)
        if folder is None or operand.constant is TOP or operand.constant is BOTTOM:
            return AbstractValue.unknown()
        if not isinstance(operand.constant, (int, float, bool)):
            return AbstractValue.unknown()
        try:
            return AbstractValue.of(folder(operand.constant))
        except (TypeError, ValueError, ArithmeticError):
            return AbstractValue.unknown()

    @staticmethod
    def fold(
        folder: Callable[..., Any],
        left: AbstractValue,
        right: AbstractValue,
        *,
        numeric_only: bool = False,
    ) -> AbstractValue:
        for side in (left.constant, right.constant):
            if side is TOP or side is BOTTOM or not isinstance(side, _SAFE_TYPES):
                return AbstractValue.unknown()
        if numeric_only and not all(isinstance(c, (int, float, bool)) for c in (left.constant, right.constant)):
            return AbstractValue.unknown()
        try:
            return AbstractValue.of(folder(left.constant, right.constant))
        except (TypeError, ValueError, ArithmeticError):
            return AbstractValue.unknown()


def propagate_constants(function: FunctionIR, cfg: CFG) -> ConstantFacts:
    problem = _ConstantProblem(function)
    solution = solve(problem, cfg)
    values: dict[Value, AbstractValue] = {}
    reachable: set[BlockId] = set()
    for block in function.blocks:
        if solution.reached(block.id):
            reachable.add(block.id)
            values.update(problem.evaluate(block, solution.incoming(block.id)))
    return ConstantFacts(values, frozenset(reachable))


class ConstantPropagation(FunctionAnalysis[ConstantFacts]):
    name: ClassVar[str] = "abstract.constants"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({SSAAnalysis, CFGAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> ConstantFacts:
        return propagate_constants(ctx.get(SSAAnalysis, function), ctx.get(CFGAnalysis, function))
