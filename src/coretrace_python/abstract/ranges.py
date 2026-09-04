"""Numeric range analysis (architecture §18, §24).

Every value proven numeric gets an ``Interval``: numeric constants, arithmetic on
numbers, the results of ``int()``, ``len()`` and friends. Comparisons refine the
intervals of both sides on the branch they take, chained comparisons and ``and`` / ``or``
included, and loops converge by widening. Values not proven numeric have no interval:
the domain doubles as a proof of numeric type, which is what the refutation engine
needs, since a number cannot carry an injection.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.analysis import AnalysisContext, AnyAnalysis, FunctionAnalysis
from coretrace_python.cfg import CFG, BlockId, CFGAnalysis
from coretrace_python.dataflow import DataflowProblem, Direction, solve
from coretrace_python.hir import nodes
from coretrace_python.ir.model import (
    BasicBlock,
    BinaryOp,
    BoolOp,
    Branch,
    Call,
    Compare,
    Constant,
    ForNext,
    FunctionIR,
    Instruction,
    Jump,
    Phi,
    Symbol,
    UnaryOp,
    Value,
)
from coretrace_python.ir.ssa import SSAAnalysis

INF = float("inf")


def _format(bound: float) -> str:
    if bound in (INF, -INF):
        return "inf" if bound > 0 else "-inf"
    return str(int(bound)) if float(bound).is_integer() else str(bound)


@dataclass(frozen=True)
class Interval:
    """A closed range of numbers; ``inf`` bounds mean unbounded."""

    low: float
    high: float

    def join(self, other: Interval) -> Interval:
        return Interval(min(self.low, other.low), max(self.high, other.high))

    def widen(self, other: Interval) -> Interval:
        """``self`` extended to ``other``, jumping to infinity on any side that grew."""

        return Interval(
            self.low if other.low >= self.low else -INF,
            self.high if other.high <= self.high else INF,
        )

    def __str__(self) -> str:
        return f"[{_format(self.low)}, {_format(self.high)}]"


UNBOUNDED = Interval(-INF, INF)
NON_NEGATIVE = Interval(0, INF)

_NUMERIC_CALLS: Mapping[str, Interval] = {
    "python.builtins.int": UNBOUNDED,
    "python.builtins.float": UNBOUNDED,
    "python.builtins.round": UNBOUNDED,
    "python.builtins.len": NON_NEGATIVE,
    "python.builtins.abs": NON_NEGATIVE,
    "python.builtins.ord": Interval(0, 0x10FFFF),
}
_HULL_CALLS = frozenset({"python.builtins.min", "python.builtins.max"})

State = Mapping[Value, Interval]


def _times(a: float, b: float) -> float:
    return 0.0 if a == 0 or b == 0 else a * b


class RangeFacts:
    def __init__(self, states: Mapping[BlockId, State]) -> None:
        self._states: Mapping[BlockId, State] = MappingProxyType(
            {block: MappingProxyType(dict(state)) for block, state in states.items()}
        )

    def at(self, block: BlockId) -> State:
        """The intervals known at the end of ``block``; empty when it is unreachable."""

        return self._states.get(block, MappingProxyType({}))


class _RangeProblem(DataflowProblem[State]):
    direction: ClassVar[Direction] = Direction.FORWARD

    def __init__(self, function: FunctionIR) -> None:
        self.function = function
        self.blocks = {block.id: block for block in function.blocks}
        self.defs: dict[Value, Instruction] = {
            i.result: i for block in function.blocks for i in block.instructions if i.result
        }
        self._widened: dict[Value, Interval] = {}

    def initial(self) -> State:
        return MappingProxyType({})

    def join(self, a: State, b: State) -> State:
        return MappingProxyType(
            {value: a[value].join(b[value]) for value in a if value in b}
        )

    def evaluate(self, block: BasicBlock, incoming: Mapping[BlockId, State]) -> State:
        states = list(incoming.values())
        state: dict[Value, Interval] = dict(states[0]) if states else {}
        for other in states[1:]:
            state = dict(self.join(state, other))
        for instruction in block.instructions:
            if instruction.result is None:
                continue
            found = (
                self.phi(instruction, incoming)
                if isinstance(instruction, Phi)
                else self.instruction(instruction, state)
            )
            if found is None:
                state.pop(instruction.result, None)
            else:
                state[instruction.result] = found
        return MappingProxyType(state)

    def flow(self, cfg: CFG, block_id: BlockId, incoming: Mapping[BlockId, State]) -> Mapping[BlockId, State]:
        block = self.blocks[block_id]
        state = self.evaluate(block, incoming)
        exits = {target: state for target in block.exception_targets}
        terminator = block.terminator
        if isinstance(terminator, Branch):
            return {
                **exits,
                terminator.then_block: self.refined(state, terminator.condition, True),
                terminator.else_block: self.refined(state, terminator.condition, False),
            }
        if isinstance(terminator, Jump):
            return {**exits, terminator.target: state}
        if isinstance(terminator, ForNext):
            return {**exits, terminator.body: state, terminator.exit: state}
        return exits

    # ------------------------------------------------------------------ transfer

    def phi(self, phi: Phi, incoming: Mapping[BlockId, State]) -> Interval | None:
        result: Interval | None = None
        for value, predecessor in phi.incoming:
            if predecessor not in incoming:
                continue
            found = incoming[predecessor].get(value)
            if found is None:
                return None
            result = found if result is None else result.join(found)
        if result is None:
            return None
        previous = self._widened.get(phi.result)
        widened = result if previous is None else previous.widen(previous.join(result))
        self._widened[phi.result] = widened
        return widened

    def instruction(self, instruction: Instruction, state: Mapping[Value, Interval]) -> Interval | None:
        if isinstance(instruction, Constant):
            value = instruction.value
            if isinstance(value, bool | int | float) and value == value:  # noqa: PLR0124 - NaN
                return Interval(float(value), float(value))
            return None
        if isinstance(instruction, BinaryOp):
            left, right = state.get(instruction.left), state.get(instruction.right)
            if left is None or right is None:
                return None
            return self.binary(instruction.operator, left, right)
        if isinstance(instruction, UnaryOp):
            operand = state.get(instruction.operand)
            if instruction.operator == "not":
                return Interval(0, 1)
            if operand is None:
                return None
            if instruction.operator == "neg":
                return Interval(-operand.high, -operand.low)
            return operand if instruction.operator == "pos" else UNBOUNDED
        if isinstance(instruction, Compare):
            return Interval(0, 1)
        if isinstance(instruction, Call):
            callee = self.defs.get(instruction.callee)
            if not isinstance(callee, Symbol):
                return None
            name = callee.symbol_id.canonical_name
            if name in _NUMERIC_CALLS:
                return _NUMERIC_CALLS[name]
            if name in _HULL_CALLS and instruction.arguments and not instruction.keywords:
                hull: Interval | None = None
                for argument in instruction.arguments:
                    found = state.get(argument)
                    if found is None:
                        return None
                    hull = found if hull is None else hull.join(found)
                return hull
        return None

    @staticmethod
    def binary(operator: str, left: Interval, right: Interval) -> Interval | None:
        if operator == "add":
            return Interval(left.low + right.low, left.high + right.high)
        if operator == "sub":
            return Interval(left.low - right.high, left.high - right.low)
        if operator == "mul":
            products = [
                _times(a, b) for a in (left.low, left.high) for b in (right.low, right.high)
            ]
            return Interval(min(products), max(products))
        if operator in ("div", "floor_div", "mod", "pow", "bit_or", "bit_xor", "bit_and", "lshift", "rshift"):
            return UNBOUNDED
        return None

    # ------------------------------------------------------------------ refinement

    def refined(self, state: State, condition: Value, truth: bool) -> State:
        overrides: dict[Value, Interval] = {}
        self.refine(dict(state), condition, truth, overrides)
        return MappingProxyType({**state, **overrides}) if overrides else state

    def refine(
        self, state: dict[Value, Interval], condition: Value, truth: bool, overrides: dict[Value, Interval]
    ) -> None:
        definition = self.defs.get(condition)
        if isinstance(definition, UnaryOp) and definition.operator == "not":
            self.refine(state, definition.operand, not truth, overrides)
        elif isinstance(definition, BoolOp) and (definition.operator == "and") == truth:
            for value in definition.values:
                self.refine(state, value, truth, overrides)
        elif isinstance(definition, Compare):
            left, right = definition.left, definition.right
            if left not in state or right not in state:
                return
            operator = definition.operator
            if operator == "eq" and truth or operator == "not_eq" and not truth:
                low = max(state[left].low, state[right].low)
                high = min(state[left].high, state[right].high)
                if low <= high:
                    overrides[left] = overrides[right] = Interval(low, high)
                    state[left] = state[right] = Interval(low, high)
                return
            if operator not in ("lt", "lt_eq", "gt", "gt_eq"):
                return
            ascending = (operator in ("lt", "lt_eq")) == truth
            lower, upper = (left, right) if ascending else (right, left)
            bounded_lower = Interval(state[lower].low, min(state[lower].high, state[upper].high))
            bounded_upper = Interval(max(state[upper].low, state[lower].low), state[upper].high)
            overrides[lower], overrides[upper] = bounded_lower, bounded_upper
            state[lower], state[upper] = bounded_lower, bounded_upper


def analyze_ranges(function: FunctionIR, cfg: CFG) -> RangeFacts:
    problem = _RangeProblem(function)
    solution = solve(problem, cfg)
    states: dict[BlockId, State] = {}
    for block in function.blocks:
        if solution.reached(block.id):
            states[block.id] = problem.evaluate(block, solution.incoming(block.id))
    return RangeFacts(states)


class RangeAnalysis(FunctionAnalysis[RangeFacts]):
    name: ClassVar[str] = "abstract.ranges"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({SSAAnalysis, CFGAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> RangeFacts:
        return analyze_ranges(ctx.get(SSAAnalysis, function), ctx.get(CFGAnalysis, function))
