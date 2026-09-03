"""The global taint engine (architecture §17).

One forward data-flow problem over the SSA form of a function. Values defined by a
source symbol carry the source's taint kinds; arithmetic, attribute and item access,
iteration, phis and calls propagate the union of their operands' taint; sanitizer
calls clear their kinds; comparisons and literals carry nothing. Every tainted
argument reaching a sink whose kinds it still carries is reported as a ``TaintFlow``.
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
    Branch,
    Call,
    Compare,
    ForNext,
    FunctionIR,
    Instruction,
    Jump,
    Phi,
    Symbol,
    Value,
)
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceSpan
from coretrace_python.taint.models import (
    ModelTable,
    SecurityModelAnalysis,
    Sink,
    Source,
    TaintKind,
)


@dataclass(frozen=True)
class Taint:
    kinds: TaintKind
    sources: frozenset[Source]

    @classmethod
    def none(cls) -> Taint:
        return cls(TaintKind.NONE, frozenset())

    def __bool__(self) -> bool:
        return self.kinds is not TaintKind.NONE and bool(self.kinds)

    def join(self, other: Taint) -> Taint:
        return Taint(self.kinds | other.kinds, self.sources | other.sources)

    def without(self, kinds: TaintKind) -> Taint:
        remaining = self.kinds & ~kinds
        return Taint(remaining, self.sources if remaining else frozenset())


@dataclass(frozen=True)
class TaintFlow:
    source: Source
    sink: Sink
    kinds: TaintKind
    argument: Value
    location: SourceSpan


class TaintFacts:
    def __init__(self, taints: Mapping[Value, Taint], flows: tuple[TaintFlow, ...]) -> None:
        self._taints = MappingProxyType(dict(taints))
        self.flows = flows

    def taint(self, value: Value) -> Taint:
        return self._taints.get(value, Taint.none())


State = Mapping[Value, Taint]


class _TaintProblem(DataflowProblem[State]):
    direction: ClassVar[Direction] = Direction.FORWARD

    def __init__(self, function: FunctionIR, models: ModelTable) -> None:
        self.function = function
        self.models = models
        self.blocks = {block.id: block for block in function.blocks}
        self.symbols: dict[Value, SymbolId] = {
            i.result: i.symbol_id
            for block in function.blocks
            for i in block.instructions
            if isinstance(i, Symbol)
        }

    def initial(self) -> State:
        return MappingProxyType({})

    def join(self, a: State, b: State) -> State:
        merged = dict(a)
        for value, taint in b.items():
            merged[value] = merged[value].join(taint) if value in merged else taint
        return MappingProxyType(merged)

    def evaluate(
        self, block: BasicBlock, incoming: Mapping[BlockId, State]
    ) -> tuple[State, list[TaintFlow]]:
        states = list(incoming.values())
        state: dict[Value, Taint] = dict(states[0]) if states else {}
        for other in states[1:]:
            state = dict(self.join(state, other))
        flows: list[TaintFlow] = []
        for instruction in block.instructions:
            if instruction.result is None:
                continue
            if isinstance(instruction, Phi):
                taint = Taint.none()
                for value, predecessor in instruction.incoming:
                    if predecessor in incoming:
                        taint = taint.join(incoming[predecessor].get(value, Taint.none()))
            elif isinstance(instruction, Call):
                taint = self.call(instruction, state, flows)
            else:
                taint = self.instruction(instruction, state)
            state[instruction.result] = taint
        terminator = block.terminator
        if isinstance(terminator, ForNext) and terminator.result is not None:
            state[terminator.result] = state.get(terminator.iterator, Taint.none())
        return MappingProxyType(state), flows

    def flow(self, cfg: CFG, block_id: BlockId, incoming: Mapping[BlockId, State]) -> Mapping[BlockId, State]:
        block = self.blocks[block_id]
        state, _ = self.evaluate(block, incoming)
        terminator = block.terminator
        if isinstance(terminator, Branch):
            return {terminator.then_block: state, terminator.else_block: state}
        if isinstance(terminator, Jump):
            return {terminator.target: state}
        if isinstance(terminator, ForNext):
            return {terminator.body: state, terminator.exit: state}
        return {}

    # ------------------------------------------------------------------ transfer

    def instruction(self, instruction: Instruction, state: Mapping[Value, Taint]) -> Taint:
        if isinstance(instruction, Symbol):
            source = self.models.source(instruction.symbol_id)
            return Taint(source.kinds, frozenset({source})) if source else Taint.none()
        if isinstance(instruction, Compare):
            return Taint.none()
        taint = Taint.none()
        for operand in instruction.operands():
            taint = taint.join(state.get(operand, Taint.none()))
        return taint

    def call(self, call: Call, state: Mapping[Value, Taint], flows: list[TaintFlow]) -> Taint:
        symbol = self.symbols.get(call.callee)
        arguments = Taint.none()
        for argument in call.argument_values():
            arguments = arguments.join(state.get(argument, Taint.none()))
        if symbol is not None:
            sink = self.models.sink(symbol)
            if sink is not None:
                for argument in call.argument_values():
                    taint = state.get(argument, Taint.none())
                    reaching = taint.kinds & sink.kinds
                    if reaching:
                        for source in sorted(taint.sources, key=lambda s: str(s.symbol)):
                            flows.append(TaintFlow(source, sink, reaching, argument, call.location))
            sanitizer = self.models.sanitizer(symbol)
            if sanitizer is not None:
                return arguments.without(sanitizer.kinds)
            called_source = self.models.source(symbol)
            if called_source is not None:
                return arguments.join(Taint(called_source.kinds, frozenset({called_source})))
        return arguments.join(state.get(call.callee, Taint.none()))


def propagate_taint(function: FunctionIR, cfg: CFG, models: ModelTable) -> TaintFacts:
    problem = _TaintProblem(function, models)
    solution = solve(problem, cfg)
    taints: dict[Value, Taint] = {}
    flows: list[TaintFlow] = []
    for block in function.blocks:
        if solution.reached(block.id):
            state, found = problem.evaluate(block, solution.incoming(block.id))
            taints.update(state)
            flows.extend(found)
    return TaintFacts(taints, tuple(flows))


class TaintAnalysis(FunctionAnalysis[TaintFacts]):
    """Shared taint result every detector consumes."""

    name: ClassVar[str] = "taint.flows"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset(
        {SSAAnalysis, CFGAnalysis, SecurityModelAnalysis}
    )

    @classmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> TaintFacts:
        return propagate_taint(
            ctx.get(SSAAnalysis, function),
            ctx.get(CFGAnalysis, function),
            ctx.get(SecurityModelAnalysis),
        )
