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
from coretrace_python.interprocedural import (
    CallGraph,
    CallGraphAnalysis,
    ExternalSymbol,
    FunctionSummary,
    KnownFunction,
    ProjectSummaries,
    SummaryAnalysis,
    SummaryIndex,
    SummaryTable,
)
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
from coretrace_python.semantic.scopes import ScopeAnalysis, ScopeTable
from coretrace_python.semantic.symbols import SymbolAnalysis, SymbolTable
from coretrace_python.source import SourceSpan
from coretrace_python.taint.models import (
    EntryPoint,
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
    """``location`` is the call in the analysed function; when the sink is reached
    inside a known callee, ``through`` names it and ``sink_location`` points at the sink."""

    source: Source
    sink: Sink
    kinds: TaintKind
    argument: Value
    location: SourceSpan
    through: str | None = None
    sink_location: SourceSpan | None = None


class TaintFacts:
    def __init__(self, taints: Mapping[Value, Taint], flows: tuple[TaintFlow, ...]) -> None:
        self._taints = MappingProxyType(dict(taints))
        self.flows = flows

    def taint(self, value: Value) -> Taint:
        return self._taints.get(value, Taint.none())


State = Mapping[Value, Taint]


class _TaintProblem(DataflowProblem[State]):
    direction: ClassVar[Direction] = Direction.FORWARD

    def __init__(
        self,
        name: str,
        function: FunctionIR,
        models: ModelTable,
        graph: CallGraph,
        summaries: SummaryTable,
        entry: EntryPoint | None = None,
        project: SummaryIndex | None = None,
    ) -> None:
        self.name = name
        self.function = function
        self.models = models
        self.graph = graph
        self.summaries = summaries
        self.entry = entry
        self.project = project or SummaryIndex()
        self.blocks = {block.id: block for block in function.blocks}
        self.symbols = graph.symbols(name)

    def initial(self) -> State:
        if self.entry is None:
            return MappingProxyType({})
        source = Source(self.entry.symbol, self.entry.label, self.entry.kinds)
        seed = Taint(self.entry.kinds, frozenset({source}))
        return MappingProxyType({p: seed for p in self.function.parameters})

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
        taint = Taint.none()
        symbol = self.symbols.get(instruction.result) if instruction.result else None
        if symbol is not None:
            source = self.models.source_covering(symbol)
            if source is not None:
                taint = Taint(source.kinds, frozenset({source}))
        if isinstance(instruction, Symbol | Compare):
            return taint
        for operand in instruction.operands():
            taint = taint.join(state.get(operand, Taint.none()))
        return taint

    def call(self, call: Call, state: Mapping[Value, Taint], flows: list[TaintFlow]) -> Taint:
        arguments = tuple(state.get(a, Taint.none()) for a in call.arguments)
        keywords = Taint.none()
        for _, value in call.keywords:
            keywords = keywords.join(state.get(value, Taint.none()))
        everything = keywords
        for taint in arguments:
            everything = everything.join(taint)

        target = self.graph.target_at(self.name, call.location)
        if isinstance(target, ExternalSymbol):
            project = self.project.summary(target.symbol)
            if project is not None:
                through = target.symbol.canonical_name.removeprefix("python.")
                return self.known(project, through, arguments, keywords, everything, call, flows)
            sink = self.models.sink(target.symbol)
            if sink is not None:
                for argument in call.argument_values():
                    self.report(flows, sink, state.get(argument, Taint.none()), argument, call, None, None)
            sanitizer = self.models.sanitizer(target.symbol)
            if sanitizer is not None:
                return everything.without(sanitizer.kinds)
            # A method on a tainted object returns tainted data (``request.args.get``).
            everything = everything.join(state.get(call.callee, Taint.none()))
            source = self.models.source_covering(target.symbol)
            if source is not None:
                return everything.join(Taint(source.kinds, frozenset({source})))
            return everything
        if isinstance(target, KnownFunction):
            summary = self.summaries.summary(target.name)
            return self.known(summary, target.name, arguments, keywords, everything, call, flows)
        return everything.join(state.get(call.callee, Taint.none()))

    def known(
        self,
        summary: FunctionSummary,
        through: str,
        arguments: tuple[Taint, ...],
        keywords: Taint,
        everything: Taint,
        call: Call,
        flows: list[TaintFlow],
    ) -> Taint:
        """Flows and result taint of a call to a function whose summary is known."""

        if summary.unsupported:
            return everything

        def mapped(deps: frozenset[int]) -> tuple[Taint, Value | None]:
            taint, witness = Taint.none(), None
            for index in sorted(deps):
                part = arguments[index] if index < len(arguments) else keywords
                if part and witness is None:
                    witness = call.arguments[index] if index < len(arguments) else call.keywords[0][1]
                taint = taint.join(part)
            return taint, witness

        for reached in summary.external_calls:
            sink = self.models.sink(reached.symbol)
            if sink is None:
                continue
            for deps in (*reached.argument_dependencies, reached.keyword_dependencies):
                taint, witness = mapped(deps)
                if witness is not None:
                    self.report(flows, sink, taint, witness, call, through, reached.location)
        result = mapped(summary.return_dependencies)[0]
        for symbol in sorted(summary.return_externals, key=str):
            returned_source = self.models.source(symbol)
            if returned_source is not None:
                result = result.join(Taint(returned_source.kinds, frozenset({returned_source})))
        return result

    @staticmethod
    def report(
        flows: list[TaintFlow],
        sink: Sink,
        taint: Taint,
        argument: Value,
        call: Call,
        through: str | None,
        sink_location: SourceSpan | None,
    ) -> None:
        reaching = taint.kinds & sink.kinds
        if not reaching:
            return
        for source in sorted(taint.sources, key=lambda s: str(s.symbol)):
            flows.append(
                TaintFlow(
                    source,
                    sink,
                    reaching,
                    argument,
                    call.location,
                    through,
                    call.location if sink_location is None else sink_location,
                )
            )


def entry_point_of(
    function: nodes.Function, models: ModelTable, scopes: ScopeTable, symbols: SymbolTable
) -> EntryPoint | None:
    """The entry-point model matching one of the function's decorators, if any."""

    scope = scopes.scope_for(function)
    enclosing = scope.parent if scope.parent is not None else scope.id
    for decorator in function.decorators:
        symbol = symbols.resolve_expression(enclosing, decorator)
        if symbol is not None:
            entry = models.entry_point(symbol)
            if entry is not None:
                return entry
    return None


def propagate_taint(
    name: str,
    function: FunctionIR,
    cfg: CFG,
    models: ModelTable,
    graph: CallGraph,
    summaries: SummaryTable,
    entry: EntryPoint | None = None,
    project: SummaryIndex | None = None,
) -> TaintFacts:
    problem = _TaintProblem(name, function, models, graph, summaries, entry, project)
    solution = solve(problem, cfg)
    taints: dict[Value, Taint] = {}
    flows: list[TaintFlow] = []
    for block in function.blocks:
        if solution.reached(block.id):
            state, found = problem.evaluate(block, solution.incoming(block.id))
            taints.update(state)
            flows.extend(found)
    return TaintFacts(taints, tuple(dict.fromkeys(flows)))


class TaintAnalysis(FunctionAnalysis[TaintFacts]):
    """Shared taint result every detector consumes."""

    name: ClassVar[str] = "taint.flows"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset(
        {
            SSAAnalysis,
            CFGAnalysis,
            SecurityModelAnalysis,
            CallGraphAnalysis,
            SummaryAnalysis,
            ScopeAnalysis,
            SymbolAnalysis,
            ProjectSummaries,
        }
    )

    @classmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> TaintFacts:
        graph = ctx.get(CallGraphAnalysis)
        models = ctx.get(SecurityModelAnalysis)
        return propagate_taint(
            graph.name_of(function),
            ctx.get(SSAAnalysis, function),
            ctx.get(CFGAnalysis, function),
            models,
            graph,
            ctx.get(SummaryAnalysis),
            entry_point_of(function, models, ctx.get(ScopeAnalysis), ctx.get(SymbolAnalysis)),
            ctx.get(ProjectSummaries),
        )
