"""Function summaries (architecture §19).

A summary says which parameters a function's return value depends on and which external
symbols its parameters reach, directly or through calls to other known functions. It is
computed as a dependence data-flow problem over the SSA form and iterated to a fixpoint
over the call graph, so recursion converges to the least solution. Summaries carry no
security knowledge: the taint engine decides which external symbols matter.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.analysis import Analysis, AnalysisContext, AnyAnalysis
from coretrace_python.cfg import CFG, BlockId, CFGAnalysis
from coretrace_python.dataflow import DataflowProblem, Direction, solve
from coretrace_python.interprocedural.callgraph import (
    CallGraph,
    CallGraphAnalysis,
    ExternalSymbol,
    KnownFunction,
    UnknownTarget,
)
from coretrace_python.ir.model import (
    BasicBlock,
    Branch,
    Call,
    Constant,
    ForNext,
    FunctionIR,
    Global,
    Instruction,
    Jump,
    Phi,
    Return,
    Symbol,
    Undefined,
    Value,
)
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceSpan

Dependencies = frozenset[int]
NONE: Dependencies = frozenset()


@dataclass(frozen=True)
class Dep:
    """What a value depends on: parameter indices and results of external symbols."""

    parameters: Dependencies = NONE
    externals: frozenset[SymbolId] = frozenset()

    def __or__(self, other: Dep) -> Dep:
        return Dep(self.parameters | other.parameters, self.externals | other.externals)


EMPTY = Dep()


@dataclass(frozen=True)
class ExternalCall:
    """An external symbol reached from this function; dependencies are parameter indices."""

    symbol: SymbolId
    argument_dependencies: tuple[Dependencies, ...]
    keyword_dependencies: Dependencies
    location: SourceSpan
    call_site: SourceSpan | None


@dataclass(frozen=True)
class FunctionSummary:
    name: str
    parameters: int
    return_dependencies: Dependencies
    external_calls: tuple[ExternalCall, ...]
    unsupported: bool = False
    return_externals: frozenset[SymbolId] = frozenset()


class SummaryTable:
    def __init__(self, summaries: Mapping[str, FunctionSummary]) -> None:
        self._summaries = MappingProxyType(dict(summaries))
        self.names = tuple(summaries)

    def summary(self, name: str) -> FunctionSummary:
        return self._summaries[name]


State = Mapping[Value, Dep]
_CallKey = tuple[SymbolId, SourceSpan, SourceSpan | None]


class _DependenceProblem(DataflowProblem[State]):
    direction: ClassVar[Direction] = Direction.FORWARD

    def __init__(
        self, name: str, function: FunctionIR, graph: CallGraph, table: Mapping[str, FunctionSummary]
    ) -> None:
        self.name = name
        self.function = function
        self.graph = graph
        self.table = table
        self.blocks = {block.id: block for block in function.blocks}
        self.external: dict[_CallKey, ExternalCall] = {}
        self.returns: Dep = EMPTY

    def initial(self) -> State:
        return MappingProxyType(
            {p: Dep(frozenset({i})) for i, p in enumerate(self.function.parameters)}
        )

    def join(self, a: State, b: State) -> State:
        merged = dict(a)
        for value, deps in b.items():
            merged[value] = merged[value] | deps if value in merged else deps
        return MappingProxyType(merged)

    def evaluate(self, block: BasicBlock, incoming: Mapping[BlockId, State]) -> State:
        states = list(incoming.values())
        state: dict[Value, Dep] = dict(states[0]) if states else {}
        for other in states[1:]:
            state = dict(self.join(state, other))
        for instruction in block.instructions:
            if instruction.result is None:
                continue
            if isinstance(instruction, Phi):
                deps = EMPTY
                for value, predecessor in instruction.incoming:
                    if predecessor in incoming:
                        deps |= incoming[predecessor].get(value, EMPTY)
            elif isinstance(instruction, Call):
                deps = self.call(instruction, state)
            else:
                deps = self.instruction(instruction, state)
            state[instruction.result] = deps
        terminator = block.terminator
        if isinstance(terminator, ForNext) and terminator.result is not None:
            state[terminator.result] = state.get(terminator.iterator, EMPTY)
        if isinstance(terminator, Return) and terminator.value is not None:
            self.returns |= state.get(terminator.value, EMPTY)
        return MappingProxyType(state)

    def flow(self, cfg: CFG, block_id: BlockId, incoming: Mapping[BlockId, State]) -> Mapping[BlockId, State]:
        block = self.blocks[block_id]
        state = self.evaluate(block, incoming)
        terminator = block.terminator
        if isinstance(terminator, Branch):
            return {terminator.then_block: state, terminator.else_block: state}
        if isinstance(terminator, Jump):
            return {terminator.target: state}
        if isinstance(terminator, ForNext):
            return {terminator.body: state, terminator.exit: state}
        return {}

    # ------------------------------------------------------------------ transfer

    @staticmethod
    def instruction(instruction: Instruction, state: Mapping[Value, Dep]) -> Dep:
        if isinstance(instruction, Constant | Global | Symbol | Undefined):
            return EMPTY
        deps = EMPTY
        for operand in instruction.operands():
            deps |= state.get(operand, EMPTY)
        return deps

    def call(self, call: Call, state: Mapping[Value, Dep]) -> Dep:
        arguments = tuple(state.get(a, EMPTY) for a in call.arguments)
        keywords = EMPTY
        for _, value in call.keywords:
            keywords |= state.get(value, EMPTY)
        everything = keywords
        for deps in arguments:
            everything |= deps
        target = self.graph.target_at(self.name, call.location)

        if isinstance(target, ExternalSymbol):
            self.record(
                target.symbol,
                tuple(a.parameters for a in arguments),
                keywords.parameters,
                call.location,
                None,
            )
            return everything | Dep(externals=frozenset({target.symbol}))
        if isinstance(target, KnownFunction):
            callee = self.table[target.name]
            if callee.unsupported:
                return everything

            def mapped(indices: Dependencies) -> Dep:
                result = EMPTY
                for index in indices:
                    result |= arguments[index] if index < len(arguments) else keywords
                return result

            for reached in callee.external_calls:
                self.record(
                    reached.symbol,
                    tuple(mapped(d).parameters for d in reached.argument_dependencies),
                    mapped(reached.keyword_dependencies).parameters,
                    reached.location,
                    call.location,
                )
            return mapped(callee.return_dependencies) | Dep(externals=callee.return_externals)
        assert isinstance(target, UnknownTarget)
        return everything | state.get(call.callee, EMPTY)

    def record(
        self,
        symbol: SymbolId,
        arguments: tuple[Dependencies, ...],
        keywords: Dependencies,
        location: SourceSpan,
        call_site: SourceSpan | None,
    ) -> None:
        key = (symbol, location, call_site)
        previous = self.external.get(key)
        if previous is not None:
            arguments = tuple(
                a | b for a, b in zip(previous.argument_dependencies, arguments, strict=False)
            )
            keywords |= previous.keyword_dependencies
        self.external[key] = ExternalCall(symbol, arguments, keywords, location, call_site)


def summarize(
    name: str, function: FunctionIR, cfg: CFG, graph: CallGraph, table: Mapping[str, FunctionSummary]
) -> FunctionSummary:
    problem = _DependenceProblem(name, function, graph, table)
    solution = solve(problem, cfg)
    problem.external = {}
    problem.returns = EMPTY
    for block in function.blocks:
        if solution.reached(block.id):
            problem.evaluate(block, solution.incoming(block.id))
    return FunctionSummary(
        name,
        len(function.parameters),
        problem.returns.parameters,
        tuple(problem.external.values()),
        return_externals=problem.returns.externals,
    )


class SummaryAnalysis(Analysis[SummaryTable]):
    name: ClassVar[str] = "interprocedural.summaries"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset(
        {CallGraphAnalysis, SSAAnalysis, CFGAnalysis}
    )

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> SummaryTable:
        graph = ctx.get(CallGraphAnalysis)
        table: dict[str, FunctionSummary] = {}
        supported: dict[str, tuple[FunctionIR, CFG]] = {}
        for name, function in graph.definitions.items():
            if name in graph.unsupported:
                count = len(function.parameters)
                table[name] = FunctionSummary(name, count, frozenset(range(count)), (), True)
            else:
                supported[name] = (ctx.get(SSAAnalysis, function), ctx.get(CFGAnalysis, function))
                table[name] = FunctionSummary(name, len(function.parameters), NONE, ())
        changed = True
        while changed:
            changed = False
            for name, (ssa, cfg) in supported.items():
                updated = summarize(name, ssa, cfg, graph, table)
                if updated != table[name]:
                    table[name] = updated
                    changed = True
        return SummaryTable(table)
