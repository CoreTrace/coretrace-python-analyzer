"""The global taint engine (architecture §17).

One forward data-flow problem over the SSA form of a function. Values defined by a
source symbol carry the source's taint kinds; arithmetic, attribute and item access,
iteration, phis and calls propagate the union of their operands' taint; sanitizer
calls clear their kinds; comparisons and literals carry nothing. Every tainted
argument reaching a sink whose kinds it still carries is reported as a ``TaintFlow``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.abstract import (
    ATTRIBUTES,
    ELEMENTS,
    HeapAnalysis,
    HeapFacts,
    HeapLocation,
    mutated_by,
)
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
    project_symbol,
)
from coretrace_python.ir.lowering import analyzable_functions
from coretrace_python.ir.model import (
    BasicBlock,
    Branch,
    BuildDict,
    BuildList,
    BuildSet,
    BuildTuple,
    Call,
    Compare,
    ForNext,
    FunctionIR,
    GetAttr,
    GetItem,
    GetIter,
    Global,
    Instruction,
    Jump,
    MakeFunction,
    Phi,
    SetAttr,
    SetItem,
    Symbol,
    Value,
)
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.semantic.scopes import ScopeAnalysis, ScopeTable
from coretrace_python.semantic.symbols import SymbolAnalysis, SymbolId, SymbolTable
from coretrace_python.source import SourceSpan
from coretrace_python.taint.models import (
    EntryPoint,
    ModelTable,
    SecurityModelAnalysis,
    Sink,
    Source,
    TaintKind,
)
from coretrace_python.taint.routes import RegisteredRoutes, Routes


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


Key = Value | HeapLocation


class TaintFacts:
    def __init__(self, taints: Mapping[Key, Taint], flows: tuple[TaintFlow, ...]) -> None:
        self._taints = MappingProxyType(dict(taints))
        self.flows = flows

    def taint(self, value: Value) -> Taint:
        return self._taints.get(value, Taint.none())

    def heap(self, location: HeapLocation) -> Taint:
        """The taint stored in one field of one abstract object (§22)."""

        return self._taints.get(location, Taint.none())


State = Mapping[Key, Taint]


class _TaintProblem(DataflowProblem[State]):
    direction: ClassVar[Direction] = Direction.FORWARD

    def __init__(
        self,
        name: str,
        function: FunctionIR,
        models: ModelTable,
        graph: CallGraph,
        summaries: SummaryTable,
        parameters: Mapping[int, Source] | None = None,
        project: SummaryIndex | None = None,
        heap: HeapFacts | None = None,
        seeds: Mapping[HeapLocation, Taint] | None = None,
    ) -> None:
        self.name = name
        self.function = function
        self.models = models
        self.graph = graph
        self.summaries = summaries
        self.parameters = parameters or {}
        self.project = project or SummaryIndex()
        self.heap = heap or HeapFacts({})
        self.seeds = dict(seeds or {})
        self.blocks = {block.id: block for block in function.blocks}
        self.defs: dict[Value, Instruction] = {
            i.result: i for block in function.blocks for i in block.instructions if i.result
        }
        self.symbols = graph.symbols(name)

    # ------------------------------------------------------------------ heap

    def deep(self, value: Value, state: Mapping[Key, Taint]) -> Taint:
        """The taint of a value and of the contents of the objects it points to."""

        taint = state.get(value, Taint.none())
        for field in (ELEMENTS, ATTRIBUTES):
            for location in self.heap.locations(value, field):
                taint = taint.join(state.get(location, Taint.none()))
        return taint

    def store(self, state: dict[Key, Taint], receiver: Value, field: str, taint: Taint) -> None:
        for location in self.heap.locations(receiver, field):
            state[location] = state.get(location, Taint.none()).join(taint)

    def loaded(self, instruction: GetAttr | GetItem | GetIter, state: Mapping[Key, Taint]) -> Taint:
        if isinstance(instruction, GetAttr):
            receiver, field = instruction.object, ATTRIBUTES
        elif isinstance(instruction, GetItem):
            receiver, field = instruction.object, ELEMENTS
        else:
            receiver, field = instruction.iterable, ELEMENTS
        taint = Taint.none()
        for location in self.heap.locations(receiver, field):
            taint = taint.join(state.get(location, Taint.none()))
        return taint

    def initial(self) -> State:
        state: dict[Key, Taint] = {
            self.function.parameters[index]: Taint(source.kinds, frozenset({source}))
            for index, source in self.parameters.items()
            if index < len(self.function.parameters)
        }
        for location, taint in self.seeds.items():
            state[location] = taint
        return MappingProxyType(state)

    def join(self, a: State, b: State) -> State:
        merged = dict(a)
        for value, taint in b.items():
            merged[value] = merged[value].join(taint) if value in merged else taint
        return MappingProxyType(merged)

    def evaluate(
        self, block: BasicBlock, incoming: Mapping[BlockId, State]
    ) -> tuple[State, list[TaintFlow]]:
        states = list(incoming.values())
        state: dict[Key, Taint] = dict(states[0]) if states else {}
        for other in states[1:]:
            state = dict(self.join(state, other))
        flows: list[TaintFlow] = []
        for instruction in block.instructions:
            if isinstance(instruction, SetAttr):
                self.store(state, instruction.object, ATTRIBUTES, state.get(instruction.value, Taint.none()))
            elif isinstance(instruction, SetItem):
                self.store(state, instruction.object, ELEMENTS, state.get(instruction.value, Taint.none()))
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
                if isinstance(instruction, GetAttr | GetItem | GetIter):
                    taint = taint.join(self.loaded(instruction, state))
            state[instruction.result] = taint
        terminator = block.terminator
        if isinstance(terminator, ForNext) and terminator.result is not None:
            state[terminator.result] = self.deep(terminator.iterator, state)
        return MappingProxyType(state), flows

    def flow(self, cfg: CFG, block_id: BlockId, incoming: Mapping[BlockId, State]) -> Mapping[BlockId, State]:
        block = self.blocks[block_id]
        state, _ = self.evaluate(block, incoming)
        exits = {target: state for target in block.exception_targets}
        terminator = block.terminator
        if isinstance(terminator, Branch):
            return {**exits, terminator.then_block: state, terminator.else_block: state}
        if isinstance(terminator, Jump):
            return {**exits, terminator.target: state}
        if isinstance(terminator, ForNext):
            return {**exits, terminator.body: state, terminator.exit: state}
        return exits

    # ------------------------------------------------------------------ transfer

    def instruction(self, instruction: Instruction, state: Mapping[Key, Taint]) -> Taint:
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
        if isinstance(instruction, BuildList | BuildTuple | BuildDict | BuildSet):
            # ``[*xs]`` and ``{**d}`` copy the contents of what they unpack.
            for unpacked in instruction.unpacked:
                taint = taint.join(self.deep(unpacked, state))
        return taint

    def call(self, call: Call, state: dict[Key, Taint], flows: list[TaintFlow]) -> Taint:
        arguments = tuple(self.deep(a, state) for a in call.arguments)
        keywords = Taint.none()
        for value in (*call.starred, *(v for _, v in call.keywords)):
            keywords = keywords.join(self.deep(value, state))
        everything = keywords
        for taint in arguments:
            everything = everything.join(taint)
        receiver = mutated_by(call, self.defs)
        if receiver is not None:
            self.store(state, receiver, ELEMENTS, everything)

        target = self.graph.target_at(self.name, call.location)
        if isinstance(target, ExternalSymbol):
            project = self.project.summary(target.symbol)
            if project is None:
                # ``App(x)`` with ``App`` defined in another file: its ``__init__``.
                project = self.project.summary(target.symbol.attribute("__init__"))
            if project is not None:
                through = target.symbol.canonical_name.removeprefix("python.")
                bound = self.receiver(call, project.name)
                arguments = (*(self.deep(r, state) for r in bound), *arguments)
                return self.known(
                    project, through, arguments, keywords, everything, call, flows, state, (), bound
                )
            symbol = target.symbol
            if not self.modelled(symbol):
                # ``get_conn().execute`` derived ``app.database.get_conn.execute``; what
                # the project function returns says what ``execute`` really is.
                symbol = self.returned_symbol(call) or symbol
            return self.external(symbol, everything, call, state, flows)
        if isinstance(target, KnownFunction):
            summary = self.summaries.summary(target.name)
            captured = self.captured(call)
            bound = self.receiver(call, target.name)
            arguments = (
                *(self.deep(r, state) for r in bound),
                *arguments,
                *(self.deep(value, state) for value in captured),
            )
            return self.known(
                summary, target.name, arguments, keywords, everything, call, flows, state, captured, bound
            )
        returned = self.returned_symbol(call)
        if returned is not None:
            return self.external(returned, everything, call, state, flows)
        return everything.join(state.get(call.callee, Taint.none()))

    def receiver(self, call: Call, name: str) -> tuple[Value, ...]:
        """The object a method call runs on, its implicit first parameter: the receiver
        of ``obj.method(...)``, or the new object of ``Class(...)``."""

        if "." not in name:
            return ()
        callee = self.defs.get(call.callee)
        if isinstance(callee, GetAttr):
            return (callee.object,)
        if name.endswith(".__init__") and isinstance(callee, Global | Symbol):
            return (call.result,)
        return ()

    def captured(self, call: Call) -> tuple[Value, ...]:
        """The values a nested callee captured, its implicit trailing parameters."""

        made = self.defs.get(call.callee)
        return made.captured if isinstance(made, MakeFunction) else ()

    def modelled(self, symbol: SymbolId) -> bool:
        return (
            self.models.sink(symbol) is not None
            or self.models.sanitizer(symbol) is not None
            or self.models.source_covering(symbol) is not None
        )

    def external(
        self, symbol: SymbolId, everything: Taint, call: Call, state: Mapping[Key, Taint], flows: list[TaintFlow]
    ) -> Taint:
        """Sinks, sanitizers and sources of a call to an external symbol."""

        sink = self.models.sink(symbol)
        if sink is not None:
            for position, argument in enumerate(call.arguments):
                self.report(flows, sink, self.deep(argument, state), argument, call, None, None, position)
            for argument in (*call.starred, *(value for _, value in call.keywords)):
                self.report(flows, sink, self.deep(argument, state), argument, call, None, None, None)
        sanitizer = self.models.sanitizer(symbol)
        if sanitizer is not None:
            return everything.without(sanitizer.kinds)
        # A method on a tainted object returns tainted data (``request.args.get``).
        everything = everything.join(state.get(call.callee, Taint.none()))
        source = self.models.source_covering(symbol)
        if source is not None:
            return everything.join(Taint(source.kinds, frozenset({source})))
        return everything

    def returned_symbol(self, call: Call) -> SymbolId | None:
        """``get_db().execute(...)``: the method of what a known function returns, when
        its summary says the return value is one external symbol."""

        callee = self.defs.get(call.callee)
        if not isinstance(callee, GetAttr):
            return None
        origin = self.defs.get(callee.object)
        if not isinstance(origin, Call):
            return None
        target = self.graph.target_at(self.name, origin.location)
        summary: FunctionSummary | None = None
        if isinstance(target, KnownFunction):
            summary = self.summaries.summary(target.name)
        elif isinstance(target, ExternalSymbol):
            summary = self.project.summary(target.symbol)
        if summary is None:
            return None
        # ``getattr(g, "_database", None) or sqlite3.connect(...)``: among the symbols the
        # function may return, the one the models know about is the one that matters.
        for returned in sorted(summary.return_externals, key=str):
            candidate = returned.attribute(callee.attribute)
            if self.modelled(candidate):
                return candidate
        return None

    def known(
        self,
        summary: FunctionSummary,
        through: str,
        arguments: tuple[Taint, ...],
        keywords: Taint,
        everything: Taint,
        call: Call,
        flows: list[TaintFlow],
        state: dict[Key, Taint],
        captured: tuple[Value, ...] = (),
        receiver: tuple[Value, ...] = (),
    ) -> Taint:
        """Flows and result taint of a call to a function whose summary is known."""

        if summary.unsupported:
            return everything

        spread = (*call.starred, *(value for _, value in call.keywords))
        values = (*receiver, *call.arguments, *captured)

        def mapped(deps: frozenset[int]) -> tuple[Taint, Value | None]:
            taint, witness = Taint.none(), None
            for index in sorted(deps):
                positional = index < len(arguments)
                part = arguments[index] if positional else keywords
                if part and witness is None and (positional or spread):
                    witness = values[index] if positional else spread[0]
                taint = taint.join(part)
            return taint, witness

        for reached in summary.external_calls:
            sink = self.models.sink(reached.symbol)
            if sink is None:
                continue
            positions: list[int | None] = [*range(len(reached.argument_dependencies)), None]
            for position, deps in zip(positions, (*reached.argument_dependencies, reached.keyword_dependencies), strict=True):
                taint, witness = mapped(deps)
                if witness is not None:
                    self.report(flows, sink, taint, witness, call, through, reached.location, position)
        for mutation in summary.mutations:
            if mutation.parameter < len(values):
                stored = mapped(mutation.dependencies)[0]
                for symbol in sorted(mutation.externals, key=str):
                    stored_source = self.models.source(symbol)
                    if stored_source is not None:
                        stored = stored.join(Taint(stored_source.kinds, frozenset({stored_source})))
                self.store(state, values[mutation.parameter], mutation.field, stored)
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
        position: int | None = None,
    ) -> None:
        reaching = taint.kinds & sink.kinds_at(position)
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


Instances = Mapping[str, tuple[SymbolId, ...]]


def factory_instances(
    module: nodes.Module,
    scopes: ScopeTable,
    symbols: SymbolTable,
    summaries: SummaryTable,
    project: SummaryIndex,
) -> Instances:
    """Module-level names bound to the result of a project function whose summary
    returns known symbols: ``app = create_app()`` is a ``flask.Flask`` like
    ``app = Flask(__name__)``, so its decorators resolve."""

    found: dict[str, tuple[SymbolId, ...]] = {}
    module_scope = scopes.module_scope.id
    for statement in module.body:
        if isinstance(statement, nodes.Function) and statement.decorators:
            # ``@click.group() def cli``: the function is what its decorator returns, so
            # ``@cli.command()`` resolves to ``click.group.command``.
            decorated = tuple(
                s
                for d in statement.decorators
                if (s := symbols.resolve_expression(module_scope, d)) is not None
            )
            if decorated:
                found[statement.name] = decorated
            continue
        if not (
            isinstance(statement, nodes.Assign)
            and isinstance(statement.target, nodes.Name)
            and isinstance(statement.value, nodes.Call)
        ):
            continue
        callee = statement.value.callee
        externals: frozenset[SymbolId] = frozenset()
        if isinstance(callee, nodes.Name) and callee.identifier in summaries.names:
            externals = summaries.summary(callee.identifier).return_externals
        else:
            symbol = symbols.resolve_expression(module_scope, callee)
            summary = project.summary(symbol) if symbol is not None else None
            if summary is not None:
                externals = summary.return_externals
        if externals:
            found[statement.target.identifier] = tuple(sorted(externals, key=str))
    return found


def local_instances(function: nodes.Function, scopes: ScopeTable, symbols: SymbolTable) -> Instances:
    """Locals of ``function`` bound to the result of calling a resolvable symbol."""

    scope = scopes.scope_for(function).id
    found: dict[str, tuple[SymbolId, ...]] = {}
    for statement in function.body:
        if (
            isinstance(statement, nodes.Assign)
            and isinstance(statement.target, nodes.Name)
            and isinstance(statement.value, nodes.Call)
        ):
            symbol = symbols.resolve_expression(scope, statement.value.callee)
            if symbol is not None:
                found[statement.target.identifier] = (symbol,)
    return found


def _enclosing(module: nodes.Module, function: nodes.Function) -> nodes.Function | None:
    """The function whose body defines ``function``, if it is nested."""

    def search(body: tuple[nodes.Statement, ...], parent: nodes.Function | None) -> nodes.Function | None:
        for statement in body:
            if isinstance(statement, nodes.Function):
                if statement.span == function.span:
                    return parent
                found = search(statement.body, statement)
                if found is not None:
                    return found
            elif isinstance(statement, nodes.Class):
                found = search(statement.body, None)
                if found is not None:
                    return found
        return None

    found = search(module.body, None)
    if found is not None:
        return found
    # Lambdas are synthesized functions: their enclosing function is the innermost
    # analysable function whose span contains theirs.
    innermost: nodes.Function | None = None
    for candidate in analyzable_functions(module):
        if candidate.span != function.span and _contains(candidate.span, function.span):
            innermost = candidate
    return innermost


def _contains(outer: SourceSpan, inner: SourceSpan) -> bool:
    if outer.source_id != inner.source_id or outer.end_line is None or inner.end_line is None:
        return False
    return (outer.start_line, outer.start_column) <= (inner.start_line, inner.start_column) and (
        inner.end_line,
        inner.end_column,
    ) <= (outer.end_line, outer.end_column)


def _instance_symbols(expression: nodes.Expression, instances: Instances) -> tuple[SymbolId, ...]:
    """The symbols an expression rooted at a factory instance may denote."""

    if isinstance(expression, nodes.Name):
        return instances.get(expression.identifier, ())
    if isinstance(expression, nodes.Attribute):
        return tuple(s.attribute(expression.name) for s in _instance_symbols(expression.value, instances))
    if isinstance(expression, nodes.Call):
        return _instance_symbols(expression.callee, instances)
    return ()


def entry_point_of(
    function: nodes.Function,
    models: ModelTable,
    scopes: ScopeTable,
    symbols: SymbolTable,
    owner: nodes.Class | None = None,
    instances: Instances | None = None,
) -> EntryPoint | None:
    """The entry-point model matching one of the function's decorators or, for a
    method, one of the bases of ``owner``, if any."""

    scope = scopes.scope_for(function)
    enclosing = scope.parent if scope.parent is not None else scope.id
    candidates = list(function.decorators)
    if owner is not None:
        class_scope = scopes.scope_for(owner)
        outside = class_scope.parent if class_scope.parent is not None else class_scope.id
        candidates.extend(owner.bases)
        enclosing_of = {id(base): outside for base in owner.bases}
    else:
        enclosing_of = {}
    for expression in candidates:
        symbol = symbols.resolve_expression(enclosing_of.get(id(expression), enclosing), expression)
        # ``app = create_app()`` resolves to the factory's symbol; the instance symbols
        # say what the factory returns.
        found = (*((symbol,) if symbol is not None else ()), *_instance_symbols(expression, instances or {}))
        for candidate in found:
            entry = models.entry_point(candidate)
            if entry is not None:
                return entry
    return None


def parameter_sources(
    function: nodes.Function,
    module: nodes.Module,
    models: ModelTable,
    scopes: ScopeTable,
    symbols: SymbolTable,
    instances: Instances | None = None,
    routes: Routes | None = None,
) -> Mapping[int, Source]:
    """The attacker-controlled parameters of ``function``, by index: every parameter of an
    entry point (``self`` excepted for a method), including one registered elsewhere
    (``routes``), and every parameter annotated with a typed-parameter symbol."""

    owner = next(
        (s for s in module.body if isinstance(s, nodes.Class) and any(f is function for f in s.body)),
        None,
    )
    sources: dict[int, Source] = {}
    enclosing_function = _enclosing(module, function)
    if enclosing_function is not None:
        # ``app = Flask(__name__)`` inside ``create_app``: routes defined there resolve.
        instances = {**(instances or {}), **local_instances(enclosing_function, scopes, symbols)}
    entry = entry_point_of(function, models, scopes, symbols, owner, instances)
    if entry is None and routes:
        qualified = function.name if owner is None else f"{owner.name}.{function.name}"
        entry = routes.get(project_symbol(module.name, qualified))
        if entry is None and owner is not None:
            entry = routes.get(project_symbol(module.name, owner.name))
    if entry is not None:
        first = 1 if owner is not None else 0
        for index in range(first, len(function.parameters)):
            sources[index] = Source(entry.symbol, entry.label, entry.kinds)
    scope = scopes.scope_for(function)
    enclosing = scope.parent if scope.parent is not None else scope.id
    for index, parameter in enumerate(function.parameters):
        if parameter.annotation is None:
            continue
        symbol = symbols.resolve_expression(enclosing, parameter.annotation)
        typed = models.typed_parameter(symbol) if symbol is not None else None
        if typed is not None:
            sources[index] = Source(typed.symbol, typed.label, typed.kinds)
    for index, parameter in enumerate(function.parameters):
        if index in sources:
            continue
        for named in models.named_parameters:
            if named.matches(parameter.name):
                sources[index] = Source(
                    SymbolId(f"python.parameter.{parameter.name}"), named.label, named.kinds
                )
                break
    return sources


def propagate_taint(
    name: str,
    function: FunctionIR,
    cfg: CFG,
    models: ModelTable,
    graph: CallGraph,
    summaries: SummaryTable,
    parameters: Mapping[int, Source] | None = None,
    project: SummaryIndex | None = None,
    heap: HeapFacts | None = None,
    seeds: Mapping[HeapLocation, Taint] | None = None,
) -> TaintFacts:
    problem = _TaintProblem(name, function, models, graph, summaries, parameters, project, heap, seeds)
    solution = solve(problem, cfg)
    taints: dict[Key, Taint] = {}
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
            HeapAnalysis,
            RegisteredRoutes,
        }
    )

    @classmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> TaintFacts:
        graph = ctx.get(CallGraphAnalysis)
        models = ctx.get(SecurityModelAnalysis)
        scopes, symbols = ctx.get(ScopeAnalysis), ctx.get(SymbolAnalysis)
        instances = factory_instances(ctx.module, scopes, symbols, ctx.get(SummaryAnalysis), ctx.get(ProjectSummaries))
        routes = ctx.get(RegisteredRoutes)

        def sources_of(member: nodes.Function) -> Mapping[int, Source]:
            return parameter_sources(member, ctx.module, models, scopes, symbols, instances, routes)

        ssa = ctx.get(SSAAnalysis, function)
        heap = ctx.get(HeapAnalysis, function)
        sources = sources_of(function)
        # Only a method the framework calls, an entry point, starts with what its
        # siblings stored; a method the project calls gets its ``self`` from the caller.
        seeds = (
            self_seeds(function, ctx.module, ssa, heap, models, graph, ctx.get(SummaryAnalysis), sources_of)
            if sources
            else {}
        )
        return propagate_taint(
            graph.name_of(function),
            ssa,
            ctx.get(CFGAnalysis, function),
            models,
            graph,
            ctx.get(SummaryAnalysis),
            sources,
            ctx.get(ProjectSummaries),
            heap,
            seeds,
        )


def self_seeds(
    function: nodes.Function,
    module: nodes.Module,
    ssa: FunctionIR,
    heap: HeapFacts,
    models: ModelTable,
    graph: CallGraph,
    summaries: SummaryTable,
    sources_of: Callable[[nodes.Function], Mapping[int, Source]],
) -> dict[HeapLocation, Taint]:
    """What the sibling methods of a method store into ``self`` from their own inputs:
    the attributes ``self`` starts with when the framework, not the project, calls the
    methods (``self.cmd = request.POST[...]`` in ``post``, read by ``get``)."""

    owner = next(
        (s for s in module.body if isinstance(s, nodes.Class) and any(m is function for m in s.body)),
        None,
    )
    if owner is None or not ssa.parameters:
        return {}
    seeds: dict[HeapLocation, Taint] = {}
    for sibling in owner.body:
        if not isinstance(sibling, nodes.Function) or sibling is function:
            continue
        try:
            summary = summaries.summary(graph.name_of(sibling))
        except KeyError:
            continue
        sources = sources_of(sibling)
        for mutation in summary.mutations:
            if mutation.parameter != 0:
                continue
            taint = Taint.none()
            for index in mutation.dependencies:
                source = sources.get(index)
                if source is not None:
                    taint = taint.join(Taint(source.kinds, frozenset({source})))
            for symbol in mutation.externals:
                external = models.source(symbol)
                if external is not None:
                    taint = taint.join(Taint(external.kinds, frozenset({external})))
            if not taint:
                continue
            for location in heap.locations(ssa.parameters[0], mutation.field):
                seeds[location] = seeds.get(location, Taint.none()).join(taint)
    return seeds
