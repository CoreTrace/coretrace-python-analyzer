"""Lower parser-independent PyHIR into analysis-oriented PyIR, one CFG block at a time."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import ClassVar, NoReturn

from coretrace_python import cfg as control_flow
from coretrace_python.analysis import (
    Analysis,
    AnalysisContext,
    AnalysisManager,
    AnyAnalysis,
    FunctionAnalysis,
)
from coretrace_python.cfg import CFG, BlockId, CFGAnalysis
from coretrace_python.hir import nodes
from coretrace_python.hir.visitors import Node, children
from coretrace_python.ir.model import (
    Assert,
    Await,
    BasicBlock,
    BinaryOp,
    BoolOp,
    Branch,
    BuildDict,
    BuildList,
    BuildSet,
    BuildSlice,
    BuildString,
    BuildTuple,
    Call,
    Catch,
    Compare,
    Constant,
    DelAttr,
    DelItem,
    EffectInstruction,
    ForNext,
    FunctionIR,
    GetAttr,
    GetItem,
    GetIter,
    Global,
    Import,
    Instruction,
    Jump,
    LoadLocal,
    MakeClass,
    MakeFunction,
    ModuleIR,
    NonlocalResult,
    Raise,
    Return,
    SetAttr,
    SetGlobal,
    SetItem,
    SetNonlocal,
    StoreLocal,
    Symbol,
    Terminator,
    UnaryOp,
    Value,
    ValueInstruction,
    WithEnter,
    WithExit,
    Yield,
)
from coretrace_python.semantic import SEMANTIC_ANALYSES
from coretrace_python.semantic.scopes import (
    BindingKind,
    Resolution,
    ResolutionKind,
    Scope,
    ScopeAnalysis,
    ScopeKind,
    ScopeTable,
)
from coretrace_python.semantic.symbols import SymbolAnalysis, SymbolId, SymbolTable
from coretrace_python.source import SourceSpan


class LoweringError(Exception):
    """Raised when PyHIR uses constructs outside the current PyIR subset."""


@dataclass
class _FunctionLowerer:
    symbols: SymbolTable
    scopes: ScopeTable
    scope: Scope
    cfg: CFG
    next_value_id: int = 0
    parameters: dict[str, Value] = field(default_factory=dict)
    instructions: list[Instruction] = field(default_factory=list)
    iterators: dict[BlockId, Value] = field(default_factory=dict)
    contexts: dict[SourceSpan, Value] = field(default_factory=dict)

    def fail(
        self,
        node: nodes.Statement | nodes.Expression,
        message: str | None = None,
    ) -> NoReturn:
        detail = message or f"unsupported syntax: {type(node).__name__}"
        raise LoweringError(f"{node.span.display()}: {detail}")

    def new_value(self) -> Value:
        value = Value(self.next_value_id)
        self.next_value_id += 1
        return value

    def emit(self, instruction: ValueInstruction) -> Value:
        self.instructions.append(instruction)
        return instruction.result

    def emit_effect(self, instruction: EffectInstruction) -> None:
        self.instructions.append(instruction)

    def resolve(self, name: str) -> Resolution:
        if name in self.cfg.synthetic_locals:
            return Resolution(ResolutionKind.LOCAL, self.scope.id)
        return self.scopes.resolve(self.scope.id, name)

    # ------------------------------------------------------------------ expressions

    def imported_symbol(self, node: nodes.Expression) -> SymbolId | None:
        if isinstance(node, nodes.Name):
            return self.symbols.resolve(self.scope.id, node.identifier)
        if isinstance(node, nodes.Attribute):
            parent = self.imported_symbol(node.value)
            return parent.attribute(node.name) if parent is not None else None
        return None

    def expression(self, node: nodes.Expression) -> Value:
        imported_symbol = self.imported_symbol(node)
        if imported_symbol is not None:
            return self.emit(Symbol(self.new_value(), node.span, imported_symbol))
        if isinstance(node, nodes.Name):
            resolution = self.resolve(node.identifier)
            if resolution.kind is ResolutionKind.FREE:
                # A captured variable is an implicit parameter of the nested function; a
                # ``nonlocal`` one lives in a local slot initialised from it.
                if node.identifier in self.nonlocals:
                    return self.emit(LoadLocal(self.new_value(), node.span, node.identifier))
                if node.identifier in self.parameters:
                    return self.parameters[node.identifier]
                self.fail(node, "closures are not supported yet")
            if resolution.kind is not ResolutionKind.LOCAL:
                return self.emit(Global(self.new_value(), node.span, node.identifier))
            if node.identifier in self.parameters:
                return self.parameters[node.identifier]
            return self.emit(LoadLocal(self.new_value(), node.span, node.identifier))
        if isinstance(node, nodes.Constant):
            return self.emit(Constant(self.new_value(), node.span, node.value))
        if isinstance(node, nodes.BinaryOp):
            left = self.expression(node.left)
            right = self.expression(node.right)
            return self.emit(BinaryOp(self.new_value(), node.span, node.operator, left, right))
        if isinstance(node, nodes.UnaryOp):
            operand = self.expression(node.operand)
            return self.emit(UnaryOp(self.new_value(), node.span, node.operator, operand))
        if isinstance(node, nodes.Compare):
            left = self.expression(node.left)
            right = self.expression(node.right)
            return self.emit(Compare(self.new_value(), node.span, node.operator, left, right))
        if isinstance(node, nodes.Call):
            callee = self.expression(node.callee)
            arguments, starred = self.spread(node.arguments)
            keywords = tuple((k.name, self.expression(k.value)) for k in node.keywords)
            result = self.emit(Call(self.new_value(), node.span, callee, arguments, keywords, starred))
            self.write_back_nonlocals(node, result)
            return result
        if isinstance(node, nodes.BoolOp):
            values = tuple(self.expression(value) for value in node.values)
            return self.emit(BoolOp(self.new_value(), node.span, node.operator, values))
        if isinstance(node, nodes.List | nodes.Tuple):
            elements, unpacked = self.spread(node.elements)
            builder = BuildList if isinstance(node, nodes.List) else BuildTuple
            return self.emit(builder(self.new_value(), node.span, elements, unpacked))
        if isinstance(node, nodes.Dict):
            items = tuple((self.expression(k), self.expression(v)) for k, v in node.items if k is not None)
            unpacked = tuple(self.expression(v) for k, v in node.items if k is None)
            return self.emit(BuildDict(self.new_value(), node.span, items, unpacked))
        if isinstance(node, nodes.FormattedString):
            parts = tuple(self.expression(part) for part in node.parts)
            return self.emit(BuildString(self.new_value(), node.span, parts))
        if isinstance(node, nodes.Slice):
            bounds = [self.expression(b) if b is not None else None for b in (node.lower, node.upper, node.step)]
            return self.emit(BuildSlice(self.new_value(), node.span, bounds[0], bounds[1], bounds[2]))
        if isinstance(node, nodes.Starred):
            self.fail(node, "a starred expression is only supported in calls, lists and tuples")
        if isinstance(node, nodes.Set):
            elements, unpacked = self.spread(node.elements)
            return self.emit(BuildSet(self.new_value(), node.span, elements, unpacked))
        if isinstance(node, nodes.Lambda):
            synthesized = lambda_function(node)
            captured = tuple(self.captured_value(name, node.span) for name in captured_names(synthesized, self.scopes))
            return self.emit(MakeFunction(self.new_value(), node.span, synthesized.name, captured))
        if isinstance(node, nodes.Conditional | nodes.Comprehension):
            self.fail(node, "expression-level control flow must be laid out by the CFG builder")
        if isinstance(node, nodes.Await):
            return self.emit(Await(self.new_value(), node.span, self.expression(node.value)))
        if isinstance(node, nodes.Yield):
            value = self.expression(node.value) if node.value is not None else None
            return self.emit(Yield(self.new_value(), node.span, value))
        if isinstance(node, nodes.Attribute):
            object_value = self.expression(node.value)
            return self.emit(GetAttr(self.new_value(), node.span, object_value, node.name))
        if isinstance(node, nodes.Subscript):
            object_value = self.expression(node.value)
            key = self.expression(node.key)
            return self.emit(GetItem(self.new_value(), node.span, object_value, key))
        self.fail(node)

    def spread(self, elements: tuple[nodes.Expression, ...]) -> tuple[tuple[Value, ...], tuple[Value, ...]]:
        """Plain elements and ``*iterable`` elements of a display or an argument list."""

        plain: list[Value] = []
        unpacked: list[Value] = []
        for element in elements:
            if isinstance(element, nodes.Starred):
                unpacked.append(self.expression(element.value))
            else:
                plain.append(self.expression(element))
        return tuple(plain), tuple(unpacked)

    def write_back_nonlocals(self, node: nodes.Call, call: Value) -> None:
        """After a direct call to a nested function defined here, store what it left in
        each of its ``nonlocal`` names back into this function's variable."""

        if not isinstance(node.callee, nodes.Name):
            return
        nested = self.nested_defs.get(node.callee.identifier)
        if nested is None:
            return
        bindings = self.scopes.scope_for(nested).bindings
        for name in sorted(n for n, b in bindings.items() if b.kind is BindingKind.NONLOCAL):
            written = self.emit(NonlocalResult(self.new_value(), node.span, call, name))
            self.store(nodes.Name(name, node.span), written)

    # ------------------------------------------------------------------ statements

    def store(self, target: nodes.Target, value: Value) -> None:
        if isinstance(target, nodes.Name):
            resolution = self.resolve(target.identifier)
            if resolution.kind is ResolutionKind.GLOBAL:
                self.emit_effect(SetGlobal(None, target.span, target.identifier, value))
                return
            if resolution.kind is not ResolutionKind.LOCAL and target.identifier not in self.nonlocals:
                self.fail(target, "assignment to a free variable that is not declared nonlocal")
            self.emit_effect(StoreLocal(None, target.span, target.identifier, value))
            if target.identifier in self.nonlocals:
                self.emit_effect(SetNonlocal(None, target.span, target.identifier, value))
        elif isinstance(target, nodes.Attribute):
            object_value = self.expression(target.value)
            self.emit_effect(SetAttr(None, target.span, object_value, target.name, value))
        elif isinstance(target, nodes.Subscript):
            object_value = self.expression(target.value)
            key = self.expression(target.key)
            self.emit_effect(SetItem(None, target.span, object_value, key, value))
        else:
            self.unpack(target, value)

    def unpack(self, target: nodes.Tuple, value: Value) -> None:
        """Store each element of ``value`` into the targets; a starred target receives
        the slice the others leave, and the targets after it index from the end."""

        count = len(target.elements)
        starred = next((i for i, e in enumerate(target.elements) if isinstance(e, nodes.Starred)), None)
        for index, element in enumerate(target.elements):
            if isinstance(element, nodes.Starred):
                lower = self.emit(Constant(self.new_value(), element.span, index))
                upper = None
                if index < count - 1:
                    upper = self.emit(Constant(self.new_value(), element.span, index - count + 1))
                bounds = self.emit(BuildSlice(self.new_value(), element.span, lower, upper, None))
                item = self.emit(GetItem(self.new_value(), element.span, value, bounds))
                element = element.value
            else:
                offset = index if starred is None or index < starred else index - count
                position = self.emit(Constant(self.new_value(), element.span, offset))
                item = self.emit(GetItem(self.new_value(), element.span, value, position))
            assert isinstance(element, nodes.Name | nodes.Attribute | nodes.Subscript | nodes.Tuple)
            self.store(element, item)

    def statement(self, node: nodes.Statement) -> None:
        if isinstance(node, nodes.Assign):
            self.store(node.target, self.expression(node.value))
            return
        if isinstance(node, nodes.Declaration):
            return
        if isinstance(node, nodes.Class):
            # A local class is a value bound to its name; bases and decorators run here,
            # its methods are analysed as nested functions.
            for decorator in node.decorators:
                self.expression(decorator)
            for base in node.bases:
                self.expression(base)
            for keyword in node.keywords:
                self.expression(keyword.value)
            made_class = self.emit(MakeClass(self.new_value(), node.span, node.name))
            self.store(nodes.Name(node.name, node.span), made_class)
            return
        if isinstance(node, nodes.Delete):
            for target in node.targets:
                if isinstance(target, nodes.Subscript):
                    obj, key = self.expression(target.value), self.expression(target.key)
                    self.emit_effect(DelItem(None, target.span, obj, key))
                elif isinstance(target, nodes.Attribute):
                    self.emit_effect(DelAttr(None, target.span, self.expression(target.value), target.name))
                # ``del name`` unbinds a local; the SSA form has no slot to clear.
            return
        if isinstance(node, nodes.Function):
            # A nested definition is a value bound to its name; its body is its own
            # scope and is not lowered here.
            for decorator in node.decorators:
                self.expression(decorator)
            for parameter in node.parameters:
                if parameter.default is not None:
                    self.expression(parameter.default)
            captured = tuple(self.captured_value(name, node.span) for name in captured_names(node, self.scopes))
            made = self.emit(MakeFunction(self.new_value(), node.span, node.name, captured))
            self.store(nodes.Name(node.name, node.span), made)
            self.nested_defs[node.name] = node
            return
        if isinstance(node, nodes.AugAssign):
            current = self.expression(node.target)
            operand = self.expression(node.value)
            result = self.emit(BinaryOp(self.new_value(), node.span, node.operator, current, operand))
            self.store(node.target, result)
            return
        if isinstance(node, nodes.Assert):
            test = self.expression(node.test)
            message = self.expression(node.message) if node.message is not None else None
            self.emit_effect(Assert(None, node.span, test, message))
            return
        if isinstance(node, nodes.EnterWith):
            context = self.expression(node.item.context)
            self.contexts[node.item.span] = context
            entered = self.emit(WithEnter(self.new_value(), node.item.span, context))
            if node.item.target is not None:
                self.store(node.item.target, entered)
            return
        if isinstance(node, nodes.ExitWith):
            self.emit_effect(WithExit(None, node.item.span, self.contexts[node.item.span]))
            return
        if isinstance(node, nodes.EnterHandler):
            handler = node.handler
            caught_type = self.expression(handler.type) if handler.type is not None else None
            caught = self.emit(Catch(self.new_value(), handler.span, caught_type))
            if handler.name is not None:
                self.store(nodes.Name(handler.name, handler.span), caught)
            return
        if isinstance(node, nodes.ExpressionStatement):
            self.expression(node.expression)
            return
        if isinstance(node, nodes.Import | nodes.ImportFrom):
            # The binding is already applied by the semantic analyses; the instruction
            # records that the import runs here (§39 rule 3).
            module = "." * node.level + (node.module or "") if isinstance(node, nodes.ImportFrom) else ""
            for alias in node.names:
                bound = alias.as_name or alias.name.partition(".")[0]
                symbol = self.symbols.resolve(self.scope.id, bound)
                if symbol is None:
                    self.fail(node, f"unresolved import of {bound!r}")
                written = alias.name if isinstance(node, nodes.Import) else module
                self.emit_effect(Import(None, alias.span, written, symbol, bound))
            return
        if isinstance(node, nodes.Pass | nodes.Global | nodes.Nonlocal):
            # Declarations are already applied by the semantic analyses.
            return
        self.fail(node)

    # ------------------------------------------------------------------ blocks

    def terminator(self, block: control_flow.BasicBlock) -> Terminator:
        terminator = block.terminator
        if isinstance(terminator, control_flow.Return):
            value = self.expression(terminator.value) if terminator.value is not None else None
            return Return(terminator.span, value)
        if isinstance(terminator, control_flow.Branch):
            condition = self.expression(terminator.condition)
            return Branch(terminator.span, condition, terminator.then_block, terminator.else_block)
        if isinstance(terminator, control_flow.Raise):
            exception = (
                self.expression(terminator.exception) if terminator.exception is not None else None
            )
            cause = self.expression(terminator.cause) if terminator.cause is not None else None
            return Raise(terminator.span, exception, cause)
        if isinstance(terminator, control_flow.Jump):
            self.enter_loop(block.id, terminator.target)
            return Jump(terminator.span, terminator.target)
        target = terminator.target
        if self.resolve(target.identifier).kind is not ResolutionKind.LOCAL:
            self.fail(target, "assignment to a global or nonlocal name is not supported yet")
        return ForNext(
            terminator.span,
            self.iterators[block.id],
            target.identifier,
            terminator.body,
            terminator.exit,
        )

    def enter_loop(self, source: BlockId, target: BlockId) -> None:
        """Take the iterator of a ``for`` loop in the block that enters its header."""

        header = self.cfg.block(target).terminator
        if isinstance(header, control_flow.ForEach) and (source, target) not in self.cfg.back_edges():
            iterable = self.expression(header.iterable)
            self.iterators[target] = self.emit(GetIter(self.new_value(), header.span, iterable))

    def captured_value(self, name: str, span: SourceSpan) -> Value:
        """The current value of a variable a nested function captures."""

        return self.expression(nodes.Name(name, span))

    def function(self, node: nodes.Function) -> FunctionIR:
        captured = captured_names(node, self.scopes)
        parameter_values = tuple(self.new_value() for _ in (*node.parameters, *captured))
        reassigned = _reassigned_parameters(node)
        self.parameters = {
            parameter.name: value
            for parameter, value in zip(node.parameters, parameter_values, strict=False)
            if parameter.name not in reassigned
        }
        # Captured variables come after the explicit parameters. A ``nonlocal`` one is
        # assigned in this body, so it lives in a local slot initialised from the
        # captured value; the others are never reassigned.
        bindings = self.scopes.scope_for(node).bindings
        # Nested definitions bound in this body, so a direct call to one can write its
        # ``nonlocal`` names back into this function's variables.
        self.nested_defs: dict[str, nodes.Function] = {}
        self.nonlocals = frozenset(
            name for name in captured if name in bindings and bindings[name].kind is BindingKind.NONLOCAL
        )
        captured_values = dict(zip(captured, parameter_values[len(node.parameters) :], strict=True))
        self.parameters.update({n: v for n, v in captured_values.items() if n not in self.nonlocals})
        blocks: list[BasicBlock] = []
        for cfg_block in self.cfg.blocks.values():
            self.instructions = []
            if cfg_block.id == self.cfg.entry:
                # Reassigned parameters live in locals so every block reads the same slot.
                for parameter, value in zip(node.parameters, parameter_values, strict=False):
                    if parameter.name in reassigned:
                        self.emit_effect(StoreLocal(None, parameter.span, parameter.name, value))
                for name in sorted(self.nonlocals):
                    self.emit_effect(StoreLocal(None, node.span, name, captured_values[name]))
            for statement in cfg_block.statements:
                self.statement(statement)
            terminator = self.terminator(cfg_block)
            blocks.append(
                BasicBlock(
                    cfg_block.id, tuple(self.instructions), terminator, cfg_block.exception_targets
                )
            )
        return FunctionIR(
            qualified_name(self.scopes, node),
            parameter_values,
            self.cfg.entry,
            tuple(blocks),
            node.span,
        )


def qualified_name(scopes: ScopeTable, function: nodes.Function) -> str:
    """``Class.method`` for methods, ``outer.inner`` for nested functions, the bare name
    for module-level functions; lambda and comprehension scopes keep identifier names."""

    names = [function.name]
    scope = scopes.scope_for(function)
    parent = scopes.scope(scope.parent) if scope.parent else None
    while parent is not None and parent.kind is not ScopeKind.MODULE:
        names.append(parent.name.strip("<>"))
        parent = scopes.scope(parent.parent) if parent.parent else None
    return ".".join(reversed(names))


def lambda_function(node: nodes.Lambda) -> nodes.Function:
    """A lambda as a function named after its position, returning its body."""

    return nodes.Function(
        f"lambda_{node.span.start_line}_{node.span.start_column}",
        node.parameters,
        (nodes.Return(node.body, node.span),),
        False,
        node.span,
    )


def captured_names(function: nodes.Function, scopes: ScopeTable) -> tuple[str, ...]:
    """The enclosing-function variables ``function`` reads, sorted: its implicit
    parameters after the explicit ones."""

    scope = scopes.scope_for(function)
    names: set[str] = set()

    def walk(node: Node) -> None:
        if isinstance(node, nodes.Name):
            names.add(node.identifier)
        for child in children(node):
            walk(child)

    for statement in function.body:
        walk(statement)
    for parameter in function.parameters:
        if parameter.default is not None:
            walk(parameter.default)
    return tuple(sorted(n for n in names if scopes.resolve(scope.id, n).kind is ResolutionKind.FREE))


def _reassigned_parameters(function: nodes.Function) -> frozenset[str]:
    """Parameters that the function body assigns to, outside nested scopes."""

    assigned: set[str] = set()

    def names(target: nodes.Target | nodes.Starred | None) -> None:
        if isinstance(target, nodes.Name):
            assigned.add(target.identifier)
        elif isinstance(target, nodes.Starred):
            names(target.value)  # type: ignore[arg-type]
        elif isinstance(target, nodes.Tuple):
            for element in target.elements:
                names(element)  # type: ignore[arg-type]

    def walk(node: Node) -> None:
        if isinstance(node, nodes.Assign | nodes.AugAssign | nodes.For | nodes.WithItem):
            names(node.target)
        elif isinstance(node, nodes.ExceptHandler) and node.name is not None:
            assigned.add(node.name)
        if isinstance(node, nodes.Function | nodes.Class | nodes.Comprehension | nodes.Lambda):
            return
        for child in children(node):
            walk(child)

    for statement in function.body:
        walk(statement)
    return frozenset(assigned & {parameter.name for parameter in function.parameters})


class PyIRAnalysis(FunctionAnalysis[FunctionIR]):
    """Lower one function to PyIR on demand, following its control-flow graph."""

    name: ClassVar[str] = "ir.pyir"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset(
        {ScopeAnalysis, SymbolAnalysis, CFGAnalysis}
    )

    @classmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> FunctionIR:
        scopes = ctx.get(ScopeAnalysis)
        lowerer = _FunctionLowerer(
            ctx.get(SymbolAnalysis),
            scopes,
            scopes.scope_for(function),
            ctx.get(CFGAnalysis, function),
        )
        return lowerer.function(function)


_FUNCTIONS_CACHE: OrderedDict[int, tuple[nodes.Module, tuple[nodes.Function, ...]]] = OrderedDict()
_FUNCTIONS_CACHE_SIZE = 32


def analyzable_functions(module: nodes.Module) -> tuple[nodes.Function, ...]:
    """Top-level functions, the methods of top-level classes, and the functions and
    lambdas nested inside them, in source order. Computed once per module: the result is
    memoised for the last few modules seen, keyed by identity, so every consumer shares
    one tuple and the synthesized lambda functions it holds."""

    cached = _FUNCTIONS_CACHE.get(id(module))
    if cached is not None and cached[0] is module:
        _FUNCTIONS_CACHE.move_to_end(id(module))
        return cached[1]
    functions = _analyzable_functions(module)
    _FUNCTIONS_CACHE[id(module)] = (module, functions)
    while len(_FUNCTIONS_CACHE) > _FUNCTIONS_CACHE_SIZE:
        _FUNCTIONS_CACHE.popitem(last=False)
    return functions


def _analyzable_functions(module: nodes.Module) -> tuple[nodes.Function, ...]:
    functions: list[nodes.Function] = []
    for statement in module.body:
        if isinstance(statement, nodes.Function):
            _collect(statement, functions)
        elif isinstance(statement, nodes.Class):
            for member in statement.body:
                if isinstance(member, nodes.Function):
                    _collect(member, functions)
    return tuple(functions)


def _collect(function: nodes.Function, into: list[nodes.Function]) -> None:
    into.append(function)

    def walk(node: Node) -> None:
        if isinstance(node, nodes.Function):
            _collect(node, into)
            return
        if isinstance(node, nodes.Lambda):
            _collect(lambda_function(node), into)
            return
        if isinstance(node, nodes.Class):
            # The methods of a class defined inside a function are nested functions.
            for member in node.body:
                if isinstance(member, nodes.Function):
                    _collect(member, into)
            return
        for child in children(node):
            walk(child)

    for statement in function.body:
        walk(statement)


class ModuleIRAnalysis(Analysis[ModuleIR]):
    """Assemble the PyIR of every top-level function of the module."""

    name: ClassVar[str] = "ir.module"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({PyIRAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> ModuleIR:
        return ModuleIR(
            tuple(ctx.get(PyIRAnalysis, function) for function in analyzable_functions(ctx.module))
        )


def lower_module(module: nodes.Module, *, ssa: bool = False) -> ModuleIR:
    """Lower a whole module through a fresh analysis manager, optionally to SSA form."""

    manager = AnalysisManager(module)
    manager.register(*SEMANTIC_ANALYSES, CFGAnalysis, PyIRAnalysis, ModuleIRAnalysis)
    if not ssa:
        return manager.get(ModuleIRAnalysis)
    # Imported here because the SSA pass is built on top of this module's analyses.
    from coretrace_python.cfg.dominance import DominanceAnalysis
    from coretrace_python.ir.ssa import SSAAnalysis

    manager.register(DominanceAnalysis, SSAAnalysis)
    return ModuleIR(
        tuple(manager.get(SSAAnalysis, function) for function in analyzable_functions(module))
    )
