"""Intra-module call graph (architecture §20).

Every call site of every analysable function resolves, through the SSA form, to a
``KnownFunction`` defined at module level, an ``ExternalSymbol`` reached through imports
or builtins, or ``UnknownTarget`` (parameters, attributes, methods) until type inference
and framework models narrow it down.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.analysis import Analysis, AnalysisContext, AnyAnalysis
from coretrace_python.cfg import CFGError
from coretrace_python.hir import nodes
from coretrace_python.ir.lowering import (
    MODULE_BODY,
    LoweringError,
    analyzable_functions,
    qualified_name,
)
from coretrace_python.ir.model import (
    Await,
    Call,
    Constant,
    FunctionIR,
    GetAttr,
    GetItem,
    Global,
    Instruction,
    MakeFunction,
    Symbol,
    Value,
    WithEnter,
)
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.semantic.scopes import BindingKind, ScopeAnalysis, ScopeTable
from coretrace_python.semantic.symbols import SymbolAnalysis, SymbolId, SymbolTable
from coretrace_python.source import SourceSpan


@dataclass(frozen=True)
class KnownFunction:
    name: str


@dataclass(frozen=True)
class ExternalSymbol:
    symbol: SymbolId


@dataclass(frozen=True)
class UnknownTarget:
    pass


Target = KnownFunction | ExternalSymbol | UnknownTarget


@dataclass(frozen=True)
class Arguments:
    """What the arguments of a call denote: a symbol's canonical name
    (``python.yaml.FullLoader``), a constant as Python writes it (``True``, ``'/static'``),
    or None for anything else (a parameter, an expression). ``unpacked`` says the call
    unpacks ``*args`` or ``**kwargs``, so an argument it does not give explicitly may
    still be given; after ``*args`` no position is known, and ``positional`` is empty."""

    positional: tuple[str | None, ...] = ()
    keywords: tuple[tuple[str, str | None], ...] = ()
    unpacked: bool = False

    def given(self, keyword: str | None, position: int | None = None) -> tuple[bool, str | None] | None:
        """Whether the call gives an argument, by ``keyword`` or at ``position``, and what it
        denotes: ``(True, value)`` when given, ``(False, None)`` when surely absent, None
        when the call cannot tell because it unpacks arguments."""

        for name, value in self.keywords:
            if name == keyword:
                return True, value
        if position is not None and position < len(self.positional):
            return True, self.positional[position]
        return None if self.unpacked else (False, None)


@dataclass(frozen=True)
class CallSite:
    caller: str
    location: SourceSpan
    target: Target
    arguments: Arguments = field(default_factory=Arguments)


@dataclass(frozen=True)
class ModuleFunction:
    """One function of a module as a project plugin sees it: the name the call graph
    gives it (``Class.method``, ``outer.inner``, ``<module>``), where it is, and the label
    of the entry point it is (``http`` for a route, ``argv`` for a command), if any."""

    name: str
    span: SourceSpan
    entry_point: str | None = None


class CallGraph:
    def __init__(
        self,
        definitions: Mapping[str, nodes.Function],
        sites: Mapping[str, tuple[CallSite, ...]],
        unsupported: frozenset[str],
        symbols: Mapping[str, Mapping[Value, SymbolId]] | None = None,
    ) -> None:
        self._symbols = {name: MappingProxyType(dict(found)) for name, found in (symbols or {}).items()}
        self.definitions: Mapping[str, nodes.Function] = MappingProxyType(dict(definitions))
        # A graph rebuilt from cached call sites has sites but no definitions.
        self.functions = tuple(dict.fromkeys((*definitions, *sites)))
        self._names = {function.span: name for name, function in definitions.items()}
        self.unsupported = unsupported
        self._sites = MappingProxyType(dict(sites))
        self._at = {(site.caller, site.location): site for found in sites.values() for site in found}
        callers: dict[str, set[str]] = {name: set() for name in definitions}
        for found in sites.values():
            for site in found:
                if isinstance(site.target, KnownFunction):
                    callers.setdefault(site.target.name, set()).add(site.caller)
        self._callers = {name: frozenset(found) for name, found in callers.items()}

    def name_of(self, function: nodes.Function) -> str:
        return self._names[function.span]

    def symbols(self, name: str) -> Mapping[Value, SymbolId]:
        """Values of ``name`` that denote a symbol, including derived call-chain symbols."""

        return self._symbols.get(name, MappingProxyType({}))

    def sites(self, caller: str) -> tuple[CallSite, ...]:
        return self._sites.get(caller, ())

    def target_at(self, caller: str, location: SourceSpan) -> Target:
        site = self._at.get((caller, location))
        return site.target if site is not None else UnknownTarget()

    def arguments_at(self, caller: str, location: SourceSpan) -> Arguments:
        """What the arguments of the call at ``location`` in ``caller`` denote."""

        site = self._at.get((caller, location))
        return site.arguments if site is not None else Arguments()

    def callees(self, caller: str) -> frozenset[str]:
        return frozenset(
            site.target.name for site in self.sites(caller) if isinstance(site.target, KnownFunction)
        )

    def callers(self, name: str) -> frozenset[str]:
        return self._callers.get(name, frozenset())


def derive_symbols(
    function: FunctionIR, initial: Mapping[Value, SymbolId] | None = None
) -> dict[Value, SymbolId]:
    """Symbols of values: ``Symbol`` results, attributes and items of symbol values,
    results of calling a symbol (``sqlite3.connect(p)`` denotes ``python.sqlite3.connect``)
    and the values a ``with`` on such a result binds. Known functions derive nothing;
    parameters only through ``initial``, their annotated classes."""

    symbols: dict[Value, SymbolId] = dict(initial or {})
    changed = True
    while changed:
        changed = False
        for block in function.blocks:
            for instruction in block.instructions:
                if instruction.result is None or instruction.result in symbols:
                    continue
                symbol: SymbolId | None = None
                if isinstance(instruction, Symbol):
                    symbol = instruction.symbol_id
                elif isinstance(instruction, GetAttr) and instruction.object in symbols:
                    symbol = symbols[instruction.object].attribute(instruction.attribute)
                elif isinstance(instruction, GetItem) and instruction.object in symbols:
                    # An item of a symbol-denoted container (``request.files['f']``)
                    # carries the container's symbol, so its methods resolve.
                    symbol = symbols[instruction.object]
                elif isinstance(instruction, Call | WithEnter):
                    origin = (
                        instruction.callee if isinstance(instruction, Call) else instruction.context
                    )
                    symbol = symbols.get(origin)
                elif isinstance(instruction, Await) and instruction.value in symbols:
                    # ``await asyncpg.connect()`` denotes what the awaited call denotes.
                    symbol = symbols[instruction.value]
                if symbol is not None:
                    symbols[instruction.result] = symbol
                    changed = True
    return symbols


# Conditions name short constants (``True``, ``None``, a mode); a log message or a query
# passed as an argument is not recorded, so call sites stay small in the cache.
MAX_CONSTANT_LENGTH = 64


def _arguments(call: Call, symbols: Mapping[Value, SymbolId], defs: Mapping[Value, Instruction]) -> Arguments:
    def denoted(value: Value) -> str | None:
        symbol = symbols.get(value)
        if symbol is not None:
            return str(symbol)
        made = defs.get(value)
        if not isinstance(made, Constant):
            return None
        written = repr(made.value)
        return written if len(written) <= MAX_CONSTANT_LENGTH else None

    return Arguments(
        () if call.starred else tuple(denoted(value) for value in call.arguments),
        tuple((name, denoted(value)) for name, value in call.keywords if name is not None),
        bool(call.starred) or any(name is None for name, _ in call.keywords),
    )


def resolve_targets(
    function: FunctionIR,
    scopes: ScopeTable,
    known: frozenset[str],
    parameters: Mapping[Value, SymbolId] | None = None,
    nested: frozenset[str] = frozenset(),
    classes: Mapping[str, frozenset[str]] | None = None,
    owner: str | None = None,
    typed: Mapping[Value, str] | None = None,
    bases: Mapping[str, SymbolId] | None = None,
) -> tuple[dict[Value, Target], dict[Value, SymbolId]]:
    """Map every callee value of ``function`` to its target, and every symbol value.
    ``nested`` names the functions defined inside this one (``outer.inner``);
    ``classes`` maps the module's classes to their methods, ``owner`` is the class of a
    method and ``typed`` the parameters annotated with a module class. ``App(x)`` is a
    call to ``App.__init__``, ``app.run()`` and ``self.run()`` calls to ``App.run``.
    ``bases`` maps a module class to the symbol of its base: an attribute the class does
    not define is inherited, so ``self.get_argument`` in a ``RequestHandler`` subclass
    denotes ``tornado.web.RequestHandler.get_argument``."""

    module = scopes.module_scope
    classes = classes or {}
    instance_of: dict[Value, str] = dict(typed or {})
    if owner is not None and function.parameters:
        instance_of[function.parameters[0]] = owner
    defs = {i.result: i for block in function.blocks for i in block.instructions if i.result}
    for block in function.blocks:
        for instruction in block.instructions:
            if isinstance(instruction, Call):
                callee = defs.get(instruction.callee)
                if isinstance(callee, Global) and callee.name in classes:
                    instance_of[instruction.result] = callee.name
    inherited: dict[Value, SymbolId] = dict(parameters or {})
    for block in function.blocks:
        for instruction in block.instructions:
            if isinstance(instruction, GetAttr) and instruction.object in instance_of:
                if instruction.object in inherited:
                    continue  # an annotated parameter denotes its own class
                class_name = instance_of[instruction.object]
                base = (bases or {}).get(class_name)
                if base is not None and instruction.attribute not in classes.get(class_name, ()):
                    inherited[instruction.result] = base.attribute(instruction.attribute)
    symbols = derive_symbols(function, inherited)
    targets: dict[Value, Target] = {
        value: ExternalSymbol(symbol) for value, symbol in symbols.items()
    }
    for block in function.blocks:
        for instruction in block.instructions:
            if isinstance(instruction, MakeFunction):
                # A lambda or def made by the module body is named without a prefix, as
                # its scope's parent is the module.
                qualified = instruction.name if function.name == MODULE_BODY else f"{function.name}.{instruction.name}"
                if qualified in nested:
                    targets[instruction.result] = KnownFunction(qualified)
            elif isinstance(instruction, Global):
                binding = module.bindings.get(instruction.name)
                if binding is None:
                    continue
                if binding.kind is BindingKind.FUNCTION and instruction.name in known:
                    targets[instruction.result] = KnownFunction(instruction.name)
                elif binding.kind is BindingKind.CLASS and "__init__" in classes.get(instruction.name, ()):
                    targets[instruction.result] = KnownFunction(f"{instruction.name}.__init__")
            elif isinstance(instruction, GetAttr) and instruction.object in instance_of:
                method = f"{instance_of[instruction.object]}.{instruction.attribute}"
                if method in nested:
                    targets[instruction.result] = KnownFunction(method)
            elif isinstance(instruction, GetAttr):
                # ``Student.create(...)``: a static or class method called on the class.
                origin = defs.get(instruction.object)
                if isinstance(origin, Global) and origin.name in classes:
                    method = f"{origin.name}.{instruction.attribute}"
                    if method in nested:
                        targets[instruction.result] = KnownFunction(method)
    return targets, symbols


def _is_staticmethod(function: nodes.Function) -> bool:
    for decorator in function.decorators:
        if isinstance(decorator, nodes.Name) and decorator.identifier == "staticmethod":
            return True
        if isinstance(decorator, nodes.Attribute) and decorator.name == "staticmethod":
            return True
    return False


def _annotated(
    function: nodes.Function, ssa: FunctionIR, scopes: ScopeTable, table: SymbolTable
) -> dict[Value, SymbolId]:
    """Parameters annotated with a resolvable class denote that class (``db: Session``)."""

    scope = scopes.scope_for(function)
    enclosing = scope.parent if scope.parent is not None else scope.id
    found: dict[Value, SymbolId] = {}
    # Captured variables follow the explicit parameters and carry no annotation.
    for value, parameter in zip(ssa.parameters, function.parameters, strict=False):
        if parameter.annotation is None:
            continue
        symbol = table.resolve_expression(enclosing, parameter.annotation)
        if symbol is not None:
            found[value] = symbol
    return found


def _typed_with_module_classes(
    function: nodes.Function, ssa: FunctionIR, classes: Mapping[str, frozenset[str]]
) -> dict[Value, str]:
    """Parameters annotated with a class of this module (``a: App``)."""

    found: dict[Value, str] = {}
    for value, parameter in zip(ssa.parameters, function.parameters, strict=False):
        annotation = parameter.annotation
        if isinstance(annotation, nodes.Name) and annotation.identifier in classes:
            found[value] = annotation.identifier
    return found


class CallGraphAnalysis(Analysis[CallGraph]):
    name: ClassVar[str] = "interprocedural.callgraph"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({SSAAnalysis, ScopeAnalysis, SymbolAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> CallGraph:
        scopes = ctx.get(ScopeAnalysis)
        table = ctx.get(SymbolAnalysis)
        definitions: dict[str, nodes.Function] = {}
        for function in analyzable_functions(ctx.module):
            # A property and its setter, or a redefinition, share a qualified name; each
            # definition still needs a name of its own.
            base = unique = qualified_name(scopes, function)
            ordinal = 2
            while unique in definitions:
                unique = f"{base}__{ordinal}"
                ordinal += 1
            definitions[unique] = function
        known = frozenset(
            name for name, function in definitions.items() if function in ctx.module.body
        )
        classes = {
            statement.name: frozenset(m.name for m in statement.body if isinstance(m, nodes.Function))
            for statement in ctx.module.body
            if isinstance(statement, nodes.Class)
        }
        bases: dict[str, SymbolId] = {}
        for statement in ctx.module.body:
            if isinstance(statement, nodes.Class):
                for base_expression in statement.bases:
                    symbol = table.resolve_expression(scopes.module_scope.id, base_expression)
                    if symbol is not None:
                        bases[statement.name] = symbol
                        break
        sites: dict[str, tuple[CallSite, ...]] = {}
        symbols: dict[str, Mapping[Value, SymbolId]] = {}
        unsupported: set[str] = set()
        for name, function in definitions.items():
            try:
                ssa = ctx.get(SSAAnalysis, function)
            except (LoweringError, CFGError):
                unsupported.add(name)
                sites[name] = ()
                continue
            owner = name.rsplit(".", 1)[0] if "." in name and name.rsplit(".", 1)[0] in classes else None
            if owner is not None and _is_staticmethod(function):
                owner = None  # a static method has no receiver
            targets, symbols[name] = resolve_targets(
                ssa,
                scopes,
                known,
                _annotated(function, ssa, scopes, table),
                frozenset(definitions),
                classes,
                owner,
                _typed_with_module_classes(function, ssa, classes),
                bases,
            )
            defs = {i.result: i for block in ssa.blocks for i in block.instructions if i.result is not None}
            found: list[CallSite] = []
            for block in ssa.blocks:
                for instruction in block.instructions:
                    if isinstance(instruction, Call):
                        found.append(
                            CallSite(
                                name,
                                instruction.location,
                                targets.get(instruction.callee, UnknownTarget()),
                                _arguments(instruction, symbols[name], defs),
                            )
                        )
            sites[name] = tuple(found)
        return CallGraph(definitions, sites, frozenset(unsupported), symbols)
