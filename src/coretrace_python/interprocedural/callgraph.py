"""Intra-module call graph (architecture §20).

Every call site of every analysable function resolves, through the SSA form, to a
``KnownFunction`` defined at module level, an ``ExternalSymbol`` reached through imports
or builtins, or ``UnknownTarget`` (parameters, attributes, methods) until type inference
and framework models narrow it down. The graph also keeps the symbols each function
reads, called or not: reading ``request.form`` runs its getter.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.analysis import Analysis, AnalysisContext, AnyAnalysis
from coretrace_python.cfg import BlockId, CFGError
from coretrace_python.cfg.dominance import DominanceAnalysis, DominatorTree
from coretrace_python.hir import nodes
from coretrace_python.ir.defuse import DefUse, def_use
from coretrace_python.ir.lowering import (
    MODULE_BODY,
    LoweringError,
    analyzable_functions,
    qualified_name,
)
from coretrace_python.ir.model import (
    Await,
    BasicBlock,
    BuildDict,
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
    still be given; after ``*args`` no position is known, and ``positional`` is empty.
    ``keyword_unpacked`` says the call expands a ``**mapping`` whose keys it does not
    write, so a keyword name may be anything; a literal with constant keys is written out
    as its keywords, and ``unpacked`` stays true for it only when ``*args`` is also given."""

    positional: tuple[str | None, ...] = ()
    keywords: tuple[tuple[str, str | None], ...] = ()
    unpacked: bool = False
    keyword_unpacked: bool = False

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
class PriorCall:
    """Another call on the same receiver in this function; ``dominates`` says it surely
    executes before this one."""

    symbol: SymbolId
    location: SourceSpan
    arguments: Arguments
    dominates: bool


@dataclass(frozen=True)
class CallSite:
    caller: str
    location: SourceSpan
    target: Target
    arguments: Arguments = field(default_factory=Arguments)
    # None: no receiver, or one the engine cannot follow; a tuple is the complete set
    # of other external calls on the receiver, in source order.
    prior_calls: tuple[PriorCall, ...] | None = None


@dataclass(frozen=True)
class SymbolRead:
    """Where ``function`` first reads ``symbol``: an imported name or an attribute of a
    value denoting a symbol (``request.form`` in ``request.form['name']``)."""

    function: str
    location: SourceSpan
    symbol: SymbolId


@dataclass(frozen=True)
class Signature:
    """What the parameters of the methods of a class denote when the canonical symbol
    of its base matches ``pattern``, by position after ``self``: a class symbol, or None
    for a parameter denoting none. A method taking another number of parameters has
    none. The engine derives signatures from the security models (§16)."""

    pattern: str
    parameters: tuple[SymbolId | None, ...]

    def matches(self, base: SymbolId) -> bool:
        return re.search(self.pattern, base.canonical_name) is not None


class SignaturesAnalysis(Analysis[tuple[Signature, ...]]):
    """The signatures the models declare, provided by the engine; none on its own."""

    name: ClassVar[str] = "interprocedural.signatures"

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> tuple[Signature, ...]:
        return ()


@dataclass(frozen=True)
class ModuleFunction:
    """One function of a module as a project plugin sees it: the name the call graph
    gives it (``Class.method``, ``outer.inner``, ``<module>``), where it is, the label
    of the entry point it is (``http`` for a route, ``argv`` for a command), if any, and
    the module-level ``aliases`` bound to it by assigning one name to another
    (``main = actual``), transitively and in source order; a method or a nested
    function has none."""

    name: str
    span: SourceSpan
    entry_point: str | None = None
    aliases: tuple[str, ...] = ()


class CallGraph:
    def __init__(
        self,
        definitions: Mapping[str, nodes.Function],
        sites: Mapping[str, tuple[CallSite, ...]],
        unsupported: frozenset[str],
        symbols: Mapping[str, Mapping[Value, SymbolId]] | None = None,
        reads: Mapping[str, tuple[SymbolRead, ...]] | None = None,
    ) -> None:
        self._symbols = {name: MappingProxyType(dict(found)) for name, found in (symbols or {}).items()}
        self._reads = MappingProxyType(dict(reads or {}))
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

    def reads(self, function: str) -> tuple[SymbolRead, ...]:
        """The symbols ``function`` reads, each where it first reads it."""

        return self._reads.get(function, ())

    def target_at(self, caller: str, location: SourceSpan) -> Target:
        site = self._at.get((caller, location))
        return site.target if site is not None else UnknownTarget()

    def arguments_at(self, caller: str, location: SourceSpan) -> Arguments:
        """What the arguments of the call at ``location`` in ``caller`` denote."""

        site = self._at.get((caller, location))
        return site.arguments if site is not None else Arguments()

    def prior_calls_at(self, caller: str, location: SourceSpan) -> tuple[PriorCall, ...] | None:
        """The other calls on the receiver of the call at ``location`` in ``caller``;
        None when there is no receiver, or one the engine cannot follow."""

        site = self._at.get((caller, location))
        return site.prior_calls if site is not None else None

    def callees(self, caller: str) -> frozenset[str]:
        return frozenset(
            site.target.name for site in self.sites(caller) if isinstance(site.target, KnownFunction)
        )

    def callers(self, name: str) -> frozenset[str]:
        return self._callers.get(name, frozenset())


def derive_symbols(
    function: FunctionIR, table: SymbolTable, initial: Mapping[Value, SymbolId] | None = None
) -> dict[Value, SymbolId]:
    """Symbols of values: ``Symbol`` results, attributes and items of symbol values, as
    ``table`` types them, results of calling a symbol (``sqlite3.connect(p)`` denotes
    ``python.sqlite3.connect``) and the values a ``with`` on such a result binds. Known
    functions derive nothing; parameters only through ``initial``, their annotated classes."""

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
                    symbol = table.attribute(symbols[instruction.object], instruction.attribute)
                elif isinstance(instruction, GetItem) and instruction.object in symbols:
                    symbol = table.item(symbols[instruction.object])
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

_DICT = SymbolId("python.builtins.dict")


def _keyword_entries(
    value: Value, symbols: Mapping[Value, SymbolId], defs: Mapping[Value, Instruction], uses: DefUse
) -> tuple[tuple[str, Value], ...] | None:
    """The keywords a ``**value`` gives when every name is established: the string keys
    of a dict literal, the keywords of ``dict(...)``, through what they unpack in turn;
    None when a key is computed, the mapping is built elsewhere, or anything but the
    call uses it, since a store or a mutating call may add a key the literal does not
    write."""

    if len(uses.uses(value)) != 1:
        return None
    made = defs.get(value)
    entries: list[tuple[str, Value]] = []
    if isinstance(made, BuildDict):
        for key, item in made.items:
            constant = defs.get(key)
            if not isinstance(constant, Constant) or not isinstance(constant.value, str):
                return None
            entries.append((constant.value, item))
        nested = made.unpacked
    elif isinstance(made, Call) and symbols.get(made.callee) == _DICT and not made.arguments and not made.starred:
        nested = tuple(v for name, v in made.keywords if name is None)
        entries.extend((name, v) for name, v in made.keywords if name is not None)
    else:
        return None
    for inner in nested:
        found = _keyword_entries(inner, symbols, defs, uses)
        if found is None:
            return None
        entries.extend(found)
    return tuple(entries)


def _arguments(
    call: Call, symbols: Mapping[Value, SymbolId], defs: Mapping[Value, Instruction], uses: DefUse
) -> Arguments:
    def denoted(value: Value) -> str | None:
        symbol = symbols.get(value)
        if symbol is not None:
            return str(symbol)
        made = defs.get(value)
        if not isinstance(made, Constant):
            return None
        written = repr(made.value)
        return written if len(written) <= MAX_CONSTANT_LENGTH else None

    keywords: list[tuple[str, str | None]] = []
    keyword_unpacked = False
    for name, value in call.keywords:
        if name is not None:
            keywords.append((name, denoted(value)))
            continue
        entries = _keyword_entries(value, symbols, defs, uses)
        if entries is None:
            keyword_unpacked = True
        else:
            keywords.extend((key, denoted(item)) for key, item in entries)
    return Arguments(
        () if call.starred else tuple(denoted(value) for value in call.arguments),
        tuple(keywords),
        bool(call.starred) or keyword_unpacked,
        keyword_unpacked,
    )


def _reads(name: str, function: FunctionIR, symbols: Mapping[Value, SymbolId]) -> tuple[SymbolRead, ...]:
    first: dict[SymbolId, SymbolRead] = {}
    for block in function.blocks:
        for instruction in block.instructions:
            if isinstance(instruction, Symbol | GetAttr) and instruction.result in symbols:
                read = SymbolRead(name, instruction.location, symbols[instruction.result])
                known = first.get(read.symbol)
                if known is None or _position(read.location) < _position(known.location):
                    first[read.symbol] = read
    return tuple(sorted(first.values(), key=lambda read: (_position(read.location), str(read.symbol))))


def _position(span: SourceSpan) -> tuple[int, int]:
    return span.start_line, span.start_column


# A receiver carrying more calls than this is left unfollowed: the sibling pairing
# stays bounded, and such code is generated, not a client bound and used twice.
MAX_RECEIVER_CALLS = 12


def _relate_receivers(
    sites: list[CallSite],
    calls: list[tuple[Call, BlockId, int]],
    function: FunctionIR,
    defs: Mapping[Value, Instruction],
    uses: DefUse,
    symbols: Mapping[Value, SymbolId],
    tree: DominatorTree,
) -> tuple[CallSite, ...]:
    """The ``sites`` with ``prior_calls`` filled wherever the receiver's whole lifetime
    is visible, so the set of its other calls is complete and program order is decided
    by dominance; any other receiver leaves ``None``. ``calls`` gives each site's
    instruction with its block and index, aligned with ``sites``."""

    groups: dict[Value, list[int]] = {}
    for index, (call, _, _) in enumerate(calls):
        callee = defs.get(call.callee)
        if isinstance(callee, GetAttr):
            groups.setdefault(callee.object, []).append(index)
    related = list(sites)
    blocks = {block.id: block for block in function.blocks}
    for receiver, group in groups.items():
        if not _followed(receiver, group, sites, blocks, defs, uses, symbols):
            continue
        ordered = sorted(group, key=lambda member: _position(sites[member].location))
        for index in group:
            _, block, at = calls[index]
            related[index] = replace(
                sites[index],
                prior_calls=tuple(
                    PriorCall(
                        target.symbol,
                        sites[other].location,
                        sites[other].arguments,
                        _executes_before(calls[other], block, at, tree),
                    )
                    for other in ordered
                    if other != index and isinstance(target := sites[other].target, ExternalSymbol)
                ),
            )
    return tuple(related)


def _followed(
    receiver: Value,
    group: list[int],
    sites: list[CallSite],
    blocks: Mapping[BlockId, BasicBlock],
    defs: Mapping[Value, Instruction],
    uses: DefUse,
    symbols: Mapping[Value, SymbolId],
) -> bool:
    """Whether the receiver's whole lifetime is visible: bound once to the result of a
    call or a ``with`` denoting a symbol, and read only to call external methods. Only
    then is ``group`` complete enough to claim a prior call surely missing; a receiver
    returned, passed to another call, mutated through an attribute or merged by a
    ``Phi`` may be called elsewhere, and stays unfollowed."""

    if len(group) > MAX_RECEIVER_CALLS or receiver not in symbols:
        return False
    if any(not isinstance(sites[index].target, ExternalSymbol) for index in group):
        return False
    made = defs.get(receiver)
    while isinstance(made, Await):
        made = defs.get(made.value)
    if not isinstance(made, Call | WithEnter):
        return False
    for use in uses.uses(receiver):
        if use.index is None:  # a terminator use, as a return, escapes
            return False
        read = blocks[use.block].instructions[use.index]
        if not isinstance(read, GetAttr):
            return False
        for called in uses.uses(read.result):
            if called.index is None:
                return False
            call = blocks[called.block].instructions[called.index]
            if not isinstance(call, Call) or call.callee != read.result or read.result in call.argument_values():
                return False
    return True


def _executes_before(
    other: tuple[Call, BlockId, int], block: BlockId, index: int, tree: DominatorTree
) -> bool:
    """Whether ``other`` surely executes before the call at ``index`` in ``block``: it
    comes earlier in the same block, or its block dominates this one."""

    _, other_block, other_index = other
    if other_block == block:
        return other_index < index
    return tree.dominates(other_block, block)


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
    *,
    table: SymbolTable,
) -> tuple[dict[Value, Target], dict[Value, SymbolId]]:
    """Map every callee value of ``function`` to its target, and every symbol value.
    ``nested`` names the functions defined inside this one (``outer.inner``);
    ``classes`` maps the module's classes to their methods, ``owner`` is the class of a
    method and ``typed`` the parameters annotated with a module class. ``App(x)`` is a
    call to ``App.__init__``, ``app.run()`` and ``self.run()`` calls to ``App.run``.
    ``bases`` maps a module class to the symbol of its base: an attribute the class does
    not define is inherited, so ``self.get_argument`` in a ``RequestHandler`` subclass
    denotes ``tornado.web.RequestHandler.get_argument``. ``table`` says what the
    attributes and items of a class a ``Members`` model describes give."""

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
                    inherited[instruction.result] = table.attribute(base, instruction.attribute)
    symbols = derive_symbols(function, table, inherited)
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


def _declared(
    function: nodes.Function, ssa: FunctionIR, bases: tuple[SymbolId, ...], signatures: tuple[Signature, ...]
) -> dict[Value, SymbolId]:
    """Parameters a signature types by their position, for a method of a class one of
    whose ``bases`` matches the signature and which takes the parameters it lists."""

    given = function.parameters[1:]
    for signature in signatures:
        if any(signature.matches(base) for base in bases) and len(given) == len(signature.parameters):
            typed = zip(ssa.parameters[1:], signature.parameters, strict=False)
            return {value: symbol for value, symbol in typed if symbol is not None}
    return {}


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
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset(
        {SSAAnalysis, ScopeAnalysis, SymbolAnalysis, SignaturesAnalysis, DominanceAnalysis}
    )

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> CallGraph:
        scopes = ctx.get(ScopeAnalysis)
        table = ctx.get(SymbolAnalysis)
        signatures = ctx.get(SignaturesAnalysis)
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
        # Inheritance follows the first base that resolves; a signature may match any.
        bases: dict[str, SymbolId] = {}
        ancestry: dict[str, tuple[SymbolId, ...]] = {}
        for statement in ctx.module.body:
            if isinstance(statement, nodes.Class):
                resolved = [table.resolve_expression(scopes.module_scope.id, base) for base in statement.bases]
                ancestry[statement.name] = tuple(symbol for symbol in resolved if symbol is not None)
                if ancestry[statement.name]:
                    bases[statement.name] = ancestry[statement.name][0]
        sites: dict[str, tuple[CallSite, ...]] = {}
        symbols: dict[str, Mapping[Value, SymbolId]] = {}
        reads: dict[str, tuple[SymbolRead, ...]] = {}
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
            # A signature types parameters by their position; an annotation says more.
            declared = _declared(function, ssa, ancestry.get(owner, ()) if owner is not None else (), signatures)
            targets, symbols[name] = resolve_targets(
                ssa,
                scopes,
                known,
                {**declared, **_annotated(function, ssa, scopes, table)},
                frozenset(definitions),
                classes,
                owner,
                _typed_with_module_classes(function, ssa, classes),
                bases,
                table=table,
            )
            defs = {i.result: i for block in ssa.blocks for i in block.instructions if i.result is not None}
            uses = def_use(ssa)
            found: list[CallSite] = []
            calls: list[tuple[Call, BlockId, int]] = []
            for block in ssa.blocks:
                for index, instruction in enumerate(block.instructions):
                    if isinstance(instruction, Call):
                        found.append(
                            CallSite(
                                name,
                                instruction.location,
                                targets.get(instruction.callee, UnknownTarget()),
                                _arguments(instruction, symbols[name], defs, uses),
                            )
                        )
                        calls.append((instruction, block.id, index))
            sites[name] = _relate_receivers(
                found, calls, ssa, defs, uses, symbols[name], ctx.get(DominanceAnalysis, function)
            )
            reads[name] = _reads(name, ssa, symbols[name])
        return CallGraph(definitions, sites, frozenset(unsupported), symbols, reads)
