"""Intra-module call graph (architecture §20).

Every call site of every analysable function resolves, through the SSA form, to a
``KnownFunction`` defined at module level, an ``ExternalSymbol`` reached through imports
or builtins, or ``UnknownTarget`` (parameters, attributes, methods) until type inference
and framework models narrow it down.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.analysis import Analysis, AnalysisContext, AnyAnalysis
from coretrace_python.cfg import CFGError
from coretrace_python.hir import nodes
from coretrace_python.ir.lowering import LoweringError, analyzable_functions, qualified_name
from coretrace_python.ir.model import Call, FunctionIR, GetAttr, Global, Symbol, Value, WithEnter
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.semantic.scopes import BindingKind, ScopeAnalysis, ScopeTable
from coretrace_python.semantic.symbols import SymbolId
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
class CallSite:
    caller: str
    location: SourceSpan
    target: Target
    arguments: int
    keywords: int


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
        self._targets = {
            (site.caller, site.location): site.target for found in sites.values() for site in found
        }
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
        return self._targets.get((caller, location), UnknownTarget())

    def callees(self, caller: str) -> frozenset[str]:
        return frozenset(
            site.target.name for site in self.sites(caller) if isinstance(site.target, KnownFunction)
        )

    def callers(self, name: str) -> frozenset[str]:
        return self._callers.get(name, frozenset())


def derive_symbols(function: FunctionIR) -> dict[Value, SymbolId]:
    """Symbols of values: ``Symbol`` results, attributes of symbol values, results of
    calling a symbol (``sqlite3.connect(p)`` denotes ``python.sqlite3.connect``) and the
    values a ``with`` on such a result binds. Known functions and parameters derive nothing."""

    symbols: dict[Value, SymbolId] = {}
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
                elif isinstance(instruction, Call | WithEnter):
                    origin = (
                        instruction.callee if isinstance(instruction, Call) else instruction.context
                    )
                    symbol = symbols.get(origin)
                if symbol is not None:
                    symbols[instruction.result] = symbol
                    changed = True
    return symbols


def resolve_targets(
    function: FunctionIR, scopes: ScopeTable, known: frozenset[str]
) -> tuple[dict[Value, Target], dict[Value, SymbolId]]:
    """Map every callee value of ``function`` to its target, and every symbol value."""

    module = scopes.module_scope
    symbols = derive_symbols(function)
    targets: dict[Value, Target] = {
        value: ExternalSymbol(symbol) for value, symbol in symbols.items()
    }
    for block in function.blocks:
        for instruction in block.instructions:
            if isinstance(instruction, Global):
                binding = module.bindings.get(instruction.name)
                if (
                    binding is not None
                    and binding.kind is BindingKind.FUNCTION
                    and instruction.name in known
                ):
                    targets[instruction.result] = KnownFunction(instruction.name)
    return targets, symbols


class CallGraphAnalysis(Analysis[CallGraph]):
    name: ClassVar[str] = "interprocedural.callgraph"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({SSAAnalysis, ScopeAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> CallGraph:
        scopes = ctx.get(ScopeAnalysis)
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
            targets, symbols[name] = resolve_targets(ssa, scopes, known)
            found: list[CallSite] = []
            for block in ssa.blocks:
                for instruction in block.instructions:
                    if isinstance(instruction, Call):
                        found.append(
                            CallSite(
                                name,
                                instruction.location,
                                targets.get(instruction.callee, UnknownTarget()),
                                len(instruction.arguments),
                                len(instruction.keywords),
                            )
                        )
            sites[name] = tuple(found)
        return CallGraph(definitions, sites, frozenset(unsupported), symbols)
