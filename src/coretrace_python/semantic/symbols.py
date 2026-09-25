"""Symbol analysis: resolve names to canonical identities (architecture §4.3)."""

from __future__ import annotations

import builtins
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.analysis import Analysis, AnalysisContext, AnyAnalysis
from coretrace_python.hir import nodes
from coretrace_python.semantic.identity import SymbolId
from coretrace_python.semantic.imports import ImportAnalysis, ImportTable
from coretrace_python.semantic.scopes import ResolutionKind, ScopeAnalysis, ScopeId, ScopeTable

BUILTIN_NAMES = frozenset(name for name in dir(builtins) if not name.startswith("_"))


@dataclass(frozen=True)
class Members:
    """What the attributes and items of an instance of ``symbol`` give, for a class whose
    instances give other objects by name, as a pymongo client gives the database it is
    dotted or indexed with (``client.shop``, ``client['shop']``).

    ``typed`` maps an attribute to the class of what it gives, called or not, since a
    call denotes its callee: ``get_database`` gives a database, as a ``db`` property does.
    ``dynamic``, when set, is the class of every item and of every attribute outside
    ``defined`` and ``typed``. Otherwise an attribute keeps its path and an item its
    container's symbol, as for any other class."""

    symbol: SymbolId
    dynamic: SymbolId | None = None
    defined: tuple[str, ...] = ()
    typed: tuple[tuple[str, SymbolId], ...] = ()

    def __post_init__(self) -> None:
        # Sorted: the models' repr is part of the cache key, the same in every process.
        object.__setattr__(self, "defined", tuple(sorted(set(self.defined))))

    def attribute(self, name: str) -> SymbolId:
        for attribute, gives in self.typed:
            if attribute == name:
                return gives
        if self.dynamic is not None and name not in self.defined:
            return self.dynamic
        return self.symbol.attribute(name)

    def item(self) -> SymbolId:
        return self.symbol if self.dynamic is None else self.dynamic


class SymbolTable:
    """Resolve names to canonical symbols through scopes, imports, builtins and the
    module-level names bound to a value denoting a symbol (``app = Flask(__name__)``,
    ``cursor = conn.cursor()``). ``members`` holds the ``Members`` models by class."""

    def __init__(
        self,
        scopes: ScopeTable,
        imports: ImportTable,
        instances: Mapping[str, SymbolId] | None = None,
        members: Mapping[SymbolId, Members] | None = None,
    ) -> None:
        self._scopes = scopes
        self._imports = imports
        self._instances = MappingProxyType(dict(instances or {}))
        self._members = MappingProxyType(dict(members or {}))

    def attribute(self, symbol: SymbolId, name: str) -> SymbolId:
        """The symbol of attribute ``name`` of what ``symbol`` denotes: its path, unless
        a ``Members`` model describes the class."""

        members = self._members.get(symbol)
        return symbol.attribute(name) if members is None else members.attribute(name)

    def item(self, symbol: SymbolId) -> SymbolId:
        """The symbol of an item of what ``symbol`` denotes: the container's own, so its
        methods resolve (``request.files['f'].save``), unless a ``Members`` model says."""

        members = self._members.get(symbol)
        return symbol if members is None else members.item()

    def resolve(self, scope_id: ScopeId, name: str) -> SymbolId | None:
        resolution = self._scopes.resolve(scope_id, name)
        if resolution.kind is ResolutionKind.UNBOUND:
            return SymbolId(f"python.builtins.{name}") if name in BUILTIN_NAMES else None
        assert resolution.scope is not None
        imported = self._imports.bindings(resolution.scope).get(name)
        if imported is not None:
            return imported
        if resolution.scope == self._scopes.module_scope.id:
            return self._instances.get(name)
        return None

    def resolve_expression(self, scope_id: ScopeId, node: nodes.Expression) -> SymbolId | None:
        """The symbol of a name or attribute chain, or of the callee of a call."""

        if isinstance(node, nodes.Name):
            return self.resolve(scope_id, node.identifier)
        if isinstance(node, nodes.Attribute):
            parent = self.resolve_expression(scope_id, node.value)
            return self.attribute(parent, node.name) if parent is not None else None
        if isinstance(node, nodes.Call):
            return self.resolve_expression(scope_id, node.callee)
        return None


def analyze_symbols(
    scopes: ScopeTable,
    imports: ImportTable,
    module: nodes.Module | None = None,
    members: Mapping[SymbolId, Members] | None = None,
) -> SymbolTable:
    table = SymbolTable(scopes, imports, members=members)
    if module is None:
        return table
    instances: dict[str, SymbolId] = {}
    module_scope = scopes.module_scope.id
    for statement in module.body:
        if isinstance(statement, nodes.Assign) and isinstance(statement.target, nodes.Name):
            symbol = _denoted(table, module_scope, statement.value)
            if symbol is not None:
                instances[statement.target.identifier] = symbol
                # Later bindings resolve through this one, in statement order.
                table = SymbolTable(scopes, imports, instances, members)
    return table


def _denoted(table: SymbolTable, scope_id: ScopeId, node: nodes.Expression) -> SymbolId | None:
    """What a value denotes, as a function body derives it (``derive_symbols``): a
    resolved name or an attribute of one, the result of calling one, or an item of one,
    which carries its container's symbol (``os.environ['HOME']``) unless a ``Members``
    model says what its items are."""

    if isinstance(node, nodes.Subscript):
        container = _denoted(table, scope_id, node.value)
        return table.item(container) if container is not None else None
    if isinstance(node, nodes.Attribute):
        parent = _denoted(table, scope_id, node.value)
        return table.attribute(parent, node.name) if parent is not None else None
    if isinstance(node, nodes.Call):
        return _denoted(table, scope_id, node.callee)
    return table.resolve_expression(scope_id, node)


class MembersAnalysis(Analysis[Mapping[SymbolId, Members]]):
    """The ``Members`` models by class, provided by the engine from the security models;
    none on its own, so every attribute keeps its path."""

    name: ClassVar[str] = "semantic.members"

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> Mapping[SymbolId, Members]:
        return MappingProxyType({})


class SymbolAnalysis(Analysis[SymbolTable]):
    name: ClassVar[str] = "semantic.symbols"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({ScopeAnalysis, ImportAnalysis, MembersAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> SymbolTable:
        return analyze_symbols(
            ctx.get(ScopeAnalysis), ctx.get(ImportAnalysis), ctx.module, ctx.get(MembersAnalysis)
        )


__all__ = [
    "BUILTIN_NAMES",
    "Members",
    "MembersAnalysis",
    "SymbolAnalysis",
    "SymbolId",
    "SymbolTable",
    "analyze_symbols",
]
