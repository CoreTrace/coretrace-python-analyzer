"""Symbol analysis: resolve names to canonical identities (architecture §4.3)."""

from __future__ import annotations

import builtins
from collections.abc import Mapping
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.analysis import Analysis, AnalysisContext, AnyAnalysis
from coretrace_python.hir import nodes
from coretrace_python.semantic.identity import SymbolId
from coretrace_python.semantic.imports import ImportAnalysis, ImportTable
from coretrace_python.semantic.scopes import ResolutionKind, ScopeAnalysis, ScopeId, ScopeTable

BUILTIN_NAMES = frozenset(name for name in dir(builtins) if not name.startswith("_"))


class SymbolTable:
    """Resolve names to canonical symbols through scopes, imports, builtins and the
    module-level instances created by calling a symbol (``app = Flask(__name__)``)."""

    def __init__(
        self,
        scopes: ScopeTable,
        imports: ImportTable,
        instances: Mapping[str, SymbolId] | None = None,
    ) -> None:
        self._scopes = scopes
        self._imports = imports
        self._instances = MappingProxyType(dict(instances or {}))

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
            return parent.attribute(node.name) if parent is not None else None
        if isinstance(node, nodes.Call):
            return self.resolve_expression(scope_id, node.callee)
        return None


def analyze_symbols(
    scopes: ScopeTable, imports: ImportTable, module: nodes.Module | None = None
) -> SymbolTable:
    table = SymbolTable(scopes, imports)
    if module is None:
        return table
    instances: dict[str, SymbolId] = {}
    module_scope = scopes.module_scope.id
    for statement in module.body:
        if (
            isinstance(statement, nodes.Assign)
            and isinstance(statement.target, nodes.Name)
            and isinstance(statement.value, nodes.Call)
        ):
            symbol = table.resolve_expression(module_scope, statement.value.callee)
            if symbol is not None:
                instances[statement.target.identifier] = symbol
    return SymbolTable(scopes, imports, instances)


class SymbolAnalysis(Analysis[SymbolTable]):
    name: ClassVar[str] = "semantic.symbols"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({ScopeAnalysis, ImportAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> SymbolTable:
        return analyze_symbols(ctx.get(ScopeAnalysis), ctx.get(ImportAnalysis), ctx.module)


__all__ = ["BUILTIN_NAMES", "SymbolAnalysis", "SymbolId", "SymbolTable", "analyze_symbols"]
