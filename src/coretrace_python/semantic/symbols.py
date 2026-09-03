"""Symbol analysis: resolve names to canonical identities (architecture §4.3)."""

from __future__ import annotations

import builtins
from typing import ClassVar

from coretrace_python.analysis import Analysis, AnalysisContext, AnyAnalysis
from coretrace_python.semantic.identity import SymbolId
from coretrace_python.semantic.imports import ImportAnalysis, ImportTable
from coretrace_python.semantic.scopes import ResolutionKind, ScopeAnalysis, ScopeId, ScopeTable

BUILTIN_NAMES = frozenset(name for name in dir(builtins) if not name.startswith("_"))


class SymbolTable:
    """Resolve names to canonical symbols through scopes, imports and builtins."""

    def __init__(self, scopes: ScopeTable, imports: ImportTable) -> None:
        self._scopes = scopes
        self._imports = imports

    def resolve(self, scope_id: ScopeId, name: str) -> SymbolId | None:
        resolution = self._scopes.resolve(scope_id, name)
        if resolution.kind is ResolutionKind.UNBOUND:
            return SymbolId(f"python.builtins.{name}") if name in BUILTIN_NAMES else None
        assert resolution.scope is not None
        return self._imports.bindings(resolution.scope).get(name)


def analyze_symbols(scopes: ScopeTable, imports: ImportTable) -> SymbolTable:
    return SymbolTable(scopes, imports)


class SymbolAnalysis(Analysis[SymbolTable]):
    name: ClassVar[str] = "semantic.symbols"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({ScopeAnalysis, ImportAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> SymbolTable:
        return analyze_symbols(ctx.get(ScopeAnalysis), ctx.get(ImportAnalysis))


__all__ = ["BUILTIN_NAMES", "SymbolAnalysis", "SymbolId", "SymbolTable", "analyze_symbols"]
