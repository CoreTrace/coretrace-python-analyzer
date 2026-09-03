"""Import analysis: per-scope bindings from import statements (architecture §4.2).

No module is ever imported. Each binding maps the local name an import introduces to
the canonical path of the object it refers to, resolved statically from the statement
and, for relative imports, from the importing module's dotted name.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.analysis import Analysis, AnalysisContext, AnyAnalysis
from coretrace_python.hir import nodes
from coretrace_python.semantic.identity import SymbolId
from coretrace_python.semantic.scopes import ScopeAnalysis, ScopeId, ScopeTable

_NO_BINDINGS: Mapping[str, SymbolId] = MappingProxyType({})


class ImportResolutionError(Exception):
    """A source-located import that cannot be resolved statically."""


class ImportTable:
    """Immutable import bindings and wildcard imports, keyed by scope."""

    def __init__(
        self,
        bindings: Mapping[ScopeId, Mapping[str, SymbolId]],
        wildcards: Mapping[ScopeId, tuple[SymbolId, ...]],
    ) -> None:
        self._bindings = MappingProxyType(
            {scope_id: MappingProxyType(dict(found)) for scope_id, found in bindings.items()}
        )
        self._wildcards = MappingProxyType(dict(wildcards))

    def bindings(self, scope_id: ScopeId) -> Mapping[str, SymbolId]:
        return self._bindings.get(scope_id, _NO_BINDINGS)

    def wildcards(self, scope_id: ScopeId) -> tuple[SymbolId, ...]:
        return self._wildcards.get(scope_id, ())


class _Collector:
    def __init__(self, module: nodes.Module, scopes: ScopeTable) -> None:
        self.package = module.name.rpartition(".")[0]
        self.scopes = scopes
        self.bindings: dict[ScopeId, dict[str, SymbolId]] = {}
        self.wildcards: dict[ScopeId, list[SymbolId]] = {}
        self.body(module.body, scopes.module_scope.id)

    def body(self, statements: tuple[nodes.Statement, ...], scope_id: ScopeId) -> None:
        for statement in statements:
            if isinstance(statement, nodes.Import):
                for alias in statement.names:
                    # ``import a.b.c`` binds ``a``; ``import a.b.c as d`` binds the full path.
                    top_level = alias.name.partition(".")[0]
                    if alias.as_name is None:
                        self.bind(scope_id, top_level, top_level)
                    else:
                        self.bind(scope_id, alias.as_name, alias.name)
            elif isinstance(statement, nodes.ImportFrom):
                base = self.base_module(statement)
                for alias in statement.names:
                    if alias.name == "*":
                        self.wildcards.setdefault(scope_id, []).append(
                            SymbolId.from_python_path(base)
                        )
                    else:
                        self.bind(scope_id, alias.as_name or alias.name, f"{base}.{alias.name}")
            elif isinstance(statement, (nodes.Function, nodes.Class)):
                self.body(statement.body, self.scopes.scope_for(statement).id)
            elif isinstance(statement, nodes.If):
                self.body(statement.body, scope_id)
                self.body(statement.orelse, scope_id)
            elif isinstance(statement, (nodes.While, nodes.For)):
                self.body(statement.body, scope_id)

    def base_module(self, statement: nodes.ImportFrom) -> str:
        if not statement.level:
            assert statement.module is not None, "absolute import without a module"
            return statement.module
        parts = self.package.split(".") if self.package else []
        kept = len(parts) - (statement.level - 1)
        if kept < 1:
            raise ImportResolutionError(
                f"{statement.span.display()}: relative import beyond top-level package"
            )
        base = ".".join(parts[:kept])
        return f"{base}.{statement.module}" if statement.module else base

    def bind(self, scope_id: ScopeId, local_name: str, canonical_path: str) -> None:
        symbol = SymbolId.from_python_path(canonical_path)
        self.bindings.setdefault(scope_id, {})[local_name] = symbol


def analyze_imports(module: nodes.Module, scopes: ScopeTable) -> ImportTable:
    """Collect every import binding of ``module`` without importing anything."""

    collector = _Collector(module, scopes)
    return ImportTable(
        collector.bindings,
        {scope_id: tuple(found) for scope_id, found in collector.wildcards.items()},
    )


class ImportAnalysis(Analysis[ImportTable]):
    name: ClassVar[str] = "semantic.imports"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({ScopeAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> ImportTable:
        return analyze_imports(ctx.module, ctx.get(ScopeAnalysis))
