"""Canonical symbol identities and their resolution (architecture §4.3).

A ``SymbolId`` names a Python object independently of how a file spells it: every way
of importing ``os.system`` yields ``python.os.system``. Framework models may live in
their own namespaces, such as ``flask.request.args``.
"""

from __future__ import annotations

import builtins
from dataclasses import dataclass
from typing import TYPE_CHECKING

from coretrace_python.semantic.scopes import ResolutionKind, ScopeAnalysis, ScopeId

if TYPE_CHECKING:
    from coretrace_python.semantic.imports import ImportAnalysis

BUILTIN_NAMES = frozenset(name for name in dir(builtins) if not name.startswith("_"))


@dataclass(frozen=True, order=True)
class SymbolId:
    """A stable, import-style-independent, namespace-qualified dotted name."""

    canonical_name: str

    def __post_init__(self) -> None:
        components = self.canonical_name.split(".")
        if len(components) < 2:
            raise ValueError("a canonical symbol needs a namespace and a path")
        if not all(component.isidentifier() for component in components):
            raise ValueError(f"invalid canonical symbol: {self.canonical_name!r}")

    @classmethod
    def from_python_path(cls, path: str) -> SymbolId:
        normalized_path = path.removeprefix("python.")
        if not normalized_path or normalized_path.startswith("."):
            raise ValueError("a Python symbol path cannot be empty")
        return cls(f"python.{normalized_path}")

    def attribute(self, name: str) -> SymbolId:
        if not name or "." in name:
            raise ValueError("an attribute name must be one non-empty component")
        return SymbolId(f"{self.canonical_name}.{name}")

    def __str__(self) -> str:
        return self.canonical_name


class SymbolAnalysis:
    """Resolve names to canonical symbols through scopes, imports and builtins."""

    def __init__(self, scopes: ScopeAnalysis, imports: ImportAnalysis) -> None:
        self._scopes = scopes
        self._imports = imports

    def resolve(self, scope_id: ScopeId, name: str) -> SymbolId | None:
        resolution = self._scopes.resolve(scope_id, name)
        if resolution.kind is ResolutionKind.UNBOUND:
            return SymbolId(f"python.builtins.{name}") if name in BUILTIN_NAMES else None
        assert resolution.scope is not None
        return self._imports.bindings(resolution.scope).get(name)


def analyze_symbols(scopes: ScopeAnalysis, imports: ImportAnalysis) -> SymbolAnalysis:
    return SymbolAnalysis(scopes, imports)
