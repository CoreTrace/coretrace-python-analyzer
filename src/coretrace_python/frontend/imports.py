"""Collection of module-level import bindings."""

from __future__ import annotations

import ast
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from coretrace_python.ir.symbol import SymbolId


class ImportResolutionError(Exception):
    """A source-located import that cannot be represented safely."""


@dataclass(frozen=True)
class ImportBindings(Mapping[str, SymbolId]):
    """Map names visible in a module to their canonical identities."""

    _bindings: dict[str, SymbolId]

    def __getitem__(self, name: str) -> SymbolId:
        return self._bindings[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._bindings)

    def __len__(self) -> int:
        return len(self._bindings)

    def resolve(self, name: str) -> SymbolId | None:
        return self._bindings.get(name)


def _error(filename: str, node: ast.AST, message: str) -> ImportResolutionError:
    line = getattr(node, "lineno", 1)
    column = getattr(node, "col_offset", 0) + 1
    return ImportResolutionError(f"{filename}:{line}:{column}: {message}")


def collect_imports(tree: ast.Module, filename: str = "<unknown>") -> ImportBindings:
    """Collect supported top-level imports without importing any modules."""

    bindings: dict[str, SymbolId] = {}
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                if alias.asname is None:
                    local_name = alias.name.partition(".")[0]
                    canonical_path = local_name
                else:
                    local_name = alias.asname
                    canonical_path = alias.name
                bindings[local_name] = SymbolId.from_python_path(canonical_path)
        elif isinstance(statement, ast.ImportFrom):
            if statement.level:
                raise _error(filename, statement, "relative imports are not supported yet")
            if statement.module is None:
                raise _error(filename, statement, "import module is missing")
            for alias in statement.names:
                if alias.name == "*":
                    raise _error(filename, statement, "wildcard imports are not supported")
                local_name = alias.asname or alias.name
                canonical_path = f"{statement.module}.{alias.name}"
                bindings[local_name] = SymbolId.from_python_path(canonical_path)
    return ImportBindings(bindings)

