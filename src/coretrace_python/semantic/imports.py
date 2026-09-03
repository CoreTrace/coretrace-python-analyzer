"""Collection of module-level import bindings."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from coretrace_python.hir import nodes
from coretrace_python.semantic.symbols import SymbolId


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


def _error(node: nodes.ImportFrom, message: str) -> ImportResolutionError:
    return ImportResolutionError(f"{node.span.display()}: {message}")


def collect_imports(module: nodes.Module) -> ImportBindings:
    """Collect supported top-level imports without importing any modules."""

    bindings: dict[str, SymbolId] = {}
    for statement in module.body:
        if isinstance(statement, nodes.Import):
            for alias in statement.names:
                if alias.as_name is None:
                    local_name = alias.name.partition(".")[0]
                    canonical_path = local_name
                else:
                    local_name = alias.as_name
                    canonical_path = alias.name
                bindings[local_name] = SymbolId.from_python_path(canonical_path)
        elif isinstance(statement, nodes.ImportFrom):
            if statement.level:
                raise _error(statement, "relative imports are not supported yet")
            if statement.module is None:
                raise _error(statement, "import module is missing")
            for alias in statement.names:
                if alias.name == "*":
                    raise _error(statement, "wildcard imports are not supported")
                local_name = alias.as_name or alias.name
                canonical_path = f"{statement.module}.{alias.name}"
                bindings[local_name] = SymbolId.from_python_path(canonical_path)
    return ImportBindings(bindings)

