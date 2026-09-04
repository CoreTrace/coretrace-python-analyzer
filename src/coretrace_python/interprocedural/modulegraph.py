"""Module graph and project-wide summary index (architecture §21).

A project is a directory of Python files. Each file is one module named after its
packages (``app/helpers.py`` is ``app.helpers``); the graph records which project modules
each module imports. Functions defined in the project get project symbols
(``python.app.helpers.run``) whose summaries live in a ``SummaryIndex`` that the engine
provides to every module's manager, so calls into other files are analysed through
summaries rather than by retaining every module's PyIR.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from coretrace_python.hir import nodes
from coretrace_python.interprocedural.summaries import ProjectSummaries, SummaryIndex
from coretrace_python.semantic.imports import ImportTable
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceFile, SourceManager

IGNORED_DIRECTORIES = frozenset({"__pycache__", "node_modules", "venv", "build", "dist", "site-packages"})


def discover_sources(root: Path, manager: SourceManager) -> tuple[SourceFile, ...]:
    """Load every ``.py`` file under ``root``, skipping hidden and tooling directories."""

    found: list[SourceFile] = []
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if any(p.startswith(".") or p in IGNORED_DIRECTORIES for p in relative.parts[:-1]):
            continue
        found.append(manager.load_file(path))
    return tuple(found)


def project_symbol(module_name: str, qualified_name: str) -> SymbolId:
    return SymbolId(f"python.{module_name}.{qualified_name}")


@dataclass(frozen=True)
class ModuleGraph:
    _sources: Mapping[str, SourceFile]
    _imports: Mapping[str, frozenset[str]]

    @property
    def modules(self) -> tuple[str, ...]:
        return tuple(sorted(self._sources))

    def source(self, name: str) -> SourceFile:
        return self._sources[name]

    def imports(self, name: str) -> frozenset[str]:
        return self._imports.get(name, frozenset())

    def importers(self, name: str) -> frozenset[str]:
        return frozenset(m for m, imported in self._imports.items() if name in imported)


def build_module_graph(
    sources: Mapping[str, SourceFile],
    modules: Mapping[str, nodes.Module],
    imports: Mapping[str, ImportTable],
) -> ModuleGraph:
    """Edges from each module to the project modules it imports, in any scope."""

    names = frozenset(sources)
    edges: dict[str, frozenset[str]] = {}
    for name, module in modules.items():
        candidates: set[str] = set()
        dotted_tops: set[str] = set()
        for statement in _statements(module.body):
            if isinstance(statement, nodes.Import):
                for alias in statement.names:
                    candidates.add(alias.name)
                    if "." in alias.name:
                        dotted_tops.add(alias.name.partition(".")[0])
        for symbol in imports[name].all_symbols():
            path = symbol.canonical_name.removeprefix("python.")
            # ``import app.config`` binds ``app``; the statement already named the module.
            if path not in dotted_tops:
                candidates.add(path)
        # The most specific project module each import names; ``app.helpers`` implies
        # the ``app`` package, which is not an edge worth recording.
        found = {
            next((m for m in _prefixes(candidate) if m in names), None) for candidate in candidates
        }
        edges[name] = frozenset(m for m in found if m is not None and m != name)
    return ModuleGraph(MappingProxyType(dict(sources)), MappingProxyType(edges))


def _prefixes(dotted: str) -> list[str]:
    parts = dotted.split(".")
    return [".".join(parts[:length]) for length in range(len(parts), 0, -1)]


def _statements(body: Iterable[nodes.Statement]) -> Iterable[nodes.Statement]:
    for statement in body:
        yield statement
        for attribute in ("body", "orelse", "finalbody"):
            nested = getattr(statement, attribute, None)
            if isinstance(nested, tuple):
                yield from _statements(nested)
        if isinstance(statement, nodes.Try):
            for handler in statement.handlers:
                yield from _statements(handler.body)

__all__ = [
    "IGNORED_DIRECTORIES",
    "ModuleGraph",
    "ProjectSummaries",
    "SummaryIndex",
    "build_module_graph",
    "discover_sources",
    "project_symbol",
]
