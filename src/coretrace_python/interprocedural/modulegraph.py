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
    """Load every ``.py`` file under ``root``, skipping hidden and tooling directories and
    virtual environments, recognised by the ``pyvenv.cfg`` at their root whatever their
    name."""

    found: list[SourceFile] = []
    environments: dict[Path, bool] = {}
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if any(p.startswith(".") or p in IGNORED_DIRECTORIES for p in relative.parts[:-1]):
            continue
        if any(_is_environment(root / Path(*relative.parts[:depth]), environments) for depth in range(1, len(relative.parts))):
            continue
        found.append(manager.load_file(path))
    return tuple(found)


def _is_environment(directory: Path, known: dict[Path, bool]) -> bool:
    if directory not in known:
        known[directory] = (directory / "pyvenv.cfg").is_file()
    return known[directory]


def project_symbol(module_name: str, qualified_name: str) -> SymbolId:
    """The canonical symbol of a project function. A module whose name is not an
    identifier cannot be imported by that name, but its functions still need stable
    symbols: invalid characters become underscores."""

    module = ".".join(_component(part) for part in module_name.split("."))
    return SymbolId(f"python.{module}.{qualified_name}")


def _component(part: str) -> str:
    if part.isidentifier():
        return part
    cleaned = "".join(c if (c.isalnum() or c == "_") else "_" for c in part)
    return cleaned if cleaned.isidentifier() else f"_{cleaned}"


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

    def schedule(self) -> tuple[tuple[frozenset[str], ...], ...]:
        """Strongly connected components in waves: every component of a wave imports,
        outside itself, only components of earlier waves, so one wave can be analysed
        in parallel and a component's imports are final when it starts (§29)."""

        names = frozenset(self._sources)
        edges = {name: sorted(m for m in self.imports(name) if m in names) for name in names}
        component_of: dict[str, int] = {}
        components: list[frozenset[str]] = []
        index: dict[str, int] = {}
        low: dict[str, int] = {}
        stack: list[str] = []

        def visit(name: str) -> None:
            index[name] = low[name] = len(index)
            stack.append(name)
            for imported in edges[name]:
                if imported not in index:
                    visit(imported)
                    low[name] = min(low[name], low[imported])
                elif imported in stack:
                    low[name] = min(low[name], index[imported])
            if low[name] == index[name]:
                members: list[str] = []
                while True:
                    member = stack.pop()
                    members.append(member)
                    if member == name:
                        break
                for member in members:
                    component_of[member] = len(components)
                components.append(frozenset(members))

        for name in sorted(names):
            if name not in index:
                visit(name)

        depth: dict[int, int] = {}

        def level(component: int) -> int:
            if component not in depth:
                below = {
                    component_of[imported]
                    for member in components[component]
                    for imported in edges[member]
                    if component_of[imported] != component
                }
                depth[component] = 1 + max((level(c) for c in below), default=-1)
            return depth[component]

        waves: dict[int, list[frozenset[str]]] = {}
        for number in range(len(components)):
            waves.setdefault(level(number), []).append(components[number])
        return tuple(
            tuple(sorted(waves[wave], key=min)) for wave in sorted(waves)
        )


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
