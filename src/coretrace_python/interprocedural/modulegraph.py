"""Module graph and project-wide summary index (architecture §21).

A project is a directory of Python files. Each file is one module named after its
packages (``app/helpers.py`` is ``app.helpers``); the graph records which project modules
each module imports. Functions defined in the project get project symbols
(``python.app.helpers.run``) whose summaries live in a ``SummaryIndex`` that the engine
provides to every module's manager, so calls into other files are analysed through
summaries rather than by retaining every module's PyIR.

The identity of a module is its file. Two files may have the same import name
(``a/app.py`` and ``z/app.py`` outside any package are both ``app``, each from its own
directory): the engine then names them by their path from the root, ``a.app`` and
``z.app``, and an import of ``app`` resolves within the importer's own root only.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from coretrace_python.hir import nodes
from coretrace_python.interprocedural.summaries import ProjectSummaries, SummaryIndex
from coretrace_python.semantic.imports import ImportTable
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceFile, SourceManager

IGNORED_DIRECTORIES = frozenset({"__pycache__", "node_modules", "venv", "build", "dist", "site-packages"})


def discover_files(root: Path, pattern: str = "*") -> tuple[Path, ...]:
    """Every file matching ``pattern`` under ``root``, skipping hidden and tooling
    directories and virtual environments, recognised by the ``pyvenv.cfg`` at their root
    whatever their name."""

    found: list[Path] = []
    environments: dict[Path, bool] = {}
    for path in sorted(root.rglob(pattern)):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(p.startswith(".") or p in IGNORED_DIRECTORIES for p in relative.parts[:-1]):
            continue
        if any(_is_environment(root / Path(*relative.parts[:depth]), environments) for depth in range(1, len(relative.parts))):
            continue
        found.append(path)
    return tuple(found)


def discover_sources(
    root: Path, manager: SourceManager, errors: list[tuple[Path, str]] | None = None
) -> tuple[SourceFile, ...]:
    """Load every ``.py`` file under ``root`` (see ``discover_files``). A file that cannot
    be read or decoded is skipped and reported in ``errors``: Python could not import it
    either."""

    found: list[SourceFile] = []
    for path in discover_files(root, "*.py"):
        try:
            found.append(manager.load_file(path))
        except (OSError, UnicodeDecodeError) as error:
            if errors is None:
                raise
            errors.append((path, str(error)))
    return tuple(found)


def _is_environment(directory: Path, known: dict[Path, bool]) -> bool:
    if directory not in known:
        known[directory] = (directory / "pyvenv.cfg").is_file()
    return known[directory]


def name_modules(root: Path, sources: Iterable[SourceFile]) -> dict[str, SourceFile]:
    """One name per file, in the order given: its import name when no other file has it;
    otherwise its path from ``root`` as a dotted name (``a/app.py`` and ``z/app.py`` are
    ``a.app`` and ``z.app``, a root-level ``manage.py`` stays ``manage``), or that path
    itself when even the dotted names coincide (``x.y/app.py`` and ``x/y/app.py``).
    Decided over the whole set, so the names do not depend on the order the files are
    found in."""

    found = tuple(sources)
    counts = Counter(source.module_name for source in found)
    shared = [source for source in found if counts[source.module_name] > 1]
    paths = {source.source_id: _relative(root, source) for source in shared}
    dotted = {source_id: _dotted(path) for source_id, path in paths.items()}
    taken = (
        {name for name, count in counts.items() if count == 1}
        | {name for name, count in Counter(dotted.values()).items() if count > 1}
        | {path.as_posix() for path in paths.values()}
    )
    named: dict[str, SourceFile] = {}
    for source in found:
        if counts[source.module_name] == 1:
            named[source.module_name] = source
        elif dotted[source.source_id] not in taken:
            named[dotted[source.source_id]] = source
        else:
            named[paths[source.source_id].as_posix()] = source
    return named


def _relative(root: Path, source: SourceFile) -> Path:
    path = source.path if source.path is not None else Path(str(source.source_id))
    try:
        return path.relative_to(root.resolve())
    except ValueError:
        return path


def _dotted(path: Path) -> str:
    """``a/app.py`` as ``a.app`` and ``pkg/__init__.py`` as ``pkg``; a root-level
    ``__init__.py`` has no dotted name and keeps its path."""

    parts = path.with_suffix("").parts
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) or path.as_posix()


def _import_root(source: SourceFile) -> Path | None:
    """The directory an import of ``source`` by its module name starts from: the parent
    of its top-level package, or its own directory for a module outside any package,
    where ``module_name_for`` stopped. ``None`` for a source not on disk."""

    if source.path is None:
        return None
    directory = source.path.parent
    while (directory / "__init__.py").is_file():
        directory = directory.parent
    return directory


def project_symbol(module_name: str, qualified_name: str) -> SymbolId:
    """The canonical symbol of a project function. A module whose name is not an
    identifier cannot be imported by that name, but its functions still need stable
    symbols: invalid characters become underscores."""

    module = ".".join(_component(part) for part in module_name.split("."))
    # A synthetic body function is ``<module>`` or ``Cls.<body>``: valid as a name, not
    # as a symbol component. Nothing calls a body, so its symbol only needs to be one.
    qualified = ".".join(_component(part) for part in qualified_name.split("."))
    return SymbolId(f"python.{module}.{qualified}")


def _component(part: str) -> str:
    if part.isidentifier():
        return part
    cleaned = "".join(c if (c.isalnum() or c == "_") else "_" for c in part)
    return cleaned if cleaned.isidentifier() else f"_{cleaned}"


@dataclass(frozen=True)
class ModuleGraph:
    _sources: Mapping[str, SourceFile]
    _imports: Mapping[str, frozenset[str]]
    _unresolved: Mapping[str, frozenset[str]] = field(default_factory=dict)

    @property
    def modules(self) -> tuple[str, ...]:
        return tuple(sorted(self._sources))

    def source(self, name: str) -> SourceFile:
        return self._sources[name]

    def imports(self, name: str) -> frozenset[str]:
        return self._imports.get(name, frozenset())

    def importers(self, name: str) -> frozenset[str]:
        return frozenset(m for m, imported in self._imports.items() if name in imported)

    def unresolved(self, name: str) -> frozenset[str]:
        """The import names ``name`` imports that several project files have and not
        exactly one in its own root: no edge records them."""

        return self._unresolved.get(name, frozenset())

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
    """Edges from each module to the project modules it imports, in any scope. An import
    names a module by its import name; when several files have that name, it resolves to
    the one in the importer's own root and, without exactly one there, stays unresolved:
    no edge, and the name is recorded on the graph."""

    by_name: dict[str, list[str]] = {}
    for name, source in sources.items():
        by_name.setdefault(source.module_name, []).append(name)
    roots = {name: _import_root(source) for name, source in sources.items()}
    edges: dict[str, frozenset[str]] = {}
    unresolved: dict[str, frozenset[str]] = {}
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
        found: set[str] = set()
        missing: set[str] = set()
        for candidate in candidates:
            for prefix in _prefixes(candidate):
                matching = by_name.get(prefix)
                if matching is None:
                    continue
                if len(matching) > 1:
                    matching = [m for m in matching if roots[m] == roots[name]]
                if len(matching) == 1:
                    found.add(matching[0])
                else:
                    missing.add(prefix)
                break
        edges[name] = frozenset(found - {name})
        if missing:
            unresolved[name] = frozenset(missing)
    return ModuleGraph(MappingProxyType(dict(sources)), MappingProxyType(edges), MappingProxyType(unresolved))


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
    "name_modules",
    "project_symbol",
]
