"""Composition root: the full analysis DAG, plugin loading and one check run.

This is the only module that knows every layer. The CLI and future hosts call it;
plugins and analyses never import it.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import multiprocessing
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, ClassVar

from coretrace_python import __version__
from coretrace_python.abstract import ConstantPropagation, HeapAnalysis, RangeAnalysis
from coretrace_python.abstract.strings import ModuleStringsAnalysis
from coretrace_python.analysis import (
    AnalysisContext,
    AnalysisManager,
    AnyAnalysis,
    TransformationPass,
)
from coretrace_python.cache import (
    CachedModule,
    ProjectCache,
    decode,
    decode_index,
    directory_fingerprint,
    encode,
    encode_index,
    fingerprint,
    module_keys,
)
from coretrace_python.cfg import CFGAnalysis, CFGError, DominanceAnalysis, PostDominanceAnalysis
from coretrace_python.dependency import (
    ADVISORY_FILE,
    DEPENDENCY_FILES,
    POLICY_FILE,
    Advisory,
    AdvisoryFileError,
    DependencyAnalysis,
    DependencyGraph,
    Policy,
    apply_policy,
    load_advisories,
    load_policy,
    parse_dependencies,
)
from coretrace_python.dependency.correlation import (
    Affected,
    advisory_sinks,
    affected_symbols,
    correlate,
)
from coretrace_python.findings import (
    ADVISORIES,
    FINDING_SCHEMA_VERSION,
    PLUGIN,
    Component,
    Confidence,
    Coverage,
    FileCoverage,
    Finding,
    Severity,
)
from coretrace_python.findings.refutation import RefutationAnalysis
from coretrace_python.findings.suppressions import partition
from coretrace_python.frontend import HIRBuildError, ParseError, build_hir
from coretrace_python.hir import HIR_SCHEMA_VERSION, nodes
from coretrace_python.interprocedural import (
    CallGraph,
    CallGraphAnalysis,
    CallSite,
    ClearingAnalysis,
    FunctionSummary,
    ModuleFunction,
    ModuleGraph,
    ProjectSummaries,
    SummaryAnalysis,
    SummaryIndex,
    SymbolRead,
    build_module_graph,
    discover_sources,
    project_symbol,
)
from coretrace_python.ir import PYIR_SCHEMA_VERSION
from coretrace_python.ir.defuse import DefUseAnalysis
from coretrace_python.ir.lowering import (
    LoweringError,
    ModuleIRAnalysis,
    PyIRAnalysis,
    analyzable_functions,
)
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.plugins import (
    PLUGIN_API_VERSION,
    Plugin,
    PluginRegistry,
    ProjectContext,
    ProjectPlugin,
    apply_refinement,
    discover_plugins,
    run_plugins,
)
from coretrace_python.reporters import Report
from coretrace_python.semantic import SEMANTIC_ANALYSES
from coretrace_python.semantic.imports import ImportAnalysis, ImportResolutionError, ImportTable
from coretrace_python.semantic.scopes import ScopeAnalysis, ScopeError
from coretrace_python.semantic.symbols import MembersAnalysis, SymbolAnalysis, SymbolId
from coretrace_python.source import SourceFile, SourceId, SourceManager, SourceSpan, decode_text
from coretrace_python.taint import (
    EntryPoint,
    EntryPointAnalysis,
    EscapedTemplates,
    ModelTable,
    RegisteredRoutes,
    Routes,
    SecurityModelAnalysis,
    SecurityModelRegistry,
    TaintAnalysis,
    TaintKind,
    escaped_templates,
    registered_routes,
)
from coretrace_python.taint.urls import flow_url

TOOL_NAME = "coretrace-python-analyzer"

# The plugins shipped with the package: models, detectors, secrets and dependency
# checks. They are loaded by default; ``--plugins`` adds directories on top.
BUNDLED_PLUGINS = Path(__file__).resolve().parent / "bundled"

ALL_ANALYSES: tuple[AnyAnalysis, ...] = (
    *SEMANTIC_ANALYSES,
    CFGAnalysis,
    DominanceAnalysis,
    PostDominanceAnalysis,
    PyIRAnalysis,
    ModuleIRAnalysis,
    SSAAnalysis,
    DefUseAnalysis,
    ConstantPropagation,
    RangeAnalysis,
    ModuleStringsAnalysis,
    HeapAnalysis,
    CallGraphAnalysis,
    SummaryAnalysis,
    ProjectSummaries,
    SecurityModelAnalysis,
    TaintAnalysis,
    EntryPointAnalysis,
    RefutationAnalysis,
    DependencyAnalysis,
    RegisteredRoutes,
    EscapedTemplates,
    ClearingAnalysis,
)


# Named so the set stays right whichever analyses a build registers.
_PROJECT_DEPENDANT_NAMES = frozenset(
    {"interprocedural.project", "interprocedural.summaries", "taint.flows", "taint.entry_points", "findings.refutation"}
)
_PROJECT_DEPENDANTS: frozenset[AnyAnalysis] = frozenset(
    a for a in ALL_ANALYSES if a.name in _PROJECT_DEPENDANT_NAMES
)
MAX_PROJECT_ITERATIONS = 20


class ProjectSummariesUpdated(TransformationPass):
    """Invalidates every result that depends on the project-wide summary index."""

    name: ClassVar[str] = "project.summaries-updated"
    preserves: ClassVar[frozenset[AnyAnalysis]] = frozenset(
        a for a in ALL_ANALYSES if a not in _PROJECT_DEPENDANTS
    )

    @classmethod
    def run(cls, ctx: AnalysisContext) -> None:
        pass


class ResultsEvicted(TransformationPass):
    """Drops a module's PyIR and every derived result once its summaries, call sites and
    findings are extracted (§30); the semantic tables and the engine inputs stay."""

    name: ClassVar[str] = "project.results-evicted"
    preserves: ClassVar[frozenset[AnyAnalysis]] = frozenset(
        {
            *SEMANTIC_ANALYSES,
            SecurityModelAnalysis,
            ProjectSummaries,
            DependencyAnalysis,
            RegisteredRoutes,
            EscapedTemplates,
            ClearingAnalysis,
        }
    )

    @classmethod
    def run(cls, ctx: AnalysisContext) -> None:
        pass


def _no_keys() -> Mapping[str, str]:
    return MappingProxyType({})


@dataclass(frozen=True)
class ProjectAnalysis:
    graph: ModuleGraph
    index: SummaryIndex
    findings: tuple[Finding, ...]
    dependencies: DependencyGraph = field(default_factory=DependencyGraph)
    keys: Mapping[str, str] = field(default_factory=_no_keys)
    reused: tuple[str, ...] = ()
    advisories: tuple[Advisory, ...] = ()
    coverage: Coverage = field(default_factory=Coverage)
    # Findings silenced by an inline ``# coretrace: ignore`` comment.
    suppressed: tuple[Finding, ...] = ()
    # Findings about an advisory the policy accepts, still evidence of what is reached.
    accepted: tuple[Finding, ...] = ()
    # The plugins and advisory files the result was produced with.
    components: tuple[Component, ...] = ()


@dataclass(frozen=True)
class FileAnalysis:
    findings: tuple[Finding, ...]
    coverage: Coverage
    suppressed: tuple[Finding, ...] = ()


def _text_of(sources: SourceManager) -> Callable[[SourceId], str | None]:
    """The text of a source by identifier: loaded sources first, then the file on disk."""

    def text_of(source_id: SourceId) -> str | None:
        try:
            return sources.get(source_id).text
        except KeyError:
            pass
        path = Path(str(source_id))
        try:
            return decode_text(path.read_bytes()) if path.is_file() else None
        except (OSError, UnicodeDecodeError):
            return None

    return text_of


def build_manager(
    module: nodes.Module, models: SecurityModelRegistry | None = None
) -> AnalysisManager:
    """A manager with every engine analysis registered and the engine inputs provided."""

    manager = _register_all(module)
    table = (models or SecurityModelRegistry()).freeze()
    manager.provide(SecurityModelAnalysis, table)
    manager.provide(MembersAnalysis, table.members_by_class())
    manager.provide(ClearingAnalysis, table.clearing())
    manager.provide(ProjectSummaries, SummaryIndex())
    manager.provide(RegisteredRoutes, _routes_of(manager))
    return manager


def _routes_of(manager: AnalysisManager) -> dict[SymbolId, EntryPoint]:
    """The handlers one module registers, given the models already provided."""

    return registered_routes(
        manager.module,
        manager.get(ScopeAnalysis),
        manager.get(SymbolAnalysis),
        manager.get(SecurityModelAnalysis),
    )


def load_plugins(plugin_roots: Sequence[Path], manager: AnalysisManager) -> PluginRegistry:
    """Every plugin below the roots, each manifest loaded once even when roots overlap."""

    registry = PluginRegistry()
    seen: set[Path] = set()
    for root in plugin_roots:
        for loaded in discover_plugins(root, manager):
            if loaded.directory.resolve() not in seen:
                seen.add(loaded.directory.resolve())
                registry.add(loaded)
    return registry


def plugin_models(plugins: Iterable[Plugin], root: Path | None = None) -> ModelTable:
    """The models of ``plugins``, with those they read from the project at ``root``."""

    models = SecurityModelRegistry()
    for plugin in plugins:
        models.register(*plugin.models, origin=plugin.name)
        if root is not None:
            models.register(*plugin.project_models(root), origin=plugin.name)
    return models.freeze()


def check(source: SourceFile, plugin_roots: Sequence[Path]) -> tuple[Finding, ...]:
    """Run every plugin found under ``plugin_roots`` against one file."""

    return analyze_file(source, plugin_roots).findings


def analyze_file(source: SourceFile, plugin_roots: Sequence[Path]) -> FileAnalysis:
    """One file's findings and coverage, with every plugin found under ``plugin_roots``."""

    manager = _register_all(build_hir(source))
    registry = load_plugins(plugin_roots, manager)
    table = plugin_models(loaded.plugin for loaded in registry)
    manager.provide(SecurityModelAnalysis, table)
    manager.provide(MembersAnalysis, table.members_by_class())
    manager.provide(ClearingAnalysis, table.clearing())
    manager.provide(ProjectSummaries, SummaryIndex())
    manager.provide(RegisteredRoutes, _routes_of(manager))
    findings, supported = _check_module(manager, tuple(loaded.plugin for loaded in registry))
    functions = len(analyzable_functions(manager.module))
    coverage = Coverage((FileCoverage(str(source.source_id), "analysed", functions, len(supported)),))
    kept, suppressed = partition(findings, lambda sid: source.text if sid == source.source_id else None)
    return FileAnalysis(kept, coverage, suppressed)


def resolve_dependencies(root: Path, sources: SourceManager) -> DependencyGraph:
    """The requirements declared or pinned by the dependency files at ``root`` (§26)."""

    graph = DependencyGraph()
    candidates = sorted(root.glob("requirements*.txt")) + [root / name for name in DEPENDENCY_FILES]
    for path in candidates:
        if not path.is_file():
            continue
        try:
            text = decode_text(path.read_bytes())
        except (OSError, UnicodeDecodeError) as error:
            graph = graph.merge(DependencyGraph(errors=(f"{path}: {error}",)))
            continue
        graph = graph.merge(parse_dependencies(sources.add_source(str(path), text)))
    return graph


def analyze_project(
    root: Path,
    plugin_roots: Sequence[Path] = (),
    plugins: Sequence[Plugin] = (),
    cache: ProjectCache | None = None,
    jobs: int = 1,
    advisory_files: Sequence[Path] = (),
    policy_file: Path | None = None,
) -> ProjectAnalysis:
    """Analyse every Python file under ``root`` with a shared summary index (§21) and the
    dependency graph of its manifests (§26). ``plugins`` adds plugin instances to the
    ones discovered under ``plugin_roots``. With a ``cache``, modules whose key is
    unchanged since a previous run are served from it (§11). Modules are scheduled by
    strongly connected components of the module graph, imports first; with ``jobs``
    above one the components of a wave are analysed in that many processes (§29).
    ``advisory_files`` add to the ``advisories.json`` at ``root``; ``policy_file``
    replaces the ``coretrace-policy.toml`` there."""

    if jobs < 1:
        raise ValueError("jobs must be at least 1")
    sources = SourceManager()
    findings: list[Finding] = []
    dependencies = resolve_dependencies(root, sources)
    for error in dependencies.errors:
        findings.append(_note("syntax-error", error, sources.add_source(error.split(":")[0], ""), 1))
    advisory_paths = _advisory_paths(root, advisory_files)
    file_advisories: list[tuple[Path, tuple[Advisory, ...]]] = []
    for path in advisory_paths:
        try:
            file_advisories.append((path, load_advisories(path)))
        except AdvisoryFileError as error:
            findings.append(_note("syntax-error", str(error), sources.add_source(str(path), ""), 1))
    policy = Policy()
    policy_path = policy_file if policy_file is not None else root / POLICY_FILE
    if policy_path.is_file():
        try:
            policy = load_policy(policy_path)
        except AdvisoryFileError as error:
            findings.append(_note("syntax-error", str(error), sources.add_source(str(policy_path), ""), 1))
    modules: dict[str, nodes.Module] = {}
    files: dict[str, SourceFile] = {}
    unreadable: list[tuple[Path, str]] = []
    coverage: list[FileCoverage] = []
    discovered = discover_sources(root, sources, unreadable)
    for path, reason in unreadable:
        findings.append(_note("syntax-error", f"{path}: {reason}", sources.add_source(str(path), ""), 1))
        coverage.append(FileCoverage(str(path), "unreadable", 0, 0))
    for source in discovered:
        try:
            modules[source.module_name] = build_hir(source)
        except (ParseError, HIRBuildError) as error:
            findings.append(_note("syntax-error", str(error), source, 1))
            coverage.append(FileCoverage(str(source.source_id), "syntax-error", 0, 0))
            continue
        files[source.module_name] = source

    managers = {name: _register_all(module) for name, module in modules.items()}
    probe = next(iter(managers.values()), None) or _register_all(build_hir(sources.add_source("<empty>", "")))
    registry = load_plugins(plugin_roots, probe)
    all_plugins: tuple[Plugin, ...] = (*(loaded.plugin for loaded in registry), *plugins)
    components = _components(registry, root, (path for path, _ in file_advisories))
    advisories, origins = _merge_advisories(_contributions(registry, plugins, root, file_advisories))
    affected = affected_symbols(dependencies, advisories)
    models = plugin_models(all_plugins, root).extended(*advisory_sinks(affected))
    members = models.members_by_class()
    for manager in managers.values():
        manager.provide(SecurityModelAnalysis, models)
        manager.provide(MembersAnalysis, members)
        manager.provide(DependencyAnalysis, dependencies)

    imports: dict[str, ImportTable] = {}
    analysable: dict[str, AnalysisManager] = {}
    for name, manager in managers.items():
        try:
            imports[name] = manager.get(ImportAnalysis)
        except (ImportResolutionError, ScopeError) as error:
            findings.append(_note("syntax-error", str(error), files[name], 1))
            coverage.append(FileCoverage(str(files[name].source_id), "syntax-error", 0, 0))
            continue
        analysable[name] = manager
    graph = build_module_graph(
        {name: files[name] for name in analysable}, {name: modules[name] for name in analysable}, imports
    )
    routes: dict[SymbolId, EntryPoint] = {}
    for name in sorted(analysable):
        for symbol, registered in _routes_of(analysable[name]).items():
            routes.setdefault(symbol, registered)
    escaped = escaped_templates(root)
    clearing = models.clearing(escaped)
    for manager in analysable.values():
        manager.provide(RegisteredRoutes, routes)
        manager.provide(EscapedTemplates, escaped)
        manager.provide(ClearingAnalysis, clearing)

    configuration = _configuration_key(components, plugins, models, advisories, dependencies, routes, escaped)
    keys = module_keys(
        graph,
        {name: fingerprint(configuration, str(files[name].source_id), name, files[name].text) for name in analysable},
    )
    results: dict[str, CachedModule] = {}
    if cache is not None:
        for name in analysable:
            entry = cache.load(keys[name])
            if entry is not None:
                results[name] = entry
    reused = tuple(sorted(results))

    module_plugins = tuple(p for p in all_plugins if not isinstance(p, ProjectPlugin))
    pool = None
    if jobs > 1:
        pool = concurrent.futures.ProcessPoolExecutor(
            max_workers=jobs, mp_context=multiprocessing.get_context("spawn")
        )
    try:
        for wave in graph.schedule():
            pending = [c for c in wave if any(m not in results for m in c)]
            computed: dict[str, CachedModule] = {}
            if pool is None:
                for component in pending:
                    batch = {name: analysable[name] for name in sorted(component)}
                    computed.update(_analyse_managers(batch, _seed(results, graph, component), module_plugins, affected))
                    for manager in batch.values():
                        manager.run(ResultsEvicted)
            else:
                futures = [
                    pool.submit(
                        _analyse_batch,
                        _Batch(
                            root,
                            tuple(plugin_roots),
                            tuple(plugins),
                            {name: _path_of(files[name]) for name in sorted(component)},
                            encode_index(_seed(results, graph, component)),
                            advisory_paths,
                            _encode_routes(routes),
                            tuple(sorted(escaped)),
                        ),
                    )
                    for component in pending
                ]
                for future in futures:
                    computed.update({name: decode(data) for name, data in future.result().items()})
            for name, entry in computed.items():
                if cache is not None:
                    cache.store(keys[name], entry)
            results.update(computed)
    finally:
        if pool is not None:
            pool.shutdown()

    index = _seed(results, graph, frozenset())
    call_graphs: dict[str, CallGraph] = {}
    functions: dict[str, tuple[ModuleFunction, ...]] = {}
    for name in sorted(analysable):
        entry = results[name]
        findings.extend(entry.findings)
        unsupported = sum(1 for f in entry.findings if f.rule_id == "unsupported-syntax")
        coverage.append(
            FileCoverage(str(files[name].source_id), "analysed", len(entry.functions), len(entry.functions) - unsupported)
        )
        functions[name] = entry.functions
        sites: dict[str, list[CallSite]] = {function.name: [] for function in entry.functions}
        for site in entry.sites:
            sites.setdefault(site.caller, []).append(site)
        reads: dict[str, list[SymbolRead]] = {}
        for read in entry.reads:
            reads.setdefault(read.function, []).append(read)
        call_graphs[name] = CallGraph(
            {},
            {f: tuple(s) for f, s in sites.items()},
            frozenset(),
            reads={f: tuple(r) for f, r in reads.items()},
        )
    context = ProjectContext(graph, dependencies, advisories, analysable, call_graphs, policy, root, functions)
    for plugin in all_plugins:
        if isinstance(plugin, ProjectPlugin):
            findings.extend(plugin.analyze_project(context))
    for plugin in all_plugins:
        if isinstance(plugin, ProjectPlugin):
            findings = list(apply_refinement(plugin, findings, plugin.refine(context, tuple(findings))))
    findings = [_sourced(finding, origins) for finding in findings]
    accepted = tuple(f for f in findings if policy.accepts(f))
    kept, suppressed = partition(apply_policy(policy, findings), _text_of(sources))
    return ProjectAnalysis(
        graph,
        index,
        kept,
        dependencies,
        MappingProxyType(keys),
        reused,
        advisories,
        Coverage(tuple(sorted(coverage, key=lambda c: c.path))),
        suppressed,
        accepted,
        components,
    )


Origins = Mapping[tuple[str, str], str]


def _merge_advisories(contributions: Iterable[tuple[str, Iterable[Advisory]]]) -> tuple[tuple[Advisory, ...], Origins]:
    """One advisory per identifier and package, with the contributor it comes from: a
    later contributor replaces an earlier one, so a curated plugin refines a bundled
    sample and a local file, the project's own feed, wins over every plugin."""

    merged: dict[tuple[str, str], tuple[str, Advisory]] = {}
    for source, advisories in contributions:
        for advisory in advisories:
            merged[(advisory.id, advisory.package)] = (source, advisory)
    return (
        tuple(advisory for _, advisory in merged.values()),
        MappingProxyType({key: source for key, (source, _) in merged.items()}),
    )


def _contributions(
    registry: PluginRegistry,
    plugins: Sequence[Plugin],
    root: Path,
    files: Iterable[tuple[Path, tuple[Advisory, ...]]],
) -> list[tuple[str, Iterable[Advisory]]]:
    """The advisories of each plugin, then of each advisory file, each under the name a
    finding cites it by: ``name@version`` for a loaded plugin, the path for a file."""

    return [
        *((f"{loaded.manifest.name}@{loaded.manifest.version}", loaded.plugin.advisories) for loaded in registry),
        *((plugin.name, plugin.advisories) for plugin in plugins),
        *((_located(path, root), advisories) for path, advisories in files),
    ]


def _components(registry: PluginRegistry, root: Path, files: Iterable[Path]) -> tuple[Component, ...]:
    """The plugins and advisory files a project result is produced with, each with the
    digest of its content: the plugin directory as the cache fingerprints it, the file's
    bytes."""

    return (
        *(
            Component(PLUGIN, loaded.manifest.name, f"sha256:{directory_fingerprint(loaded.directory)}", loaded.manifest.version)
            for loaded in registry
        ),
        *(
            Component(ADVISORIES, _located(path, root), f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}")
            for path in files
        ),
    )


def _located(path: Path, root: Path) -> str:
    """``path`` relative to ``root``, POSIX style, when it lies under it."""

    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _sourced(finding: Finding, origins: Origins) -> Finding:
    """``finding`` with the plugin or advisory file its advisory comes from, when it
    cites one."""

    origin = origins.get((finding.metadata.get("advisory", ""), finding.metadata.get("package", "")))
    if origin is None:
        return finding
    return replace(finding, metadata={**finding.metadata, "advisory_source": origin})


def _advisory_paths(root: Path, advisory_files: Sequence[Path]) -> tuple[Path, ...]:
    """The advisory file at ``root``, when present, then the explicit ones."""

    default = root / ADVISORY_FILE
    return (*([default] if default.is_file() else []), *advisory_files)


def _seed(results: Mapping[str, CachedModule], graph: ModuleGraph, component: frozenset[str]) -> SummaryIndex:
    """The summaries a component starts from: those of every module it imports,
    transitively, all final by the time its wave runs; the whole index for no component."""

    if component:
        wanted: set[str] = set()
        pending = list(component)
        while pending:
            for imported in graph.imports(pending.pop()):
                if imported in results and imported not in wanted:
                    wanted.add(imported)
                    pending.append(imported)
    else:
        wanted = set(results)
    return SummaryIndex(
        {
            project_symbol(name, function): summary
            for name in sorted(wanted)
            for function, summary in results[name].summaries.items()
        }
    )


def _analyse_managers(
    managers: Mapping[str, AnalysisManager],
    seed: SummaryIndex,
    plugins: tuple[Plugin, ...],
    affected: Affected,
) -> dict[str, CachedModule]:
    """Analyse one component: iterate its summaries to a fixpoint over ``seed`` (§21),
    then extract what the rest of the run needs from each module."""

    index = seed
    for manager in managers.values():
        manager.provide(ProjectSummaries, index)
    for _ in range(MAX_PROJECT_ITERATIONS):
        updated = SummaryIndex(
            {
                **seed.summaries,
                **{
                    project_symbol(name, function): summary
                    for name, manager in managers.items()
                    for function, summary in _summaries_of(manager).items()
                },
            }
        )
        if updated == index:
            break
        index = updated
        for manager in managers.values():
            manager.run(ProjectSummariesUpdated)
            manager.provide(ProjectSummaries, index)
    return {name: _analyse_module(manager, plugins, affected) for name, manager in managers.items()}


@dataclass(frozen=True)
class _Batch:
    """One component handed to a worker process: it rebuilds the configuration from the
    project root and the plugin roots, so only paths and the imported summaries travel."""

    root: Path
    plugin_roots: tuple[Path, ...]
    plugins: tuple[Plugin, ...]
    paths: Mapping[str, Path]
    seed: Mapping[str, Any]
    advisory_paths: tuple[Path, ...] = ()
    routes: tuple[tuple[str, str, str, int], ...] = ()
    escaped: tuple[str, ...] = ()


def _analyse_batch(batch: _Batch) -> dict[str, dict[str, Any]]:
    sources = SourceManager()
    managers = {name: _register_all(build_hir(sources.load_file(path))) for name, path in batch.paths.items()}
    registry = load_plugins(batch.plugin_roots, next(iter(managers.values())))
    all_plugins: tuple[Plugin, ...] = (*(loaded.plugin for loaded in registry), *batch.plugins)
    dependencies = resolve_dependencies(batch.root, sources)
    file_advisories: list[tuple[Path, tuple[Advisory, ...]]] = []
    for path in batch.advisory_paths:
        try:
            file_advisories.append((path, load_advisories(path)))
        except AdvisoryFileError:
            continue
    advisories, _ = _merge_advisories(_contributions(registry, batch.plugins, batch.root, file_advisories))
    affected = affected_symbols(dependencies, advisories)
    models = plugin_models(all_plugins, batch.root).extended(*advisory_sinks(affected))
    routes = _decode_routes(batch.routes)
    escaped = frozenset(batch.escaped)
    members = models.members_by_class()
    for manager in managers.values():
        manager.provide(SecurityModelAnalysis, models)
        manager.provide(MembersAnalysis, members)
        manager.provide(DependencyAnalysis, dependencies)
        manager.provide(RegisteredRoutes, routes)
        manager.provide(EscapedTemplates, escaped)
        manager.provide(ClearingAnalysis, models.clearing(escaped))
    module_plugins = tuple(p for p in all_plugins if not isinstance(p, ProjectPlugin))
    results = _analyse_managers(managers, decode_index(batch.seed), module_plugins, affected)
    return {name: encode(entry) for name, entry in results.items()}


def _path_of(source: SourceFile) -> Path:
    assert source.path is not None, "project sources are loaded from files"
    return source.path


def _encode_routes(routes: Routes) -> tuple[tuple[str, str, str, int], ...]:
    return tuple(
        sorted((str(symbol), str(entry.symbol), entry.label, entry.kinds.value) for symbol, entry in routes.items())
    )


def _decode_routes(data: tuple[tuple[str, str, str, int], ...]) -> dict[SymbolId, EntryPoint]:
    return {SymbolId(symbol): EntryPoint(SymbolId(registrar), label, TaintKind(kinds)) for symbol, registrar, label, kinds in data}


def _configuration_key(
    components: Sequence[Component],
    plugins: Sequence[Plugin],
    models: ModelTable,
    advisories: tuple[Advisory, ...],
    dependencies: DependencyGraph,
    routes: Routes | None = None,
    escaped: frozenset[str] = frozenset(),
) -> str:
    """Everything a module's results depend on besides the project sources (§11)."""

    return fingerprint(
        __version__,
        str(HIR_SCHEMA_VERSION),
        str(PYIR_SCHEMA_VERSION),
        str(FINDING_SCHEMA_VERSION),
        str(PLUGIN_API_VERSION),
        *(f"{c.name}={c.version}:{c.digest}" for c in components if c.kind == PLUGIN),
        *(f"{type(p).__module__}.{type(p).__qualname__}" for p in plugins),
        repr(models),
        repr(advisories),
        repr(dependencies.requirements),
        repr(dependencies.errors),
        repr(_encode_routes(routes or {})),
        repr(sorted(escaped)),
    )


def _analyse_module(
    manager: AnalysisManager, plugins: tuple[Plugin, ...], affected: Affected
) -> CachedModule:
    """One module's findings, summaries, call sites and symbol reads: what the cache
    keeps (§11)."""

    findings, supported = _check_module(manager, plugins)
    graph = manager.get(CallGraphAnalysis)
    correlated: list[Finding] = []
    if affected:
        strings = manager.get(ModuleStringsAnalysis)
        for function in supported:
            flows = manager.get(TaintAnalysis, function).flows
            ssa = manager.get(SSAAnalysis, function)
            defs = {i.result: i for block in ssa.blocks for i in block.instructions if i.result is not None}
            urls = {flow: flow_url(flow, defs, strings) for flow in flows if flow.kinds & TaintKind.ADVISORY}
            correlated.extend(
                correlate(graph.name_of(function), flows, manager.get(RefutationAnalysis, function), affected, urls)
            )
    return CachedModule(
        manager.get(EntryPointAnalysis),
        _summaries_of(manager),
        tuple(site for function in graph.functions for site in graph.sites(function)),
        (*findings, *correlated),
        tuple(read for function in graph.functions for read in graph.reads(function)),
    )


def _summaries_of(manager: AnalysisManager) -> dict[str, FunctionSummary]:
    table = manager.get(SummaryAnalysis)
    return {name: table.summary(name) for name in table.names}


def _check_module(
    manager: AnalysisManager, plugins: tuple[Plugin, ...]
) -> tuple[tuple[Finding, ...], tuple[nodes.Function, ...]]:
    """Findings of the module plugins plus notes for unsupported functions, and the
    functions that could be analysed."""

    supported: list[nodes.Function] = []
    notes: list[Finding] = []
    for function in analyzable_functions(manager.module):
        try:
            manager.get(SSAAnalysis, function)
        except (LoweringError, CFGError) as error:
            notes.append(
                Finding(
                    rule_id="unsupported-syntax",
                    message=str(error),
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    span=function.span,
                    function=function.name,
                )
            )
        else:
            supported.append(function)
    findings = run_plugins(manager, plugins, tuple(supported))
    return (*findings, *notes), tuple(supported)


def _note(rule_id: str, message: str, source: SourceFile, line: int) -> Finding:
    return Finding(
        rule_id=rule_id,
        message=message,
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        span=SourceSpan(source.source_id, line, 1),
    )


def _register_all(module: nodes.Module) -> AnalysisManager:
    manager = AnalysisManager(module)
    manager.register(*ALL_ANALYSES)
    return manager


def report(
    findings: Sequence[Finding],
    coverage: Coverage | None = None,
    root: Path | None = None,
    suppressed: Sequence[Finding] = (),
    baselined: Sequence[Finding] | None = None,
    components: Sequence[Component] = (),
) -> Report:
    """The report of a check; paths under ``root`` are rendered relative to it.
    ``baselined`` is the findings a baseline accounts for, ``None`` when none applied."""

    return Report(
        tuple(findings),
        TOOL_NAME,
        __version__,
        coverage,
        root,
        tuple(suppressed),
        tuple(baselined or ()),
        baselined is not None,
        tuple(components),
    )
