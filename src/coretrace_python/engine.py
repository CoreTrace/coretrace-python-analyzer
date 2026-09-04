"""Composition root: the full analysis DAG, plugin loading and one check run.

This is the only module that knows every layer. The CLI and future hosts call it;
plugins and analyses never import it.
"""

from __future__ import annotations

import concurrent.futures
import multiprocessing
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, ClassVar

from coretrace_python import __version__
from coretrace_python.abstract import ConstantPropagation, HeapAnalysis, RangeAnalysis
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
from coretrace_python.dependency.correlation import advisory_sinks, affected_symbols, correlate
from coretrace_python.findings import FINDING_SCHEMA_VERSION, Confidence, Finding, Severity
from coretrace_python.findings.refutation import RefutationAnalysis
from coretrace_python.frontend import HIRBuildError, ParseError, build_hir
from coretrace_python.hir import HIR_SCHEMA_VERSION, nodes
from coretrace_python.interprocedural import (
    CallGraph,
    CallGraphAnalysis,
    CallSite,
    FunctionSummary,
    ModuleGraph,
    ProjectSummaries,
    SummaryAnalysis,
    SummaryIndex,
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
    discover_plugins,
    run_plugins,
)
from coretrace_python.reporters import Report
from coretrace_python.semantic import SEMANTIC_ANALYSES
from coretrace_python.semantic.imports import ImportAnalysis, ImportResolutionError, ImportTable
from coretrace_python.semantic.scopes import ScopeError
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceFile, SourceManager, SourceSpan
from coretrace_python.taint import (
    ModelTable,
    SecurityModelAnalysis,
    SecurityModelRegistry,
    TaintAnalysis,
)

TOOL_NAME = "coretrace-python-analyzer"

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
    HeapAnalysis,
    CallGraphAnalysis,
    SummaryAnalysis,
    ProjectSummaries,
    SecurityModelAnalysis,
    TaintAnalysis,
    RefutationAnalysis,
    DependencyAnalysis,
)


# Named so the set stays right whichever analyses a build registers.
_PROJECT_DEPENDANT_NAMES = frozenset(
    {"interprocedural.project", "interprocedural.summaries", "taint.flows", "findings.refutation"}
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
        {*SEMANTIC_ANALYSES, SecurityModelAnalysis, ProjectSummaries, DependencyAnalysis}
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


def build_manager(
    module: nodes.Module, models: SecurityModelRegistry | None = None
) -> AnalysisManager:
    """A manager with every engine analysis registered and the engine inputs provided."""

    manager = _register_all(module)
    manager.provide(SecurityModelAnalysis, (models or SecurityModelRegistry()).freeze())
    manager.provide(ProjectSummaries, SummaryIndex())
    return manager


def load_plugins(plugin_roots: Sequence[Path], manager: AnalysisManager) -> PluginRegistry:
    registry = PluginRegistry()
    for root in plugin_roots:
        for loaded in discover_plugins(root, manager):
            registry.add(loaded)
    return registry


def plugin_models(plugins: Iterable[Plugin]) -> ModelTable:
    models = SecurityModelRegistry()
    for plugin in plugins:
        models.register(*plugin.models)
    return models.freeze()


def check(source: SourceFile, plugin_roots: Sequence[Path]) -> tuple[Finding, ...]:
    """Run every plugin found under ``plugin_roots`` against one file."""

    manager = _register_all(build_hir(source))
    registry = load_plugins(plugin_roots, manager)
    manager.provide(SecurityModelAnalysis, plugin_models(loaded.plugin for loaded in registry))
    manager.provide(ProjectSummaries, SummaryIndex())
    return _check_module(manager, tuple(loaded.plugin for loaded in registry))[0]


def resolve_dependencies(root: Path, sources: SourceManager) -> DependencyGraph:
    """The requirements declared or pinned by the dependency files at ``root`` (§26)."""

    graph = DependencyGraph()
    candidates = sorted(root.glob("requirements*.txt")) + [root / name for name in DEPENDENCY_FILES]
    for path in candidates:
        if path.is_file():
            graph = graph.merge(parse_dependencies(sources.load_file(path)))
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
    file_advisories: list[Advisory] = []
    for path in advisory_paths:
        try:
            file_advisories.extend(load_advisories(path))
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
    for source in discover_sources(root, sources):
        try:
            modules[source.module_name] = build_hir(source)
        except (ParseError, HIRBuildError) as error:
            findings.append(_note("syntax-error", str(error), source, 1))
            continue
        files[source.module_name] = source

    managers = {name: _register_all(module) for name, module in modules.items()}
    probe = next(iter(managers.values()), None) or _register_all(build_hir(sources.add_source("<empty>", "")))
    registry = load_plugins(plugin_roots, probe)
    all_plugins: tuple[Plugin, ...] = (*(loaded.plugin for loaded in registry), *plugins)
    advisories = _merge_advisories(
        (a for plugin in all_plugins for a in plugin.advisories), file_advisories
    )
    affected = affected_symbols(dependencies, advisories)
    models = plugin_models(all_plugins).extended(*advisory_sinks(affected))
    for manager in managers.values():
        manager.provide(SecurityModelAnalysis, models)
        manager.provide(DependencyAnalysis, dependencies)

    imports: dict[str, ImportTable] = {}
    analysable: dict[str, AnalysisManager] = {}
    for name, manager in managers.items():
        try:
            imports[name] = manager.get(ImportAnalysis)
        except (ImportResolutionError, ScopeError) as error:
            findings.append(_note("syntax-error", str(error), files[name], 1))
            continue
        analysable[name] = manager
    graph = build_module_graph(
        {name: files[name] for name in analysable}, {name: modules[name] for name in analysable}, imports
    )

    configuration = _configuration_key(registry, plugins, models, advisories, dependencies)
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
    for name in sorted(analysable):
        entry = results[name]
        findings.extend(entry.findings)
        sites: dict[str, list[CallSite]] = {function: [] for function in entry.functions}
        for site in entry.sites:
            sites.setdefault(site.caller, []).append(site)
        call_graphs[name] = CallGraph({}, {f: tuple(s) for f, s in sites.items()}, frozenset())
    context = ProjectContext(graph, dependencies, advisories, analysable, call_graphs, policy)
    for plugin in all_plugins:
        if isinstance(plugin, ProjectPlugin):
            findings.extend(plugin.analyze_project(context))
    return ProjectAnalysis(
        graph,
        index,
        apply_policy(policy, findings),
        dependencies,
        MappingProxyType(keys),
        reused,
        advisories,
    )


def _merge_advisories(
    from_plugins: Iterable[Advisory], from_files: Iterable[Advisory]
) -> tuple[Advisory, ...]:
    """One advisory per identifier, package and range; a local file's version wins over
    a plugin's, since the file is the project's own curated feed."""

    merged: dict[tuple[str, str, str], Advisory] = {}
    for advisory in (*from_plugins, *from_files):
        merged[(advisory.id, advisory.package, advisory.vulnerable)] = advisory
    return tuple(merged.values())


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
    affected: Mapping[SymbolId, Advisory],
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


def _analyse_batch(batch: _Batch) -> dict[str, dict[str, Any]]:
    sources = SourceManager()
    managers = {name: _register_all(build_hir(sources.load_file(path))) for name, path in batch.paths.items()}
    registry = load_plugins(batch.plugin_roots, next(iter(managers.values())))
    all_plugins: tuple[Plugin, ...] = (*(loaded.plugin for loaded in registry), *batch.plugins)
    dependencies = resolve_dependencies(batch.root, sources)
    file_advisories: list[Advisory] = []
    for path in batch.advisory_paths:
        try:
            file_advisories.extend(load_advisories(path))
        except AdvisoryFileError:
            continue
    advisories = _merge_advisories(
        (a for plugin in all_plugins for a in plugin.advisories), file_advisories
    )
    affected = affected_symbols(dependencies, advisories)
    models = plugin_models(all_plugins).extended(*advisory_sinks(affected))
    for manager in managers.values():
        manager.provide(SecurityModelAnalysis, models)
        manager.provide(DependencyAnalysis, dependencies)
    module_plugins = tuple(p for p in all_plugins if not isinstance(p, ProjectPlugin))
    results = _analyse_managers(managers, decode_index(batch.seed), module_plugins, affected)
    return {name: encode(entry) for name, entry in results.items()}


def _path_of(source: SourceFile) -> Path:
    assert source.path is not None, "project sources are loaded from files"
    return source.path


def _configuration_key(
    registry: PluginRegistry,
    plugins: Sequence[Plugin],
    models: ModelTable,
    advisories: tuple[Advisory, ...],
    dependencies: DependencyGraph,
) -> str:
    """Everything a module's results depend on besides the project sources (§11)."""

    return fingerprint(
        __version__,
        str(HIR_SCHEMA_VERSION),
        str(PYIR_SCHEMA_VERSION),
        str(FINDING_SCHEMA_VERSION),
        str(PLUGIN_API_VERSION),
        *(
            f"{loaded.manifest.name}={loaded.manifest.version}:{directory_fingerprint(loaded.directory)}"
            for loaded in registry
        ),
        *(f"{type(p).__module__}.{type(p).__qualname__}" for p in plugins),
        repr(models),
        repr(advisories),
        repr(dependencies.requirements),
        repr(dependencies.errors),
    )


def _analyse_module(
    manager: AnalysisManager, plugins: tuple[Plugin, ...], affected: Mapping[SymbolId, Advisory]
) -> CachedModule:
    """One module's findings, summaries and call sites: what the cache keeps (§11)."""

    findings, supported = _check_module(manager, plugins)
    graph = manager.get(CallGraphAnalysis)
    correlated: list[Finding] = []
    if affected:
        for function in supported:
            correlated.extend(
                correlate(
                    graph.name_of(function),
                    manager.get(TaintAnalysis, function).flows,
                    manager.get(RefutationAnalysis, function),
                    affected,
                )
            )
    return CachedModule(
        graph.functions,
        _summaries_of(manager),
        tuple(site for function in graph.functions for site in graph.sites(function)),
        (*findings, *correlated),
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


def report(findings: Sequence[Finding]) -> Report:
    return Report(tuple(findings), TOOL_NAME, __version__)
