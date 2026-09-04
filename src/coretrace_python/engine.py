"""Composition root: the full analysis DAG, plugin loading and one check run.

This is the only module that knows every layer. The CLI and future hosts call it;
plugins and analyses never import it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import ClassVar

from coretrace_python import __version__
from coretrace_python.abstract import ConstantPropagation
from coretrace_python.analysis import (
    AnalysisContext,
    AnalysisManager,
    AnyAnalysis,
    TransformationPass,
)
from coretrace_python.cache import (
    CachedModule,
    ProjectCache,
    directory_fingerprint,
    fingerprint,
    module_keys,
)
from coretrace_python.cfg import CFGAnalysis, CFGError, DominanceAnalysis, PostDominanceAnalysis
from coretrace_python.dependency import (
    DEPENDENCY_FILES,
    Advisory,
    DependencyAnalysis,
    DependencyGraph,
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
) -> ProjectAnalysis:
    """Analyse every Python file under ``root`` with a shared summary index (§21) and the
    dependency graph of its manifests (§26). ``plugins`` adds plugin instances to the
    ones discovered under ``plugin_roots``. With a ``cache``, modules whose key is
    unchanged since a previous run are served from it (§11)."""

    sources = SourceManager()
    findings: list[Finding] = []
    dependencies = resolve_dependencies(root, sources)
    for error in dependencies.errors:
        findings.append(_note("syntax-error", error, sources.add_source(error.split(":")[0], ""), 1))
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
    advisories = tuple(a for plugin in all_plugins for a in plugin.advisories)
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
    cached: dict[str, CachedModule] = {}
    if cache is not None:
        for name in analysable:
            entry = cache.load(keys[name])
            if entry is not None:
                cached[name] = entry
    fresh = {name: manager for name, manager in analysable.items() if name not in cached}

    index = SummaryIndex()
    cached_summaries = {
        project_symbol(name, function): summary
        for name, entry in cached.items()
        for function, summary in entry.summaries.items()
    }
    for manager in fresh.values():
        manager.provide(ProjectSummaries, index)
    for _ in range(MAX_PROJECT_ITERATIONS):
        updated = SummaryIndex(
            {
                **cached_summaries,
                **{
                    project_symbol(name, function): summary
                    for name, manager in fresh.items()
                    for function, summary in _summaries_of(manager).items()
                },
            }
        )
        if updated == index:
            break
        index = updated
        for manager in fresh.values():
            manager.run(ProjectSummariesUpdated)
            manager.provide(ProjectSummaries, index)

    module_plugins = tuple(p for p in all_plugins if not isinstance(p, ProjectPlugin))
    call_graphs: dict[str, CallGraph] = {}
    for name in sorted(analysable):
        entry = cached.get(name)
        if entry is None:
            entry = _analyse_module(analysable[name], module_plugins, affected)
            if cache is not None:
                cache.store(keys[name], entry)
        else:
            sites: dict[str, list[CallSite]] = {function: [] for function in entry.functions}
            for site in entry.sites:
                sites.setdefault(site.caller, []).append(site)
            call_graphs[name] = CallGraph({}, {f: tuple(s) for f, s in sites.items()}, frozenset())
        findings.extend(entry.findings)
    context = ProjectContext(graph, dependencies, advisories, analysable, call_graphs)
    for plugin in all_plugins:
        if isinstance(plugin, ProjectPlugin):
            findings.extend(plugin.analyze_project(context))
    return ProjectAnalysis(
        graph, index, tuple(findings), dependencies, MappingProxyType(keys), tuple(sorted(cached))
    )


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
