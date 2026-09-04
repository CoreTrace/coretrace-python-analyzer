"""Composition root: the full analysis DAG, plugin loading and one check run.

This is the only module that knows every layer. The CLI and future hosts call it;
plugins and analyses never import it.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from coretrace_python import __version__
from coretrace_python.abstract import ConstantPropagation
from coretrace_python.analysis import (
    AnalysisContext,
    AnalysisManager,
    AnyAnalysis,
    TransformationPass,
)
from coretrace_python.cfg import CFGAnalysis, CFGError, DominanceAnalysis, PostDominanceAnalysis
from coretrace_python.dependency import (
    DEPENDENCY_FILES,
    DependencyAnalysis,
    DependencyGraph,
    parse_dependencies,
)
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.findings.refutation import RefutationAnalysis
from coretrace_python.frontend import HIRBuildError, ParseError, build_hir
from coretrace_python.hir import nodes
from coretrace_python.interprocedural import (
    CallGraphAnalysis,
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


@dataclass(frozen=True)
class ProjectAnalysis:
    graph: ModuleGraph
    index: SummaryIndex
    findings: tuple[Finding, ...]
    dependencies: DependencyGraph = field(default_factory=DependencyGraph)


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
    return _check_module(manager, tuple(loaded.plugin for loaded in registry))


def resolve_dependencies(root: Path, sources: SourceManager) -> DependencyGraph:
    """The requirements declared or pinned by the dependency files at ``root`` (§26)."""

    graph = DependencyGraph()
    candidates = sorted(root.glob("requirements*.txt")) + [root / name for name in DEPENDENCY_FILES]
    for path in candidates:
        if path.is_file():
            graph = graph.merge(parse_dependencies(sources.load_file(path)))
    return graph


def analyze_project(
    root: Path, plugin_roots: Sequence[Path] = (), plugins: Sequence[Plugin] = ()
) -> ProjectAnalysis:
    """Analyse every Python file under ``root`` with a shared summary index (§21) and the
    dependency graph of its manifests (§26). ``plugins`` adds plugin instances to the
    ones discovered under ``plugin_roots``."""

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
    models = plugin_models(all_plugins)
    advisories = tuple(a for plugin in all_plugins for a in plugin.advisories)
    index = SummaryIndex()
    for manager in managers.values():
        manager.provide(SecurityModelAnalysis, models)
        manager.provide(ProjectSummaries, index)
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

    for _ in range(MAX_PROJECT_ITERATIONS):
        updated = SummaryIndex(
            {
                project_symbol(name, function): summary
                for name, manager in analysable.items()
                for function, summary in _summaries_of(manager).items()
            }
        )
        if updated == index:
            break
        index = updated
        for manager in analysable.values():
            manager.run(ProjectSummariesUpdated)
            manager.provide(ProjectSummaries, index)

    module_plugins = tuple(p for p in all_plugins if not isinstance(p, ProjectPlugin))
    for name in sorted(analysable):
        findings.extend(_check_module(analysable[name], module_plugins))
    context = ProjectContext(graph, dependencies, advisories, analysable)
    for plugin in all_plugins:
        if isinstance(plugin, ProjectPlugin):
            findings.extend(plugin.analyze_project(context))
    return ProjectAnalysis(graph, index, tuple(findings), dependencies)


def _summaries_of(manager: AnalysisManager) -> dict[str, FunctionSummary]:
    table = manager.get(SummaryAnalysis)
    return {name: table.summary(name) for name in table.names}


def _check_module(manager: AnalysisManager, plugins: tuple[Plugin, ...]) -> tuple[Finding, ...]:
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
    return (*findings, *notes)


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
