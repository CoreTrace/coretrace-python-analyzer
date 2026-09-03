"""Composition root: the full analysis DAG, plugin loading and one check run.

This is the only module that knows every layer. The CLI and future hosts call it;
plugins and analyses never import it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
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
from coretrace_python.plugins import LoadedPlugin, PluginRegistry, discover_plugins, run_plugins
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


def plugin_models(registry: PluginRegistry) -> ModelTable:
    models = SecurityModelRegistry()
    for loaded in registry:
        models.register(*loaded.plugin.models)
    return models.freeze()


def check(source: SourceFile, plugin_roots: Sequence[Path]) -> tuple[Finding, ...]:
    """Run every plugin found under ``plugin_roots`` against one file."""

    manager = _register_all(build_hir(source))
    registry = load_plugins(plugin_roots, manager)
    manager.provide(SecurityModelAnalysis, plugin_models(registry))
    manager.provide(ProjectSummaries, SummaryIndex())
    return _check_module(manager, tuple(registry))


def analyze_project(root: Path, plugin_roots: Sequence[Path] = ()) -> ProjectAnalysis:
    """Analyse every Python file under ``root`` with a shared summary index (§21)."""

    sources = SourceManager()
    findings: list[Finding] = []
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
    models = plugin_models(registry)
    index = SummaryIndex()
    for manager in managers.values():
        manager.provide(SecurityModelAnalysis, models)
        manager.provide(ProjectSummaries, index)

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

    plugins = tuple(registry)
    for name in sorted(analysable):
        findings.extend(_check_module(analysable[name], plugins))
    return ProjectAnalysis(graph, index, tuple(findings))


def _summaries_of(manager: AnalysisManager) -> dict[str, FunctionSummary]:
    table = manager.get(SummaryAnalysis)
    return {name: table.summary(name) for name in table.names}


def _check_module(manager: AnalysisManager, plugins: tuple[LoadedPlugin, ...]) -> tuple[Finding, ...]:
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
    findings = run_plugins(manager, [loaded.plugin for loaded in plugins], tuple(supported))
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
