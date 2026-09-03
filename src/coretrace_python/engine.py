"""Composition root: the full analysis DAG, plugin loading and one check run.

This is the only module that knows every layer. The CLI and future hosts call it;
plugins and analyses never import it.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from coretrace_python import __version__
from coretrace_python.abstract import ConstantPropagation
from coretrace_python.analysis import AnalysisManager, AnyAnalysis
from coretrace_python.cfg import CFGAnalysis, CFGError, DominanceAnalysis, PostDominanceAnalysis
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.interprocedural import CallGraphAnalysis, SummaryAnalysis
from coretrace_python.ir.defuse import DefUseAnalysis
from coretrace_python.ir.lowering import (
    LoweringError,
    ModuleIRAnalysis,
    PyIRAnalysis,
    analyzable_functions,
)
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.plugins import PluginRegistry, discover_plugins, run_plugins
from coretrace_python.reporters import Report
from coretrace_python.semantic import SEMANTIC_ANALYSES
from coretrace_python.source import SourceFile
from coretrace_python.taint import SecurityModelAnalysis, SecurityModelRegistry, TaintAnalysis

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
    SecurityModelAnalysis,
    TaintAnalysis,
)


def build_manager(
    module: nodes.Module, models: SecurityModelRegistry | None = None
) -> AnalysisManager:
    """A manager with every engine analysis registered and the security models provided."""

    manager = _register_all(module)
    manager.provide(SecurityModelAnalysis, (models or SecurityModelRegistry()).freeze())
    return manager


def check(source: SourceFile, plugin_roots: Sequence[Path]) -> tuple[Finding, ...]:
    """Run every plugin found under ``plugin_roots`` against ``source``.

    Plugins are loaded first so the models they contribute are all registered before the
    table is provided; framework models and detectors compose without knowing each other.
    """

    manager = _register_all(build_hir(source))
    registry = PluginRegistry()
    for root in plugin_roots:
        for loaded in discover_plugins(root, manager):
            registry.add(loaded)
    models = SecurityModelRegistry()
    for loaded in registry:
        models.register(*loaded.plugin.models)
    manager.provide(SecurityModelAnalysis, models.freeze())

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
    findings = run_plugins(manager, [loaded.plugin for loaded in registry], tuple(supported))
    return (*findings, *notes)


def _register_all(module: nodes.Module) -> AnalysisManager:
    manager = AnalysisManager(module)
    manager.register(*ALL_ANALYSES)
    return manager


def report(findings: Sequence[Finding]) -> Report:
    return Report(tuple(findings), TOOL_NAME, __version__)
