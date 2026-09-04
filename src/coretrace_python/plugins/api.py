"""The typed plugin contract (architecture §13, §32, §33, §34).

A plugin declares the analyses it needs and consumes them through a ``PluginContext``,
a deliberately narrow view of the engine: the module, its functions and the declared
analyses. Nothing else is reachable, which keeps plugins on the stable API and leaves
room for out-of-process isolation later.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, ClassVar, overload

from coretrace_python.analysis import (
    Analysis,
    AnalysisManager,
    AnyAnalysis,
    FunctionAnalysis,
    UndeclaredDependencyError,
)
from coretrace_python.analysis.provider import R
from coretrace_python.dependency import Advisory, DependencyGraph
from coretrace_python.findings import Finding
from coretrace_python.hir import nodes
from coretrace_python.interprocedural import CallGraph, CallGraphAnalysis, ModuleGraph
from coretrace_python.ir.lowering import analyzable_functions
from coretrace_python.semantic.imports import ImportAnalysis, ImportTable
from coretrace_python.taint import Model

PLUGIN_API_VERSION = 1


class Plugin(ABC):
    """Declares the analyses it needs and the security models it contributes,
    then turns analysis results into findings."""

    name: ClassVar[str]
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset()
    models: ClassVar[tuple[Model, ...]] = ()
    advisories: ClassVar[tuple[Advisory, ...]] = ()

    @abstractmethod
    def analyze(self, ctx: PluginContext) -> Sequence[Finding]:
        raise NotImplementedError


class ModelPlugin(Plugin):
    """A plugin that only contributes security models or advisories (§15 providers)."""

    def analyze(self, ctx: PluginContext) -> Sequence[Finding]:
        return ()


class ProjectContext:
    """What a project-scoped plugin sees: the module graph, the dependency graph, the
    advisories every plugin contributed, and each module's imports and call graph."""

    def __init__(
        self,
        graph: ModuleGraph,
        dependencies: DependencyGraph,
        advisories: tuple[Advisory, ...],
        managers: Mapping[str, AnalysisManager],
    ) -> None:
        self.graph = graph
        self.dependencies = dependencies
        self.advisories = advisories
        self._managers = managers

    @property
    def modules(self) -> tuple[str, ...]:
        return tuple(self._managers)

    def imports(self, module: str) -> ImportTable:
        return self._managers[module].get(ImportAnalysis)

    def call_graph(self, module: str) -> CallGraph:
        return self._managers[module].get(CallGraphAnalysis)


class ProjectPlugin(Plugin):
    """A plugin that runs once per project rather than once per module (§26)."""

    def analyze(self, ctx: PluginContext) -> Sequence[Finding]:
        return ()

    @abstractmethod
    def analyze_project(self, ctx: ProjectContext) -> Sequence[Finding]:
        raise NotImplementedError


class PluginContext:
    """What one plugin may see while analysing one module."""

    def __init__(
        self,
        manager: AnalysisManager,
        plugin: Plugin,
        functions: tuple[nodes.Function, ...] | None = None,
    ) -> None:
        self._manager = manager
        self._plugin = plugin
        self._functions = analyzable_functions(manager.module) if functions is None else functions

    @property
    def module(self) -> nodes.Module:
        return self._manager.module

    def functions(self) -> tuple[nodes.Function, ...]:
        """Top-level functions and methods the engine can analyse."""

        return self._functions

    @overload
    def get(self, analysis: type[Analysis[R]], function: None = None) -> R: ...

    @overload
    def get(self, analysis: type[FunctionAnalysis[R]], function: nodes.Function) -> R: ...

    def get(self, analysis: AnyAnalysis, function: nodes.Function | None = None) -> Any:
        if analysis not in self._plugin.requires:
            raise UndeclaredDependencyError(
                f"{self._plugin.name} requests {analysis.name} without declaring it in requires"
            )
        if function is None:
            assert issubclass(analysis, Analysis)
            return self._manager.get(analysis)
        assert issubclass(analysis, FunctionAnalysis)
        return self._manager.get(analysis, function)


def run_plugins(
    manager: AnalysisManager,
    plugins: Iterable[Plugin],
    functions: tuple[nodes.Function, ...] | None = None,
) -> tuple[Finding, ...]:
    """Run every plugin against one shared manager and concatenate their findings."""

    findings: list[Finding] = []
    for plugin in plugins:
        findings.extend(plugin.analyze(PluginContext(manager, plugin, functions)))
    return tuple(findings)
