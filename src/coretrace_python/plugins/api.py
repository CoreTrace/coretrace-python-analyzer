"""The typed plugin contract (architecture §13, §32, §33, §34).

A plugin declares the analyses it needs and consumes them through a ``PluginContext``,
a deliberately narrow view of the engine: the module, its functions and the declared
analyses. Nothing else is reachable, which keeps plugins on the stable API and leaves
room for out-of-process isolation later.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from typing import Any, ClassVar, overload

from coretrace_python.analysis import (
    Analysis,
    AnalysisManager,
    AnyAnalysis,
    FunctionAnalysis,
    UndeclaredDependencyError,
)
from coretrace_python.analysis.provider import R
from coretrace_python.findings import Finding
from coretrace_python.hir import nodes

PLUGIN_API_VERSION = 1


class Plugin(ABC):
    """A detector: declares ``requires`` and turns analysis results into findings."""

    name: ClassVar[str]
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset()

    @abstractmethod
    def analyze(self, ctx: PluginContext) -> Sequence[Finding]:
        raise NotImplementedError


class PluginContext:
    """What one plugin may see while analysing one module."""

    def __init__(self, manager: AnalysisManager, plugin: Plugin) -> None:
        self._manager = manager
        self._plugin = plugin

    @property
    def module(self) -> nodes.Module:
        return self._manager.module

    def functions(self) -> tuple[nodes.Function, ...]:
        return tuple(s for s in self.module.body if isinstance(s, nodes.Function))

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


def run_plugins(manager: AnalysisManager, plugins: Iterable[Plugin]) -> tuple[Finding, ...]:
    """Run every plugin against one shared manager and concatenate their findings."""

    findings: list[Finding] = []
    for plugin in plugins:
        findings.extend(plugin.analyze(PluginContext(manager, plugin)))
    return tuple(findings)
