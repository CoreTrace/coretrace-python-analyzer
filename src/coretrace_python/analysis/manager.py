"""The Analysis Manager: registry, dependency DAG, lazy evaluation, cache, invalidation."""

from __future__ import annotations

from typing import Any, overload

from coretrace_python.analysis.provider import (
    Analysis,
    AnyAnalysis,
    FunctionAnalysis,
    R,
    TransformationPass,
)
from coretrace_python.hir import nodes
from coretrace_python.source import SourceSpan


class AnalysisError(Exception):
    """Misuse of the analysis registry or dependency declarations."""


class UnregisteredAnalysisError(AnalysisError):
    pass


class UndeclaredDependencyError(AnalysisError):
    pass


class CyclicDependencyError(AnalysisError):
    pass


_CacheKey = tuple[AnyAnalysis, SourceSpan | None]


class AnalysisManager:
    """Compute registered analyses lazily, once, and share their results."""

    def __init__(self, module: nodes.Module) -> None:
        self._module = module
        self._registry: set[AnyAnalysis] = set()
        self._cache: dict[_CacheKey, Any] = {}
        self._computing: list[AnyAnalysis] = []

    @property
    def module(self) -> nodes.Module:
        return self._module

    # ------------------------------------------------------------------ registry

    def register(self, *analyses: AnyAnalysis) -> None:
        for analysis in analyses:
            self._registry.add(analysis)
            self._check_acyclic(analysis)

    def dependencies(self, analysis: AnyAnalysis) -> frozenset[AnyAnalysis]:
        """Transitive closure of ``analysis.requires``."""

        found: set[AnyAnalysis] = set()
        pending = list(analysis.requires)
        while pending:
            dependency = pending.pop()
            if dependency not in found:
                found.add(dependency)
                pending.extend(dependency.requires)
        return frozenset(found)

    def _check_acyclic(self, root: AnyAnalysis) -> None:
        path: list[AnyAnalysis] = []

        def visit(analysis: AnyAnalysis) -> None:
            if analysis in path:
                cycle = [*path[path.index(analysis) :], analysis]
                raise CyclicDependencyError(
                    "dependency cycle: " + " -> ".join(a.name for a in cycle)
                )
            path.append(analysis)
            for dependency in analysis.requires:
                visit(dependency)
            path.pop()

        visit(root)

    # ------------------------------------------------------------------ evaluation

    @overload
    def get(self, analysis: type[Analysis[R]], function: None = None) -> R: ...

    @overload
    def get(self, analysis: type[FunctionAnalysis[R]], function: nodes.Function) -> R: ...

    def get(self, analysis: AnyAnalysis, function: nodes.Function | None = None) -> Any:
        self._check_target(analysis, function)
        if analysis not in self._registry:
            raise UnregisteredAnalysisError(f"analysis {analysis.name!r} is not registered")
        if self._computing and analysis not in self._computing[-1].requires:
            current = self._computing[-1]
            raise UndeclaredDependencyError(
                f"{current.name} requests {analysis.name} without declaring it in requires"
            )

        key = self._key(analysis, function)
        if key in self._cache:
            return self._cache[key]

        self._computing.append(analysis)
        try:
            if function is None:
                assert issubclass(analysis, Analysis)
                result = analysis.compute(self)
            else:
                assert issubclass(analysis, FunctionAnalysis)
                result = analysis.compute(self, function)
        finally:
            self._computing.pop()
        self._cache[key] = result
        return result

    def is_cached(self, analysis: AnyAnalysis, function: nodes.Function | None = None) -> bool:
        self._check_target(analysis, function)
        return self._key(analysis, function) in self._cache

    # ------------------------------------------------------------------ invalidation

    def run(self, transformation: type[TransformationPass]) -> None:
        """Run a transformation, then drop every cached result it does not preserve."""

        transformation.run(self)
        self._cache = {
            key: result for key, result in self._cache.items() if key[0] in transformation.preserves
        }

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _check_target(analysis: AnyAnalysis, function: nodes.Function | None) -> None:
        if issubclass(analysis, FunctionAnalysis) and function is None:
            raise TypeError(f"{analysis.name} is a function analysis and needs a function")
        if issubclass(analysis, Analysis) and function is not None:
            raise TypeError(f"{analysis.name} is a module analysis and takes no function")

    @staticmethod
    def _key(analysis: AnyAnalysis, function: nodes.Function | None) -> _CacheKey:
        return (analysis, None if function is None else function.span)
