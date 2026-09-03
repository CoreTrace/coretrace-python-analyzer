"""Typed analysis providers and the context they compute in (architecture §8, §12).

An analysis is a class, not an instance: its ``name`` and ``version`` identify cached
results, its ``requires`` declares the dependency DAG, and ``compute`` builds the
result from an ``AnalysisContext``. Read-only analyses never modify shared IR; a
``TransformationPass`` may, and must say what it preserves.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar, Generic, Protocol, TypeVar, overload

from coretrace_python.hir import nodes

R = TypeVar("R")


class Analysis(ABC, Generic[R]):
    """A module-level analysis producing one immutable result per module."""

    name: ClassVar[str]
    version: ClassVar[int] = 1
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset()

    @classmethod
    @abstractmethod
    def compute(cls, ctx: AnalysisContext) -> R:
        raise NotImplementedError


class FunctionAnalysis(ABC, Generic[R]):
    """A function-level analysis producing one result per function, on demand."""

    name: ClassVar[str]
    version: ClassVar[int] = 1
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset()

    @classmethod
    @abstractmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> R:
        raise NotImplementedError


AnyAnalysis = type[Analysis[Any]] | type[FunctionAnalysis[Any]]


class TransformationPass(ABC):
    """A pass that may change shared state and therefore invalidates cached results.

    Every cached analysis not listed in ``preserves`` is dropped after the pass runs.
    """

    name: ClassVar[str]
    preserves: ClassVar[frozenset[AnyAnalysis]] = frozenset()

    @classmethod
    @abstractmethod
    def run(cls, ctx: AnalysisContext) -> None:
        raise NotImplementedError


class AnalysisContext(Protocol):
    """What an analysis sees while computing: the module and its declared dependencies."""

    @property
    def module(self) -> nodes.Module: ...

    @overload
    def get(self, analysis: type[Analysis[R]], function: None = None) -> R: ...

    @overload
    def get(self, analysis: type[FunctionAnalysis[R]], function: nodes.Function) -> R: ...
