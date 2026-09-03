"""Acceptance tests for the Analysis Manager (``docs/architecture.md`` §8–§12).

The manager is the core of the engine: analyses are registered with declarative
dependencies, computed lazily at module or function granularity, cached, shared, and
invalidated only by transformations that say what they preserve.

Contract under test:

- ``Analysis[R]`` and ``FunctionAnalysis[R]`` are subclassed with ``name``, ``version``,
  ``requires`` and a ``compute`` classmethod receiving an ``AnalysisContext``.
- ``AnalysisManager(module)``: ``register``, ``get``, ``is_cached``, ``dependencies``,
  ``run(transformation)``.
- The Phase 2 semantic results and per-function PyIR are the first registered analyses.

Expected to remain red until ``coretrace_python.analysis`` exists.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.ir.lowering import lower_module
from coretrace_python.ir.model import FunctionIR, ModuleIR
from coretrace_python.semantic.scopes import ScopeTable
from coretrace_python.semantic.symbols import SymbolId, SymbolTable
from coretrace_python.source import SourceManager

try:
    from coretrace_python.analysis import (
        Analysis,
        AnalysisContext,
        AnalysisManager,
        CyclicDependencyError,
        FunctionAnalysis,
        TransformationPass,
        UndeclaredDependencyError,
        UnregisteredAnalysisError,
    )

    from coretrace_python.ir.lowering import ModuleIRAnalysis, PyIRAnalysis
    from coretrace_python.semantic import SEMANTIC_ANALYSES
    from coretrace_python.semantic.imports import ImportAnalysis
    from coretrace_python.semantic.scopes import ScopeAnalysis
    from coretrace_python.semantic.symbols import SymbolAnalysis
except ImportError as error:  # pragma: no cover - red until the analysis manager lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_analysis_manager() -> None:
    if MISSING is not None:
        pytest.fail(f"analysis manager is not implemented yet: {MISSING}")


SOURCE = (
    "import os\n\n"
    "def first(command):\n"
    "    os.system(command)\n\n"
    "def second(command):\n"
    "    print(command)\n"
)


def hir(source_text: str = SOURCE) -> nodes.Module:
    return build_hir(SourceManager().add_source("managed.py", source_text))


def functions(module: nodes.Module) -> dict[str, nodes.Function]:
    return {s.name: s for s in module.body if isinstance(s, nodes.Function)}


# --------------------------------------------------------------------------- stub analyses


if MISSING is None:  # the stubs subclass the base classes under test

    class Counting(Analysis[int]):
        """Module-level analysis that counts how often it is computed."""

        name: ClassVar[str] = "test.counting"
        computed: ClassVar[int] = 0

        @classmethod
        def compute(cls, ctx: AnalysisContext) -> int:
            cls.computed += 1
            return len(ctx.module.body)


    class Doubled(Analysis[int]):
        name: ClassVar[str] = "test.doubled"
        requires: ClassVar[frozenset[type[Analysis[object]]]] = frozenset({Counting})
        computed: ClassVar[int] = 0

        @classmethod
        def compute(cls, ctx: AnalysisContext) -> int:
            cls.computed += 1
            return 2 * ctx.get(Counting)


    class Undeclared(Analysis[int]):
        """Requests an analysis it did not declare."""

        name: ClassVar[str] = "test.undeclared"

        @classmethod
        def compute(cls, ctx: AnalysisContext) -> int:
            return ctx.get(Counting)


    class ParameterCount(FunctionAnalysis[int]):
        name: ClassVar[str] = "test.parameter-count"
        computed: ClassVar[list[str]] = []

        @classmethod
        def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> int:
            cls.computed.append(function.name)
            return len(function.parameters)


    class Rewrite(TransformationPass):
        name: ClassVar[str] = "test.rewrite"
        preserves: ClassVar[frozenset[type[Analysis[object]]]] = frozenset({Counting})

        @classmethod
        def run(cls, ctx: AnalysisContext) -> None:
            pass


@pytest.fixture(autouse=True)
def reset_counters() -> None:
    Counting.computed = 0
    Doubled.computed = 0
    ParameterCount.computed = []


def manager(*analyses: type[object], source_text: str = SOURCE) -> AnalysisManager:
    result = AnalysisManager(hir(source_text))
    result.register(*analyses)
    return result


# --------------------------------------------------------------------------- laziness and cache


def test_context_exposes_the_module() -> None:
    engine = manager(Counting)
    assert engine.get(Counting) == 3


def test_results_are_computed_once_and_shared() -> None:
    engine = manager(Counting)

    assert engine.is_cached(Counting) is False
    first = engine.get(Counting)
    second = engine.get(Counting)

    assert first == second
    assert Counting.computed == 1
    assert engine.is_cached(Counting) is True


def test_nothing_is_computed_before_it_is_requested() -> None:
    engine = manager(Counting, Doubled)

    assert Counting.computed == 0
    assert engine.get(Doubled) == 6
    assert Counting.computed == 1
    assert Doubled.computed == 1


def test_requesting_a_dependency_does_not_compute_its_dependants() -> None:
    engine = manager(Counting, Doubled)

    engine.get(Counting)

    assert Doubled.computed == 0
    assert engine.is_cached(Doubled) is False


# --------------------------------------------------------------------------- registry and DAG


def test_unregistered_analysis_is_rejected() -> None:
    engine = manager(Counting)

    with pytest.raises(UnregisteredAnalysisError, match="test.doubled"):
        engine.get(Doubled)


def test_dependencies_must_be_declared() -> None:
    engine = manager(Counting, Undeclared)

    with pytest.raises(UndeclaredDependencyError, match="test.undeclared.*test.counting"):
        engine.get(Undeclared)


def test_dependency_cycles_are_rejected() -> None:
    class Left(Analysis[int]):
        name: ClassVar[str] = "test.left"

        @classmethod
        def compute(cls, ctx: AnalysisContext) -> int:
            return ctx.get(Right)

    class Right(Analysis[int]):
        name: ClassVar[str] = "test.right"
        requires: ClassVar[frozenset[type[Analysis[object]]]] = frozenset({Left})

        @classmethod
        def compute(cls, ctx: AnalysisContext) -> int:
            return ctx.get(Left)

    Left.requires = frozenset({Right})

    with pytest.raises(CyclicDependencyError, match="test.left.*test.right"):
        manager(Left, Right)


def test_transitive_dependencies_are_exposed() -> None:
    engine = manager(*SEMANTIC_ANALYSES)

    assert engine.dependencies(SymbolAnalysis) == frozenset({ScopeAnalysis, ImportAnalysis})
    assert engine.dependencies(ScopeAnalysis) == frozenset()


def test_registering_the_same_analysis_twice_is_harmless() -> None:
    engine = manager(Counting, Counting)
    assert engine.get(Counting) == 3


# --------------------------------------------------------------------------- function granularity


def test_function_analyses_are_computed_per_function() -> None:
    engine = manager(ParameterCount)
    module_functions = functions(engine.module)

    assert engine.get(ParameterCount, module_functions["first"]) == 1
    assert ParameterCount.computed == ["first"]
    assert engine.is_cached(ParameterCount, module_functions["first"]) is True
    assert engine.is_cached(ParameterCount, module_functions["second"]) is False

    engine.get(ParameterCount, module_functions["first"])
    assert ParameterCount.computed == ["first"]


def test_function_analysis_requires_a_function_target() -> None:
    engine = manager(ParameterCount, Counting)
    with pytest.raises(TypeError):
        engine.get(ParameterCount)  # type: ignore[call-overload]
    with pytest.raises(TypeError):
        engine.get(Counting, functions(engine.module)["first"])  # type: ignore[call-overload]


# --------------------------------------------------------------------------- invalidation


def test_transformations_invalidate_what_they_do_not_preserve() -> None:
    engine = manager(Counting, Doubled)
    engine.get(Doubled)

    engine.run(Rewrite)

    assert engine.is_cached(Counting) is True
    assert engine.is_cached(Doubled) is False
    assert engine.get(Doubled) == 6
    assert Counting.computed == 1
    assert Doubled.computed == 2


def test_transformations_invalidate_function_results_too() -> None:
    engine = manager(ParameterCount)
    first = functions(engine.module)["first"]
    engine.get(ParameterCount, first)

    engine.run(Rewrite)

    assert engine.is_cached(ParameterCount, first) is False


# --------------------------------------------------------------------------- semantic analyses


def test_semantic_results_are_available_through_the_manager() -> None:
    engine = manager(*SEMANTIC_ANALYSES)
    first = functions(engine.module)["first"]

    scopes = engine.get(ScopeAnalysis)
    symbols = engine.get(SymbolAnalysis)

    assert isinstance(scopes, ScopeTable)
    assert isinstance(symbols, SymbolTable)
    assert symbols.resolve(scopes.scope_for(first).id, "os") == SymbolId("python.os")


def test_semantic_results_are_shared_between_dependants() -> None:
    engine = manager(*SEMANTIC_ANALYSES)

    scopes = engine.get(ScopeAnalysis)
    engine.get(ImportAnalysis)
    engine.get(SymbolAnalysis)

    assert engine.get(ScopeAnalysis) is scopes


def test_analyses_declare_names_and_versions() -> None:
    for analysis in (*SEMANTIC_ANALYSES, PyIRAnalysis, ModuleIRAnalysis):
        assert analysis.name.startswith(("semantic.", "ir."))
        assert analysis.version >= 1


# --------------------------------------------------------------------------- PyIR


def test_pyir_is_computed_per_function_on_demand() -> None:
    engine = manager(*SEMANTIC_ANALYSES, PyIRAnalysis)
    module_functions = functions(engine.module)

    first = engine.get(PyIRAnalysis, module_functions["first"])

    assert isinstance(first, FunctionIR)
    assert first.name == "first"
    assert engine.is_cached(PyIRAnalysis, module_functions["second"]) is False


def test_module_ir_matches_lower_module() -> None:
    module = hir()
    engine = AnalysisManager(module)
    engine.register(*SEMANTIC_ANALYSES, PyIRAnalysis, ModuleIRAnalysis)

    module_ir = engine.get(ModuleIRAnalysis)

    assert isinstance(module_ir, ModuleIR)
    assert module_ir == lower_module(module)
    assert engine.is_cached(PyIRAnalysis, functions(module)["second"]) is True
