"""Acceptance tests for the hot spots found on large projects (issue #69).

Profiling a 45 000-line project showed the taint engine re-collecting every analysable
function of the module for every function it analysed: the search for the enclosing
function fell through to the lambda fallback for every top-level function, and the
collection itself was never memoised. The list of a module's analysable functions is
computed once per module, and the enclosing-function search only walks the module for
lambdas.

Expected to remain red until ``analyzable_functions`` is memoised per module.
"""

from __future__ import annotations

import pytest

from coretrace_python.frontend import build_hir
from coretrace_python.ir.lowering import analyzable_functions
from coretrace_python.source import SourceManager
from coretrace_python.taint import engine as taint_engine

SOURCE = (
    "def top(x):\n"
    "    return x\n"
    "\n"
    "def outer(y):\n"
    "    def inner(z):\n"
    "        return z\n"
    "    f = lambda q: q\n"
    "    return inner(y)\n"
    "\n"
    "class C:\n"
    "    def method(self):\n"
    "        return 1\n"
)


def module():  # type: ignore[no-untyped-def]
    return build_hir(SourceManager().add_source("m.py", SOURCE))


def test_the_functions_of_a_module_are_collected_once() -> None:
    m = module()
    first = analyzable_functions(m)

    assert analyzable_functions(m) is first
    assert [f.name for f in first] == ["top", "outer", "inner", "lambda_7_9", "method"]
    assert analyzable_functions(module()) is not first


def test_enclosing_function_of_a_named_function_does_not_walk_the_module(monkeypatch: pytest.MonkeyPatch) -> None:
    m = module()
    top, outer, inner, _lam, method = analyzable_functions(m)

    def forbidden(*args: object) -> object:
        raise AssertionError("analyzable_functions must not be called for named functions")

    monkeypatch.setattr(taint_engine, "analyzable_functions", forbidden)

    assert taint_engine._enclosing(m, top) is None
    assert taint_engine._enclosing(m, method) is None
    assert taint_engine._enclosing(m, inner) is outer


def test_enclosing_function_of_a_lambda_is_the_innermost_function_around_it() -> None:
    m = module()
    _top, outer, _inner, lam, _method = analyzable_functions(m)

    assert taint_engine._enclosing(m, lam) is outer
