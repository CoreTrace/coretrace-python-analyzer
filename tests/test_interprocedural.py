"""Acceptance tests for the call graph and function summaries (§19, §20 of the doc).

``CallGraphAnalysis`` resolves every call site of a module to a ``KnownFunction`` defined
in the module, an ``ExternalSymbol`` reached through imports or builtins, or
``UnknownTarget``. ``SummaryAnalysis`` computes, for every function, which parameters
its return value depends on and which external symbols its parameters reach, including
through calls to other known functions, by iterating to a fixpoint over the call graph.
Summaries carry no security knowledge; the taint engine interprets them.

Expected to remain red until ``coretrace_python.interprocedural`` exists.
"""

from __future__ import annotations

import pytest

from coretrace_python import engine
from coretrace_python.analysis import AnalysisManager
from coretrace_python.frontend import build_hir
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.semantic.scopes import ScopeAnalysis
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager

try:
    from coretrace_python.interprocedural import (
        CallGraph,
        CallGraphAnalysis,
        CallSite,
        ExternalCall,
        ExternalSymbol,
        FunctionSummary,
        KnownFunction,
        SummaryAnalysis,
        SummaryTable,
        UnknownTarget,
    )
except ImportError as error:  # pragma: no cover - red until interprocedural lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_interprocedural() -> None:
    if MISSING is not None:
        pytest.fail(f"interprocedural analyses are not implemented yet: {MISSING}")


def manager_for(source_text: str) -> AnalysisManager:
    return engine.build_manager(build_hir(SourceManager().add_source("ip.py", source_text)))


def call_graph(source_text: str) -> CallGraph:
    return manager_for(source_text).get(CallGraphAnalysis)


def summaries(source_text: str) -> SummaryTable:
    return manager_for(source_text).get(SummaryAnalysis)


# --------------------------------------------------------------------------- call graph


def test_calls_to_module_functions_are_known_targets() -> None:
    graph = call_graph("def helper(x):\n    return x\n\ndef main(y):\n    return helper(y)\n")

    (site,) = graph.sites("main")
    assert isinstance(site, CallSite)
    assert site.caller == "main"
    assert site.target == KnownFunction("helper")
    assert site.location.start_line == 5
    assert graph.callees("main") == frozenset({"helper"})
    assert graph.callers("helper") == frozenset({"main"})
    assert graph.callees("helper") == frozenset()


def test_calls_to_imported_and_builtin_symbols_are_external() -> None:
    graph = call_graph("import os\n\ndef run(c):\n    print(c)\n    os.system(c)\n")

    targets = [site.target for site in graph.sites("run")]
    assert targets == [
        ExternalSymbol(SymbolId("python.builtins.print")),
        ExternalSymbol(SymbolId("python.os.system")),
    ]
    assert graph.callees("run") == frozenset()


def test_calls_through_parameters_and_attributes_are_unknown() -> None:
    graph = call_graph("def run(self, callback, obj):\n    callback(1)\n    obj.method(2)\n    self.go()\n")

    assert [site.target for site in graph.sites("run")] == [UnknownTarget()] * 3


def test_local_aliases_and_later_definitions_resolve() -> None:
    graph = call_graph(
        "def main(y):\n    fn = helper\n    return fn(y) + helper(y)\n\n"
        "def helper(x):\n    return x\n"
    )

    assert [site.target for site in graph.sites("main")] == [KnownFunction("helper")] * 2


def test_shadowed_names_are_not_known_functions() -> None:
    graph = call_graph("def helper():\n    pass\n\ndef main(helper):\n    helper()\n")

    assert [site.target for site in graph.sites("main")] == [UnknownTarget()]


def test_methods_are_named_by_their_class() -> None:
    graph = call_graph("class Runner:\n    def go(self):\n        return top()\n\ndef top():\n    pass\n")

    assert graph.functions == ("Runner.go", "top")
    assert graph.callees("Runner.go") == frozenset({"top"})


def test_recursion_and_unsupported_functions() -> None:
    graph = call_graph(
        "def loop(n):\n    return loop(n)\n\n"
        "def outer():\n    def inner():\n        pass\n    return inner\n"
    )

    assert graph.callees("loop") == frozenset({"loop"})
    assert graph.callers("loop") == frozenset({"loop"})
    assert graph.unsupported == frozenset({"outer"})
    assert graph.sites("outer") == ()


def test_call_graph_is_a_module_analysis_over_ssa() -> None:
    assert CallGraphAnalysis.name == "interprocedural.callgraph"
    assert {SSAAnalysis, ScopeAnalysis} <= CallGraphAnalysis.requires


# --------------------------------------------------------------------------- summaries


def test_identity_returns_its_parameter() -> None:
    table = summaries("def identity(x):\n    return x\n")
    summary = table.summary("identity")

    assert isinstance(summary, FunctionSummary)
    assert summary.parameters == 1
    assert summary.return_dependencies == frozenset({0})
    assert summary.external_calls == ()


def test_return_dependencies_follow_data_flow() -> None:
    table = summaries(
        "def pick(a, b, c):\n    if c:\n        r = a + 1\n    else:\n        r = 'x'\n    return r\n\n"
        "def const(a):\n    return 42\n"
    )

    assert table.summary("pick").return_dependencies == frozenset({0})
    assert table.summary("const").return_dependencies == frozenset()


def test_return_dependencies_compose_through_known_callees() -> None:
    table = summaries(
        "def identity(x):\n    return x\n\n"
        "def wrap(a, b):\n    return identity(b)\n\n"
        "def twice(c):\n    return wrap(1, wrap(c, c))\n"
    )

    assert table.summary("wrap").return_dependencies == frozenset({1})
    assert table.summary("twice").return_dependencies == frozenset({0})


def test_unknown_calls_depend_on_every_argument() -> None:
    table = summaries("def run(f, x, y):\n    return f(x) + y.method()\n")
    assert table.summary("run").return_dependencies == frozenset({0, 1, 2})


def test_external_calls_record_which_parameters_reach_them() -> None:
    table = summaries("import os\n\ndef run(cmd, extra):\n    os.system(cmd + extra)\n    print(extra)\n")
    calls = table.summary("run").external_calls

    assert [c.symbol for c in calls] == [SymbolId("python.os.system"), SymbolId("python.builtins.print")]
    assert calls[0].argument_dependencies == (frozenset({0, 1}),)
    assert calls[1].argument_dependencies == (frozenset({1}),)
    assert calls[0].location.start_line == 4
    assert calls[0].call_site is None


def test_external_calls_propagate_transitively_through_known_callees() -> None:
    table = summaries(
        "import os\n\n"
        "def execute(command):\n    os.system(command)\n\n"
        "def run(user, other):\n    execute(user)\n"
    )
    (reached,) = table.summary("run").external_calls

    assert isinstance(reached, ExternalCall)
    assert reached.symbol == SymbolId("python.os.system")
    assert reached.argument_dependencies == (frozenset({0}),)
    assert reached.location.start_line == 4
    assert reached.call_site is not None and reached.call_site.start_line == 7


def test_return_values_record_the_external_results_they_depend_on() -> None:
    table = summaries(
        "def read():\n    return input()\n\n"
        "def wrap():\n    return 'x' + read()\n\n"
        "def const():\n    return 1\n"
    )

    assert table.summary("read").return_externals == frozenset({SymbolId("python.builtins.input")})
    assert table.summary("wrap").return_externals == frozenset({SymbolId("python.builtins.input")})
    assert table.summary("const").return_externals == frozenset()


def test_keyword_arguments_are_conservatively_merged() -> None:
    table = summaries("import subprocess\n\ndef run(cmd, flag):\n    subprocess.run(cmd, check=flag)\n")
    (call,) = table.summary("run").external_calls

    assert call.argument_dependencies == (frozenset({0}),)
    assert call.keyword_dependencies == frozenset({1})


def test_recursive_summaries_reach_a_fixpoint() -> None:
    table = summaries(
        "def ping(n):\n    return pong(n)\n\n"
        "def pong(n):\n    if n:\n        return ping(n)\n    return n\n"
    )

    assert table.summary("ping").return_dependencies == frozenset({0})
    assert table.summary("pong").return_dependencies == frozenset({0})


def test_unsupported_functions_have_conservative_summaries() -> None:
    table = summaries("def outer(a):\n    def inner():\n        pass\n    return inner\n\ndef use(b):\n    return outer(b)\n")

    assert table.summary("outer").return_dependencies == frozenset({0})
    assert table.summary("outer").unsupported is True
    assert table.summary("use").return_dependencies == frozenset({0})


def test_summary_analysis_is_declared_over_the_call_graph() -> None:
    assert SummaryAnalysis.name == "interprocedural.summaries"
    assert {CallGraphAnalysis, SSAAnalysis} <= SummaryAnalysis.requires
    table = summaries("def f():\n    pass\n")
    assert table.summary("f").return_dependencies == frozenset()
    with pytest.raises(KeyError):
        table.summary("missing")
