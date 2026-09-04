"""Acceptance tests for the bodies of nested functions and lambdas (option 2, first
point of the consolidation agreed with Hugo).

Until now a nested ``def`` or a ``lambda`` was a ``MakeFunction`` value whose body was
never analysed: a sink inside a callback was invisible and a call to it conservatively
tainted its result. Now every nested function and lambda inside an analysable function
is an analysable function of its own, named after its enclosing functions
(``outer.inner``, ``outer.lambda_L_C``). The variables it captures are implicit
parameters appended to its explicit ones; ``MakeFunction`` carries the captured values
at the definition point, and a call to a nested function maps the callee's captured
parameters onto them, so summaries and taint flow through closures like through any
known function. ``nonlocal`` assignments stay unsupported.

Expected to remain red until ``captured_names``, ``MakeFunction.captured`` and nested
analysable functions exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.interprocedural import SummaryAnalysis
from coretrace_python.ir.lowering import analyzable_functions, lower_module
from coretrace_python.ir.model import MakeFunction
from coretrace_python.ir.printer import format_module
from coretrace_python.semantic.scopes import analyze_scopes
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager

try:
    from coretrace_python.ir.lowering import captured_names
except ImportError as error:  # pragma: no cover - red until closures land
    MISSING: Exception | None = error
else:
    MISSING = None
    if "captured" not in MakeFunction.__dataclass_fields__:
        MISSING = AttributeError("MakeFunction has no captured values")


@pytest.fixture(autouse=True)
def require_closures() -> None:
    if MISSING is not None:
        pytest.fail(f"closure bodies are not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"


def hir(text: str) -> nodes.Module:
    return build_hir(SourceManager().add_source("c.py", text))


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("c.py", text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, int, str | None, str]]:
    return sorted((f.rule_id, f.span.start_line, f.function, f.metadata.get("through", "")) for f in findings)


NESTED = (
    "import os\n\n"
    "def outer(prefix):\n"
    "    cmd = input()\n"
    "    def run(suffix):\n"
    "        os.system(prefix + cmd + suffix)\n"
    "    run('!')\n"
    "    key = lambda item: item.lower()\n"
    "    return key\n"
)


# --------------------------------------------------------------------------- structure


def test_nested_functions_and_lambdas_are_analysable_functions() -> None:
    module = hir(NESTED)

    names = [f.name for f in analyzable_functions(module)]

    assert names == ["outer", "run", "lambda_8_11"]
    functions = lower_module(module).functions
    assert [f.name for f in functions] == ["outer", "outer.run", "outer.lambda_8_11"]


def test_captured_variables_become_implicit_parameters() -> None:
    module = hir(NESTED)
    scopes = analyze_scopes(module)
    outer = module.body[1]
    assert isinstance(outer, nodes.Function)
    run = next(s for s in outer.body if isinstance(s, nodes.Function))

    assert captured_names(run, scopes) == ("cmd", "prefix")
    assert captured_names(outer, scopes) == ()

    functions = {f.name: f for f in lower_module(module).functions}
    assert len(functions["outer.run"].parameters) == 3
    assert len(functions["outer.lambda_8_11"].parameters) == 1
    text = format_module(lower_module(module))
    assert "func @outer.run(%0, %1, %2) {" in text
    assert 'make_function "run"' in text and "[" in text.split('make_function "run"')[1].split("\n")[0]


def test_make_function_carries_the_captured_values() -> None:
    (outer, *_) = lower_module(hir(NESTED)).functions
    made = [i for b in outer.blocks for i in b.instructions if isinstance(i, MakeFunction)]

    assert [(m.name, len(m.captured)) for m in made] == [("run", 2), ("lambda_8_11", 0)]


def test_nonlocal_assignments_are_analysed_inside_the_writer() -> None:
    findings = check("def outer():\n    n = 0\n    def bump():\n        nonlocal n\n        n = n + 1\n    bump()\n    return n\n")
    assert findings == ()


# --------------------------------------------------------------------------- taint through closures


def test_a_sink_inside_a_closure_is_reached_through_its_call() -> None:
    findings = check(NESTED)
    assert rules(findings) == [("command-injection", 7, "outer", "outer.run")]
    assert findings[0].metadata["sink_line"] == "6"


def test_explicit_arguments_and_lambdas_flow_too() -> None:
    assert rules(check("import os\n\ndef outer():\n    def run(c):\n        os.system(c)\n    run(input())\n")) == [
        ("command-injection", 6, "outer", "outer.run")
    ]
    assert rules(check("import os\n\ndef outer():\n    handler = lambda c: os.system(c)\n    handler(input())\n")) == [
        ("command-injection", 5, "outer", "outer.lambda_4_15")
    ]
    assert rules(check("import os\n\ndef outer():\n    cmd = input()\n    fire = lambda: os.system(cmd)\n    fire()\n")) == [
        ("command-injection", 6, "outer", "outer.lambda_5_12")
    ]


def test_uncalled_and_clean_closures_stay_silent() -> None:
    assert check("import os\n\ndef outer():\n    cmd = input()\n    def run():\n        os.system(cmd)\n    return run\n") == ()
    assert check("import os\n\ndef outer():\n    def run(c):\n        os.system('ls')\n    run(input())\n") == ()


def test_closures_compose_through_summaries() -> None:
    manager = engine.build_manager(hir("import os\n\ndef outer(cmd):\n    def run():\n        os.system(cmd)\n    run()\n"))
    table = manager.get(SummaryAnalysis)

    run = table.summary("outer.run")
    assert run.parameters == 1 and [str(c.symbol) for c in run.external_calls] == ["python.os.system"]
    assert run.external_calls[0].argument_dependencies == (frozenset({0}),)
    outer = table.summary("outer")
    assert [(str(c.symbol), c.argument_dependencies) for c in outer.external_calls] == [("python.os.system", (frozenset({0}),))]


def test_routes_defined_inside_an_application_factory_are_entry_points() -> None:
    findings = check(
        "import os\nfrom flask import Flask, request\n\n"
        "def create_app():\n"
        "    app = Flask(__name__)\n\n"
        "    @app.route('/ping/<host>')\n"
        "    def ping(host):\n"
        "        os.system('ping ' + host)\n"
        "        return 'ok'\n\n"
        "    return app\n"
    )
    assert rules(findings) == [("command-injection", 9, "ping", "")]
    assert findings[0].metadata["source"] == "python.flask.Flask.route"


def test_coverage_counts_nested_functions() -> None:
    analysis = engine.analyze_file(SourceManager().add_source("c.py", NESTED), [PLUGINS])
    assert analysis.coverage.summary() == "coverage: 1/1 files, 3/3 functions"


def test_call_graph_names_nested_functions_by_their_enclosing_ones() -> None:
    from coretrace_python.interprocedural import CallGraphAnalysis, KnownFunction

    manager = engine.build_manager(hir(NESTED))
    graph = manager.get(CallGraphAnalysis)

    assert graph.functions == ("outer", "outer.run", "outer.lambda_8_11")
    assert [s.target for s in graph.sites("outer") if isinstance(s.target, KnownFunction)] == [KnownFunction("outer.run")]
    assert SymbolId("python.c.outer.run") is not None
