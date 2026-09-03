"""Acceptance tests for interprocedural taint through function summaries (§17, §19).

The shared taint engine consumes the call graph and the summaries: a tainted argument
passed to a known function whose parameter reaches a sink is a flow at the call site,
recorded with the function it went through and the sink's own location; the result of a
known function is tainted by the arguments its return value depends on; sanitizing
before the call still works. Nothing is inlined.

Expected to remain red until ``TaintAnalysis`` requires the interprocedural analyses.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.analysis import AnalysisManager
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.interprocedural import CallGraphAnalysis, SummaryAnalysis
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import (
    Sanitizer,
    SecurityModelAnalysis,
    SecurityModelRegistry,
    Sink,
    Source,
    TaintAnalysis,
    TaintFacts,
    TaintKind,
)

REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "plugins"

MODELS = (
    Source(SymbolId("python.builtins.input"), "stdin"),
    Sink(SymbolId("python.os.system"), TaintKind.COMMAND),
    Sink(SymbolId("python.subprocess.run"), TaintKind.COMMAND),
    Sanitizer(SymbolId("python.shlex.quote"), TaintKind.COMMAND),
)


@pytest.fixture(autouse=True)
def require_interprocedural_taint() -> None:
    if not {CallGraphAnalysis, SummaryAnalysis} <= TaintAnalysis.requires:
        pytest.fail("TaintAnalysis does not consume the call graph and summaries yet")


def facts(source_text: str, name: str = "run") -> TaintFacts:
    module = build_hir(SourceManager().add_source("ip.py", source_text))
    manager = AnalysisManager(module)
    manager.register(*engine.ALL_ANALYSES)
    registry = SecurityModelRegistry()
    registry.register(*MODELS)
    manager.provide(SecurityModelAnalysis, registry.freeze())
    function = next(s for s in module.body if isinstance(s, nodes.Function) and s.name == name)
    return manager.get(TaintAnalysis, function)


def lines(result: TaintFacts) -> list[int]:
    return [flow.location.start_line for flow in result.flows]


# --------------------------------------------------------------------------- parameter sinks


def test_tainted_argument_reaching_a_sink_in_a_callee_is_a_flow_at_the_call_site() -> None:
    result = facts(
        "import os\n\n"
        "def execute(command):\n"
        "    os.system(command)\n\n"
        "def run():\n"
        "    execute(input())\n"
    )

    (flow,) = result.flows
    assert flow.location.start_line == 7
    assert flow.sink.symbol == SymbolId("python.os.system")
    assert flow.kinds == TaintKind.COMMAND
    assert flow.through == "execute"
    assert flow.sink_location is not None and flow.sink_location.start_line == 4
    assert flow.source.label == "stdin"


def test_direct_flows_have_no_through_function() -> None:
    result = facts("import os\n\ndef run():\n    os.system(input())\n")
    (flow,) = result.flows
    assert flow.through is None
    assert flow.sink_location == flow.location


def test_flows_cross_several_known_calls() -> None:
    result = facts(
        "import os\n\n"
        "def leaf(c):\n    os.system(c)\n\n"
        "def middle(c):\n    leaf(c)\n\n"
        "def run():\n    middle(input())\n"
    )

    (flow,) = result.flows
    assert flow.location.start_line == 10
    assert flow.through == "middle"
    assert flow.sink_location is not None and flow.sink_location.start_line == 4


def test_untainted_arguments_to_a_dangerous_callee_are_fine() -> None:
    result = facts("import os\n\ndef execute(command):\n    os.system(command)\n\ndef run():\n    execute('ls')\n")
    assert result.flows == ()


def test_only_the_parameter_that_reaches_the_sink_matters() -> None:
    result = facts(
        "import os\n\n"
        "def execute(command, label):\n    print(label)\n    os.system(command)\n\n"
        "def run():\n    execute('ls', input())\n    execute(input(), 'x')\n"
    )
    assert lines(result) == [9]


def test_sanitizing_before_the_call_removes_the_flow() -> None:
    result = facts(
        "import os\nimport shlex\n\n"
        "def execute(command):\n    os.system(command)\n\n"
        "def run():\n    execute(shlex.quote(input()))\n",
    )
    assert result.flows == ()


def test_keyword_arguments_flow_through_summaries() -> None:
    result = facts(
        "import subprocess\n\n"
        "def execute(cmd, check):\n    subprocess.run(cmd, check=check)\n\n"
        "def run():\n    execute(input(), check=True)\n    execute('ls', check=input())\n",
    )
    assert lines(result) == [7, 8]


# --------------------------------------------------------------------------- return taints


def test_results_of_known_functions_carry_their_arguments_taint() -> None:
    result = facts(
        "import os\n\n"
        "def wrap(x):\n    return 'echo ' + x\n\n"
        "def run():\n    os.system(wrap(input()))\n"
    )
    (flow,) = result.flows
    assert flow.location.start_line == 7
    assert flow.through is None


def test_results_independent_of_their_arguments_are_clean() -> None:
    result = facts("import os\n\ndef const(x):\n    return 'ls'\n\ndef run():\n    os.system(const(input()))\n")
    assert result.flows == ()


def test_sources_inside_callees_taint_their_results() -> None:
    result = facts("import os\n\ndef read():\n    return input()\n\ndef run():\n    os.system(read())\n")
    assert lines(result) == [7]


def test_recursive_callees_terminate() -> None:
    result = facts(
        "import os\n\n"
        "def loop(n):\n    os.system(n)\n    loop(n)\n\n"
        "def run():\n    loop(input())\n"
    )
    assert lines(result) == [8]


def test_unsupported_callees_are_conservative() -> None:
    result = facts(
        "import os\n\n"
        "def outer(a):\n    def inner():\n        pass\n    return a\n\n"
        "def run():\n    os.system(outer(input()))\n"
    )
    assert lines(result) == [9]


# --------------------------------------------------------------------------- detectors


def test_detectors_report_the_function_the_flow_went_through() -> None:
    findings = engine.check(
        SourceManager().add_source(
            "app.py",
            "import os\n\ndef execute(command):\n    os.system(command)\n\ndef run():\n    execute(input())\n",
        ),
        [PLUGINS],
    )

    (finding,) = findings
    assert finding.rule_id == "command-injection"
    assert finding.span.start_line == 7
    assert finding.function == "run"
    assert finding.message.endswith("reaches python.os.system through execute")
    assert finding.metadata["through"] == "execute"
    assert finding.metadata["sink_line"] == "4"
