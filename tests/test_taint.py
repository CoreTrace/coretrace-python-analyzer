"""Acceptance tests for the security model registry and the global taint engine.

``docs/architecture.md`` §16 Security Model Registry, §17 Global Taint Engine.

Taint kinds are a bitset joined with ``|``. Plugins register ``Source``, ``Sink`` and
``Sanitizer`` models keyed by canonical symbol into a ``SecurityModelRegistry``; the
engine provides the frozen table to the manager as the ``SecurityModelAnalysis`` input,
and one shared ``TaintAnalysis`` per function propagates taint over the SSA form and
reports every tainted argument reaching a sink whose kinds it still carries.

Expected to remain red until ``coretrace_python.taint`` and ``AnalysisManager.provide``
exist.
"""

from __future__ import annotations

import dataclasses

import pytest

from coretrace_python import engine
from coretrace_python.analysis import AnalysisManager
from coretrace_python.cfg import BlockId, CFGAnalysis
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.ir.model import Call, FunctionIR
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager

try:
    from coretrace_python.analysis import MissingInputError
    from coretrace_python.taint import (
        ModelError,
        ModelTable,
        Sanitizer,
        SecurityModelAnalysis,
        SecurityModelRegistry,
        Sink,
        Source,
        Taint,
        TaintAnalysis,
        TaintFacts,
        TaintFlow,
        TaintKind,
    )
except ImportError as error:  # pragma: no cover - red until the taint engine lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_taint() -> None:
    if MISSING is not None:
        pytest.fail(f"taint engine is not implemented yet: {MISSING}")


def sym(path: str) -> SymbolId:
    return SymbolId(path)


HTTP = "http"


def default_models() -> ModelTable:
    registry = SecurityModelRegistry()
    registry.register(
        Source(sym("python.flask.request.args"), HTTP),
        Sink(sym("python.os.system"), TaintKind.COMMAND),
        Sink(sym("python.db.execute"), TaintKind.SQL),
        Sink(sym("python.app.emit"), TaintKind.HTML),
        Sink(sym("python.app.run"), TaintKind.COMMAND),
        Sanitizer(sym("python.html.escape"), TaintKind.HTML),
    )
    return registry.freeze()


def analyze(source_text: str, models: ModelTable | None = None) -> tuple[FunctionIR, TaintFacts]:
    module = build_hir(SourceManager().add_source("taint.py", source_text))
    manager = AnalysisManager(module)
    manager.register(*engine.ALL_ANALYSES)
    manager.provide(SecurityModelAnalysis, default_models() if models is None else models)
    function = next(s for s in module.body if isinstance(s, nodes.Function))
    return manager.get(SSAAnalysis, function), manager.get(TaintAnalysis, function)


def calls(function: FunctionIR) -> list[Call]:
    return [i for b in function.blocks for i in b.instructions if isinstance(i, Call)]


# --------------------------------------------------------------------------- taint kinds


def test_taint_kinds_form_a_bitset() -> None:
    assert TaintKind.SQL | TaintKind.COMMAND == TaintKind.SQL | TaintKind.COMMAND
    assert TaintKind.SQL & TaintKind.COMMAND == TaintKind.NONE
    assert TaintKind.HTML in TaintKind.ALL
    assert (TaintKind.ALL & ~TaintKind.HTML) & TaintKind.HTML == TaintKind.NONE
    assert not TaintKind.NONE
    assert {TaintKind.SQL, TaintKind.COMMAND, TaintKind.HTML, TaintKind.PATH, TaintKind.SSRF} <= set(TaintKind)


def test_taint_joins_with_or() -> None:
    a = Taint(TaintKind.SQL, frozenset({Source(sym("python.a"), "a")}))
    b = Taint(TaintKind.HTML, frozenset({Source(sym("python.b"), "b")}))
    joined = a.join(b)

    assert joined.kinds == TaintKind.SQL | TaintKind.HTML
    assert {s.label for s in joined.sources} == {"a", "b"}
    assert not Taint.none()
    assert Taint.none().join(a) == a


# --------------------------------------------------------------------------- registry


def test_registry_indexes_models_by_symbol() -> None:
    table = default_models()

    assert isinstance(table, ModelTable)
    source = table.source(sym("python.flask.request.args"))
    assert source is not None and source.label == HTTP and source.kinds == TaintKind.ALL
    sink = table.sink(sym("python.os.system"))
    assert sink is not None and sink.kinds == TaintKind.COMMAND
    sanitizer = table.sanitizer(sym("python.html.escape"))
    assert sanitizer is not None and sanitizer.kinds == TaintKind.HTML
    assert table.source(sym("python.os.system")) is None
    assert len(table.sinks) == 4


def test_registry_rejects_conflicting_models() -> None:
    registry = SecurityModelRegistry()
    registry.register(Sink(sym("python.os.system"), TaintKind.COMMAND))

    with pytest.raises(ModelError, match="python.os.system"):
        registry.register(Sink(sym("python.os.system"), TaintKind.SQL))


def test_models_and_tables_are_immutable() -> None:
    table = default_models()
    with pytest.raises(dataclasses.FrozenInstanceError):
        table.sinks[0].kinds = TaintKind.SQL  # type: ignore[misc]
    with pytest.raises(AttributeError):
        table.sinks = ()  # type: ignore[misc]


def test_model_table_is_a_provided_input() -> None:
    module = build_hir(SourceManager().add_source("taint.py", "def f():\n    pass\n"))
    manager = AnalysisManager(module)
    manager.register(SecurityModelAnalysis)

    with pytest.raises(MissingInputError, match="taint.models"):
        manager.get(SecurityModelAnalysis)

    table = default_models()
    manager.provide(SecurityModelAnalysis, table)
    assert manager.get(SecurityModelAnalysis) is table
    assert manager.is_cached(SecurityModelAnalysis)


# --------------------------------------------------------------------------- flows


def test_http_input_reaching_a_command_sink_is_a_flow() -> None:
    function, facts = analyze(
        "from flask import request\n"
        "import os\n\n"
        "def run():\n"
        "    cmd = request.args['cmd']\n"
        "    os.system(cmd)\n"
    )

    assert len(facts.flows) == 1
    flow = facts.flows[0]
    assert isinstance(flow, TaintFlow)
    assert flow.source.label == HTTP
    assert flow.sink.symbol == sym("python.os.system")
    assert flow.kinds == TaintKind.COMMAND
    assert flow.location.start_line == 6
    assert flow.argument == calls(function)[0].arguments[0]
    assert facts.taint(flow.argument).kinds == TaintKind.ALL


def test_sanitizer_clears_only_its_kinds() -> None:
    _, facts = analyze(
        "from flask import request\n"
        "import html\n"
        "from app import emit, run\n\n"
        "def render():\n"
        "    name = request.args['name']\n"
        "    safe = html.escape(name)\n"
        "    emit(safe)\n"
        "    run(safe)\n"
    )

    assert [f.sink.symbol for f in facts.flows] == [sym("python.app.run")]
    assert facts.flows[0].kinds == TaintKind.COMMAND


def test_taint_propagates_through_string_building_and_unknown_calls() -> None:
    _, facts = analyze(
        "from flask import request\n"
        "import db\n\n"
        "def lookup():\n"
        "    ident = request.args['id']\n"
        "    query = 'SELECT * FROM t WHERE id = ' + str(ident)\n"
        "    db.execute(query)\n"
    )

    assert [f.sink.symbol for f in facts.flows] == [sym("python.db.execute")]
    assert facts.flows[0].kinds == TaintKind.SQL


def test_taint_merges_at_phis() -> None:
    _, facts = analyze(
        "from flask import request\n"
        "import os\n\n"
        "def run(c):\n"
        "    if c:\n"
        "        cmd = request.args['cmd']\n"
        "    else:\n"
        "        cmd = 'ls'\n"
        "    os.system(cmd)\n"
    )

    assert len(facts.flows) == 1
    assert facts.flows[0].location.start_line == 9


def test_items_of_a_tainted_collection_are_tainted() -> None:
    _, facts = analyze(
        "from flask import request\n"
        "import os\n\n"
        "def run():\n"
        "    for cmd in request.args:\n"
        "        os.system(cmd)\n"
    )

    assert len(facts.flows) == 1
    assert facts.flows[0].location.start_line == 6


def test_comparisons_and_literals_are_not_tainted() -> None:
    function, facts = analyze(
        "from flask import request\n"
        "import os\n\n"
        "def run():\n"
        "    if request.args['mode'] == 'list':\n"
        "        os.system('ls')\n"
    )

    assert facts.flows == ()
    argument = calls(function)[0].arguments[0]
    assert facts.taint(argument) == Taint.none()


def test_untainted_sink_arguments_are_not_flows() -> None:
    _, facts = analyze("import os\n\ndef run(path):\n    os.system(path)\n")
    assert facts.flows == ()


def test_without_models_nothing_is_tainted() -> None:
    function, facts = analyze(
        "from flask import request\n"
        "import os\n\n"
        "def run():\n"
        "    os.system(request.args['cmd'])\n",
        models=SecurityModelRegistry().freeze(),
    )

    assert facts.flows == ()
    assert all(facts.taint(c.result) == Taint.none() for c in calls(function))


def test_each_tainted_argument_reports_its_own_flow() -> None:
    _, facts = analyze(
        "from flask import request\n"
        "import os\n\n"
        "def run():\n"
        "    a = request.args['a']\n"
        "    b = request.args['b']\n"
        "    os.system(a)\n"
        "    os.system(b)\n"
    )

    assert [f.location.start_line for f in facts.flows] == [7, 8]


def test_flows_are_ordered_by_block_then_instruction() -> None:
    _, facts = analyze(
        "from flask import request\n"
        "import os\n\n"
        "def run(c):\n"
        "    a = request.args['a']\n"
        "    if c:\n"
        "        os.system(a)\n"
        "    os.system(a)\n"
    )

    assert [f.location.start_line for f in facts.flows] == [7, 8]


# --------------------------------------------------------------------------- wiring


def test_taint_is_a_shared_function_analysis() -> None:
    assert TaintAnalysis.name == "taint.flows"
    assert {SSAAnalysis, CFGAnalysis, SecurityModelAnalysis} <= TaintAnalysis.requires
    assert SecurityModelAnalysis.name == "taint.models"
    function, facts = analyze("def f():\n    return 1\n")
    assert isinstance(facts, TaintFacts)
    assert facts.flows == ()
    assert function.entry == BlockId("entry")
