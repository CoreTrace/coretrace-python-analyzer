"""Acceptance tests for framework models (``docs/architecture.md`` §15, §25, §36).

Framework plugins enrich the security model; detectors stay generic. Three engine
mechanisms make that possible:

- a module-level ``name = Symbol(...)`` binds ``name`` to that symbol, so ``app.route``
  resolves to ``python.flask.Flask.route`` when ``app = Flask(__name__)``;
- inside functions, call results and ``with`` contexts carry their callee's symbol, so
  ``conn.cursor().execute`` resolves to ``python.sqlite3.connect.cursor.execute``;
- an ``EntryPoint`` model taints every parameter of a function decorated by its symbol,
  which is how route handler arguments become HTTP input.

Shipped: ``models/flask``, ``models/fastapi``, ``models/sqlalchemy`` and sqlite3 sinks in
``models/python_stdlib``. Expected to remain red until they exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.analysis import AnalysisManager
from coretrace_python.findings import Finding
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.interprocedural import CallGraphAnalysis, ExternalSymbol
from coretrace_python.ir.lowering import lower_module
from coretrace_python.ir.printer import format_module
from coretrace_python.semantic.scopes import ScopeAnalysis
from coretrace_python.semantic.symbols import SymbolAnalysis, SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import (
    SecurityModelAnalysis,
    SecurityModelRegistry,
    Sink,
    TaintAnalysis,
    TaintKind,
)

try:
    from coretrace_python.taint import EntryPoint
except ImportError as error:  # pragma: no cover - red until entry points land
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_entry_points() -> None:
    if MISSING is not None:
        pytest.fail(f"framework support is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"


def module_for(source_text: str) -> nodes.Module:
    return build_hir(SourceManager().add_source("web.py", source_text))


def manager_for(source_text: str, *models: object) -> AnalysisManager:
    registry = SecurityModelRegistry()
    registry.register(*models)  # type: ignore[arg-type]
    return engine.build_manager(module_for(source_text), registry)


def check(source_text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("web.py", source_text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[str]:
    return [f.rule_id for f in findings]


# --------------------------------------------------------------------------- symbol derivation


def test_module_level_instances_resolve_to_their_class_symbol() -> None:
    manager = manager_for("from flask import Flask\napp = Flask(__name__)\nlimit = 3\n\ndef f():\n    return app\n")
    symbols = manager.get(SymbolAnalysis)
    scopes = manager.get(ScopeAnalysis)
    f = next(s for s in scopes.children(scopes.module_scope.id) if s.name == "f")

    assert symbols.resolve(scopes.module_scope.id, "app") == SymbolId("python.flask.Flask")
    assert symbols.resolve(f.id, "app") == SymbolId("python.flask.Flask")
    assert symbols.resolve(f.id, "limit") is None


def test_attributes_of_module_level_instances_lower_to_symbols() -> None:
    module = module_for("from flask import Flask\napp = Flask(__name__)\n\ndef f():\n    return app.route\n")
    output = format_module(lower_module(module))

    assert "symbol @python.flask.Flask.route" in output


def test_call_results_and_with_contexts_carry_their_symbol_in_the_call_graph() -> None:
    manager = manager_for(
        "import sqlite3\n\n"
        "def query(path, sql):\n"
        "    conn = sqlite3.connect(path)\n"
        "    cur = conn.cursor()\n"
        "    cur.execute(sql)\n"
        "    with sqlite3.connect(path) as other:\n"
        "        other.execute(sql)\n"
    )
    graph = manager.get(CallGraphAnalysis)

    assert [site.target for site in graph.sites("query")] == [
        ExternalSymbol(SymbolId("python.sqlite3.connect")),
        ExternalSymbol(SymbolId("python.sqlite3.connect.cursor")),
        ExternalSymbol(SymbolId("python.sqlite3.connect.cursor.execute")),
        ExternalSymbol(SymbolId("python.sqlite3.connect")),
        ExternalSymbol(SymbolId("python.sqlite3.connect.execute")),
    ]


def test_symbols_are_not_derived_through_known_functions_or_parameters() -> None:
    manager = manager_for("def make():\n    return 1\n\ndef use(x):\n    make().run()\n    x.run()\n")
    graph = manager.get(CallGraphAnalysis)

    targets = [site.target for site in graph.sites("use")]
    assert not any(isinstance(t, ExternalSymbol) for t in targets[1:])


# --------------------------------------------------------------------------- entry points


ROUTE = EntryPoint(SymbolId("python.flask.Flask.route"), "http") if MISSING is None else None


def flows(source_text: str, *models: object):  # type: ignore[no-untyped-def]
    manager = manager_for(source_text, *models)
    module = manager.module
    function = next(s for s in module.body if isinstance(s, nodes.Function))
    return manager.get(TaintAnalysis, function).flows


def test_entry_point_parameters_are_sources() -> None:
    found = flows(
        "from flask import Flask\nimport os\napp = Flask(__name__)\n\n"
        "@app.route('/ping/<host>')\n"
        "def ping(host):\n"
        "    os.system('ping ' + host)\n",
        ROUTE,
        Sink(SymbolId("python.os.system"), TaintKind.COMMAND),
    )

    (flow,) = found
    assert flow.source.label == "http"
    assert flow.source.symbol == SymbolId("python.flask.Flask.route")
    assert flow.location.start_line == 7


def test_only_decorated_functions_are_entry_points() -> None:
    found = flows(
        "from flask import Flask\nimport os\napp = Flask(__name__)\n\n"
        "def helper(host):\n"
        "    os.system(host)\n",
        ROUTE,
        Sink(SymbolId("python.os.system"), TaintKind.COMMAND),
    )
    assert found == ()


def test_bare_decorators_also_mark_entry_points() -> None:
    found = flows(
        "from auth import protected\nimport os\n\n"
        "@protected\n"
        "def run(cmd):\n"
        "    os.system(cmd)\n",
        EntryPoint(SymbolId("python.auth.protected"), "rpc"),
        Sink(SymbolId("python.os.system"), TaintKind.COMMAND),
    )
    (flow,) = found
    assert flow.source.label == "rpc"


def test_entry_points_are_indexed_in_the_model_table() -> None:
    registry = SecurityModelRegistry()
    registry.register(ROUTE)
    table = registry.freeze()

    assert table.entry_point(SymbolId("python.flask.Flask.route")) == ROUTE
    assert table.entry_point(SymbolId("python.other")) is None
    assert table.entry_points == (ROUTE,)
    manager = AnalysisManager(module_for(""))
    manager.register(SecurityModelAnalysis)
    manager.provide(SecurityModelAnalysis, table)
    assert manager.get(SecurityModelAnalysis).entry_points == (ROUTE,)


# --------------------------------------------------------------------------- shipped plugins


def test_shipped_framework_plugins_load() -> None:
    from coretrace_python.plugins import discover_plugins

    loaded = {p.manifest.name: p.manifest for p in discover_plugins(PLUGINS, engine.build_manager(module_for("")))}

    assert loaded["flask-models"].provides == ("model.http-sources", "model.flask-routes")
    assert loaded["fastapi-models"].provides == ("model.http-sources", "model.fastapi-routes")
    assert loaded["sqlalchemy-models"].provides == ("model.sql-sinks",)


def test_flask_request_to_sqlite_is_a_sql_injection() -> None:
    findings = check(
        "import sqlite3\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n"
        "@app.route('/user')\n"
        "def user():\n"
        "    conn = sqlite3.connect('app.db')\n"
        "    conn.execute(\"SELECT * FROM users WHERE name = '\" + request.args['name'] + \"'\")\n"
    )

    assert rules(findings) == ["sql-injection"]
    assert findings[0].span.start_line == 9
    assert findings[0].metadata["source_label"] == "http"


def test_flask_route_parameter_to_os_system_is_a_command_injection() -> None:
    findings = check(
        "import os\nfrom flask import Flask\n\napp = Flask(__name__)\n\n"
        "@app.route('/ping/<host>')\n"
        "def ping(host):\n"
        "    os.system('ping ' + host)\n"
    )
    assert rules(findings) == ["command-injection"]


def test_flask_template_string_is_an_xss_sink_and_escape_a_sanitizer() -> None:
    findings = check(
        "from flask import Flask, request, render_template_string\nfrom markupsafe import escape\n\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/hello')\n"
        "def hello():\n"
        "    name = request.args.get('name')\n"
        "    render_template_string('<h1>' + name + '</h1>')\n"
        "    return render_template_string('<h1>' + escape(name) + '</h1>')\n"
    )
    assert rules(findings) == ["xss"]
    assert findings[0].span.start_line == 9


def test_fastapi_route_parameters_are_http_input() -> None:
    findings = check(
        "import os\nfrom fastapi import FastAPI\n\napp = FastAPI()\n\n"
        "@app.get('/run')\n"
        "def run(cmd):\n"
        "    os.system(cmd)\n"
    )
    assert rules(findings) == ["command-injection"]


def test_sqlalchemy_text_and_connection_execute_are_sql_sinks() -> None:
    findings = check(
        "from flask import Flask, request\nfrom sqlalchemy import create_engine, text\n\n"
        "app = Flask(__name__)\nengine = create_engine('sqlite://')\n\n"
        "@app.route('/find')\n"
        "def find():\n"
        "    name = request.args['name']\n"
        "    with engine.connect() as conn:\n"
        "        conn.execute(text('SELECT * FROM t WHERE n = ' + name))\n"
        "        conn.execute('SELECT * FROM t WHERE n = ' + name)\n"
    )
    assert rules(findings) == ["sql-injection", "sql-injection"]
    assert [f.span.start_line for f in findings] == [11, 12]


def test_detectors_stay_generic_across_frameworks() -> None:
    from coretrace_python.plugins import discover_plugins

    names = {p.manifest.name for p in discover_plugins(PLUGINS, engine.build_manager(module_for("")))}
    assert not any("flask" in name and "injection" in name for name in names)
    assert {"sql-injection", "command-injection", "xss"} <= names
