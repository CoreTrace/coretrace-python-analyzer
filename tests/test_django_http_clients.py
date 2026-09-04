"""Acceptance tests for the Django and Requests/httpx models (``docs/architecture.md``
§15, §25, §36; roadmap issue #30).

Django views are undecorated functions taking a request, so two engine mechanisms are
added for them, both generic:

- a ``TypedParameter`` model: a parameter annotated with the model's class symbol is
  attacker-controlled, which is how ``request: HttpRequest`` becomes HTTP input;
- an ``EntryPoint`` also applies to the methods of a class deriving from its symbol,
  which is how class-based views receive HTTP input; ``self`` stays clean.

Requests and httpx are SSRF sinks whose results are ``http-response`` sources.

Expected to remain red until ``Parameter.annotation``, ``TypedParameter``, class-based
entry points and the ``models/django`` and ``models/http_clients`` plugins exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import EntryPoint, SecurityModelRegistry, Sink, TaintAnalysis, TaintKind

try:
    from coretrace_python.taint import TypedParameter
except ImportError as error:  # pragma: no cover - red until typed parameters land
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_models() -> None:
    if MISSING is not None:
        pytest.fail(f"Django and HTTP client models are not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "plugins"

OS_SYSTEM = Sink(SymbolId("python.os.system"), TaintKind.COMMAND)


def module_for(text: str) -> nodes.Module:
    return build_hir(SourceManager().add_source("web.py", text))


def flows(text: str, *models: object):  # type: ignore[no-untyped-def]
    registry = SecurityModelRegistry()
    registry.register(*models)  # type: ignore[arg-type]
    manager = engine.build_manager(module_for(text), registry)
    found = []
    for statement in manager.module.body:
        functions = [statement] if isinstance(statement, nodes.Function) else []
        if isinstance(statement, nodes.Class):
            functions = [s for s in statement.body if isinstance(s, nodes.Function)]
        for function in functions:
            found.extend(manager.get(TaintAnalysis, function).flows)
    return tuple(found)


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("web.py", text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[str]:
    return sorted(f.rule_id for f in findings)


# --------------------------------------------------------------------------- HIR


def test_parameter_annotations_are_kept() -> None:
    module = module_for("from django.http import HttpRequest\n\ndef view(request: HttpRequest, n: int = 1, *rest):\n    pass\n")
    function = module.body[-1]
    assert isinstance(function, nodes.Function)

    request, n, rest = function.parameters
    assert isinstance(request.annotation, nodes.Name) and request.annotation.identifier == "HttpRequest"
    assert isinstance(n.annotation, nodes.Name) and n.annotation.identifier == "int"
    assert isinstance(n.default, nodes.Constant) and n.default.value == 1
    assert rest.annotation is None


def test_unsupported_annotations_do_not_break_the_build() -> None:
    module = module_for("def f(x: (lambda: 1), y: 'Request'):\n    return x\n")
    function = module.body[0]
    assert isinstance(function, nodes.Function)
    assert function.parameters[0].annotation is None


# --------------------------------------------------------------------------- typed parameters


REQUEST = SymbolId("python.django.http.HttpRequest")


def test_typed_parameters_are_indexed_in_the_model_table() -> None:
    typed = TypedParameter(REQUEST, "http")
    registry = SecurityModelRegistry()
    registry.register(typed, Sink(REQUEST, TaintKind.HTML))
    table = registry.freeze()

    assert table.typed_parameter(REQUEST) == typed
    assert table.typed_parameter(SymbolId("python.other")) is None
    assert table.typed_parameters == (typed,)
    assert typed.kinds == TaintKind.ALL
    assert table.extended(Sink(SymbolId("python.x"), TaintKind.ADVISORY)).typed_parameters == (typed,)


def test_a_parameter_annotated_with_a_typed_symbol_is_a_source() -> None:
    found = flows(
        "from django.http import HttpRequest\nimport os\n\n"
        "def view(request: HttpRequest, name):\n"
        "    os.system(request.GET['cmd'])\n"
        "    os.system(name)\n",
        TypedParameter(REQUEST, "http"),
        OS_SYSTEM,
    )

    (flow,) = found
    assert flow.source.symbol == REQUEST
    assert flow.source.label == "http"
    assert flow.location.start_line == 5


def test_annotations_resolve_through_module_aliases() -> None:
    found = flows(
        "import django.http as http\nimport os\n\n"
        "def view(request: http.HttpRequest):\n"
        "    os.system(request.body)\n",
        TypedParameter(REQUEST, "http"),
        OS_SYSTEM,
    )
    assert len(found) == 1


def test_untyped_parameters_stay_clean() -> None:
    found = flows(
        "import os\n\ndef view(request):\n    os.system(request.GET['cmd'])\n",
        TypedParameter(REQUEST, "http"),
        OS_SYSTEM,
    )
    assert found == ()


# --------------------------------------------------------------------------- class-based views


VIEW = EntryPoint(SymbolId("python.django.views.View"), "http")


def test_methods_of_classes_deriving_from_an_entry_point_receive_input() -> None:
    found = flows(
        "from django.views import View\nimport os\n\n"
        "class Run(View):\n"
        "    def get(self, request, cmd):\n"
        "        os.system(cmd)\n",
        VIEW,
        OS_SYSTEM,
    )

    (flow,) = found
    assert flow.source.symbol == VIEW.symbol
    assert flow.source.label == "http"


def test_self_is_not_input_in_class_based_views() -> None:
    found = flows(
        "from django.views import View\nimport os\n\n"
        "class Run(View):\n"
        "    def get(self, request):\n"
        "        os.system(self.command)\n",
        VIEW,
        OS_SYSTEM,
    )
    assert found == ()


def test_classes_without_an_entry_point_base_stay_clean() -> None:
    found = flows(
        "import os\n\nclass Run:\n    def get(self, request, cmd):\n        os.system(cmd)\n",
        VIEW,
        OS_SYSTEM,
    )
    assert found == ()


# --------------------------------------------------------------------------- shipped plugins


def test_shipped_django_and_http_client_plugins_load() -> None:
    from coretrace_python.plugins import discover_plugins

    loaded = {p.manifest.name: p.manifest for p in discover_plugins(PLUGINS, engine.build_manager(module_for("")))}

    assert loaded["django-models"].provides == ("model.http-sources", "model.django-views", "model.sql-sinks")
    assert loaded["http-client-models"].provides == ("model.ssrf-sinks", "model.http-response-sources")


def test_django_decorated_view_with_raw_cursor_is_a_sql_injection() -> None:
    findings = check(
        "from django.db import connection\n"
        "from django.views.decorators.csrf import csrf_exempt\n\n"
        "@csrf_exempt\n"
        "def search(request):\n"
        "    cursor = connection.cursor()\n"
        "    cursor.execute(\"SELECT * FROM t WHERE n = '\" + request.POST['n'] + \"'\")\n"
    )
    assert rules(findings) == ["sql-injection"]
    assert findings[0].span.start_line == 7


def test_django_typed_view_with_mark_safe_is_an_xss_and_escape_refutes_it() -> None:
    assert rules(
        check(
            "from django.http import HttpRequest, HttpResponse\n"
            "from django.utils.safestring import mark_safe\n\n"
            "def hello(request: HttpRequest):\n"
            "    return HttpResponse(mark_safe('<b>' + request.GET['name'] + '</b>'))\n"
        )
    ) == ["xss", "xss"]
    assert (
        check(
            "from django.http import HttpRequest, HttpResponse\n"
            "from django.utils.html import escape\n\n"
            "def hello(request: HttpRequest):\n"
            "    return HttpResponse('<b>' + escape(request.GET['name']) + '</b>')\n"
        )
        == ()
    )


def test_django_class_based_view_parameter_to_os_system_is_a_command_injection() -> None:
    findings = check(
        "import os\nfrom django.views.generic import View\n\n"
        "class Ping(View):\n"
        "    def get(self, request, host):\n"
        "        os.system('ping ' + host)\n"
    )
    assert rules(findings) == ["command-injection"]
    assert findings[0].function == "get"
    assert findings[0].span.start_line == 6


def test_django_rest_framework_api_view_is_an_entry_point() -> None:
    findings = check(
        "import os\nfrom rest_framework.decorators import api_view\n\n"
        "@api_view(['GET'])\n"
        "def ping(request):\n"
        "    os.system(request.query_params['host'])\n"
    )
    assert rules(findings) == ["command-injection"]


def test_requests_with_user_url_is_an_ssrf_and_its_response_is_input() -> None:
    findings = check(
        "import os\nimport requests\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n"
        "@app.route('/fetch')\n"
        "def fetch():\n"
        "    response = requests.get(request.args['url'])\n"
        "    os.system(response.text)\n"
    )
    # The response carries two provenances: the remote server's answer, and the URL the
    # request was built from, which the engine propagates through the call.
    assert rules(findings) == ["command-injection", "command-injection", "ssrf"]
    commands = [f for f in findings if f.rule_id == "command-injection"]
    assert {f.span.start_line for f in commands} == {10}
    assert sorted(f.metadata["source_label"] for f in commands) == ["http", "http-response"]


def test_httpx_client_instances_and_sessions_are_ssrf_sinks() -> None:
    findings = check(
        "import httpx\nimport requests\n\n"
        "client = httpx.Client()\nsession = requests.Session()\n\n"
        "def fetch():\n"
        "    client.post(input())\n"
        "    session.get(input())\n"
        "    httpx.get('https://example.com')\n"
    )
    assert rules(findings) == ["ssrf", "ssrf"]
    assert sorted(f.span.start_line for f in findings) == [8, 9]


def test_detectors_stay_generic() -> None:
    assert sorted(p.name for p in (PLUGINS / "security").iterdir() if p.is_dir()) == [
        "command_injection",
        "path_traversal",
        "sql_injection",
        "ssrf",
        "xss",
    ]
