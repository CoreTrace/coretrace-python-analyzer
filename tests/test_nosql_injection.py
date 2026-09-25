"""NoSQL injection: attacker input that may hold a structure reaching a NOSQL sink.

MongoDB operator injection needs a structure: a JSON body giving
``{"password": {"$ne": null}}`` makes ``find_one({"name": name, "password": password})``
match any password. A string cannot hold an operator, so only input that may hold a
structure carries ``NOSQL``: JSON and the raw bodies a ``json.loads`` decodes, files,
WebSocket messages, standard input. Text input carries ``TEXT_KINDS``, every kind but
``NOSQL``: form fields, query parameters, headers, cookies, URL parameters, the command
line and the environment. An entry-point parameter annotated with a scalar type is
text too, since FastAPI validates it before the handler runs.

The engine ships no NOSQL sink; these tests declare one, ``docstore.find(filter)``.

Limits: a Django or aiohttp request object is tainted as a whole, so ``request.GET``
carries ``NOSQL`` like ``request.body``; the keys of a dict literal are not followed, so
a string concatenated into ``$where`` is not reported.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding, Severity
from coretrace_python.source import SourceManager
from coretrace_python.taint import TEXT_KINDS, TaintKind

MANIFEST = (
    'name = "docstore-sinks"\nversion = "1.0.0"\nplugin_api = ">=1,<2"\nrequires = []\n'
    'provides = ["model.docstore"]\n\n[entrypoint]\nmodule = "docstore_sinks"\nclass = "DocstoreSinks"\n'
)
PLUGIN = '''
from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import Model, Sink, TaintKind


class DocstoreSinks(ModelPlugin):
    name: ClassVar[str] = "docstore-sinks"
    models: ClassVar[tuple[Model, ...]] = (
        Sink(SymbolId("python.docstore.find"), TaintKind.NOSQL, ((TaintKind.NOSQL, (0,)),)),
    )
'''


@pytest.fixture(scope="module")
def plugins(tmp_path_factory: pytest.TempPathFactory) -> list[Path]:
    root = tmp_path_factory.mktemp("plugins")
    plugin = root / "docstore_sinks"
    plugin.mkdir()
    (plugin / "plugin.toml").write_text(MANIFEST, encoding="utf-8")
    (plugin / "docstore_sinks.py").write_text(PLUGIN, encoding="utf-8")
    return [engine.BUNDLED_PLUGINS, root]


def check(plugins: list[Path], text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("app.py", text), plugins)


def injected(plugins: list[Path], text: str) -> list[int]:
    return [f.span.start_line for f in check(plugins, text) if f.rule_id == "nosql-injection"]


def test_text_kinds_are_every_kind_but_nosql() -> None:
    assert TEXT_KINDS == TaintKind.ALL & ~TaintKind.NOSQL


FLASK = (
    "import json\n\nimport docstore\nfrom flask import Flask, request\n\n"
    "app = Flask(__name__)\n\n"
    "@app.route('/users/<name>')\n"
    "def users(name):\n"
    "    return str(docstore.find({query}))\n"
)


@pytest.mark.parametrize(
    "query",
    [
        '{"name": request.json["name"], "password": request.json["password"]}',
        "request.get_json()",
        "json.loads(request.data)",
        "json.loads(request.get_data())",
        "json.load(request.files['filter'])",
    ],
)
def test_a_structure_from_the_request_in_a_filter_is_a_nosql_injection(plugins: list[Path], query: str) -> None:
    findings = [f for f in check(plugins, FLASK.format(query=query)) if f.rule_id == "nosql-injection"]

    assert [f.span.start_line for f in findings] == [10]
    assert findings[0].severity is Severity.HIGH
    assert findings[0].metadata["source_label"] == "http"


@pytest.mark.parametrize(
    "query",
    [
        '{"name": request.form["name"]}',
        '{"name": request.args.get("name")}',
        '{"name": request.values["name"], "tag": request.cookies["tag"]}',
        '{"agent": request.headers["User-Agent"], "path": request.path}',
        '{"name": name}',
    ],
)
def test_text_from_the_request_cannot_hold_an_operator(plugins: list[Path], query: str) -> None:
    assert injected(plugins, FLASK.format(query=query)) == []


def test_text_sources_still_carry_the_other_kinds(plugins: list[Path]) -> None:
    text = (
        "import sqlite3\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n"
        "@app.route('/users/<name>')\n"
        "def users(name):\n"
        "    sqlite3.connect('app.db').execute(\"SELECT * FROM users WHERE name = '\" + request.form['q'] + \"'\")\n"
        "    sqlite3.connect('app.db').execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n"
    )

    assert sorted(f.span.start_line for f in check(plugins, text) if f.rule_id == "sql-injection") == [8, 9]


FASTAPI = (
    "from typing import Annotated, Optional, Union\nfrom uuid import UUID\n\n"
    "import docstore\nfrom fastapi import FastAPI, Query\nfrom pydantic import BaseModel\n\n"
    "class Filter(BaseModel):\n    name: str\n\n"
    "app = FastAPI()\n\n"
    "@app.get('/users')\n"
    "def users({parameter}):\n"
    "    return docstore.find({{'name': q}})\n"
)


@pytest.mark.parametrize(
    "parameter",
    ["q: dict", "q", "q: Filter", "q: list[dict]", "q: Optional[dict] = None"],
)
def test_a_parameter_that_may_hold_a_structure_is_structured_input(plugins: list[Path], parameter: str) -> None:
    assert injected(plugins, FASTAPI.format(parameter=parameter)) == [15]


@pytest.mark.parametrize(
    "parameter",
    [
        "q: str",
        "q: int = 0",
        "q: Annotated[str, Query()]",
        "q: Optional[int] = None",
        "q: str | None = None",
        "q: Union[str, None] = None",
        "q: Annotated[Optional[str], Query(max_length=20)] = None",
        "q: UUID",
        # A container of scalars holds no operator either.
        "q: list[str] = Query()",
    ],
)
def test_a_parameter_annotated_with_a_scalar_type_is_text(plugins: list[Path], parameter: str) -> None:
    assert injected(plugins, FASTAPI.format(parameter=parameter)) == []


@pytest.mark.parametrize(
    "body, reported",
    [
        ("    return docstore.find(json.loads(sys.stdin.read()))\n", True),
        ("    return docstore.find({'name': input()})\n", False),
        ("    return docstore.find({'name': sys.argv[1]})\n", False),
        ("    return docstore.find({'name': os.environ['USER']})\n", False),
    ],
)
def test_standard_input_is_a_payload_and_the_command_line_text(plugins: list[Path], body: str, reported: bool) -> None:
    text = f"import json\nimport os\nimport sys\n\nimport docstore\n\ndef run():\n{body}"

    assert injected(plugins, text) == ([8] if reported else [])


DJANGO = (
    "import json\n\nimport docstore\nfrom django.http import HttpRequest, JsonResponse\n\n"
    "def users(request: HttpRequest):\n"
    "    return JsonResponse(docstore.find({query}))\n"
)


@pytest.mark.parametrize(
    "query",
    [
        "json.loads(request.body)",
        # Limit: the request object is tainted as a whole, its text fields too.
        '{"name": request.GET["name"]}',
    ],
)
def test_a_django_request_carries_nosql_as_a_whole(plugins: list[Path], query: str) -> None:
    assert injected(plugins, DJANGO.format(query=query)) == [7]


def test_parameters_of_one_entry_point_remain_one_origin(plugins: list[Path]) -> None:
    text = (
        "from fastapi import FastAPI\nfrom fastapi.responses import HTMLResponse\n\n"
        "app = FastAPI()\n\n"
        "@app.get('/users')\n"
        "def users(q, n: int):\n"
        "    return HTMLResponse(q + str(n))\n"
    )

    assert [f.span.start_line for f in check(plugins, text) if f.rule_id == "xss"] == [8]
