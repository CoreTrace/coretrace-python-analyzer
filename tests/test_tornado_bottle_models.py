"""Acceptance tests for the Tornado and Bottle models (issue #70).

Tornado handlers are classes: ``class Main(tornado.web.RequestHandler)`` reads its input
through inherited methods, ``self.get_argument(...)`` and ``self.request``, and answers
through ``self.write`` and ``self.redirect``. The call graph resolves an attribute a
module class does not define through the class's base symbol, so those calls denote
``tornado.web.RequestHandler.get_argument`` and the models apply; Django class-based
views reading ``self.request`` benefit the same way. Bottle is decorator-based like Flask:
``@route``, ``@get`` and ``Bottle().route`` are entry points, ``bottle.request`` the
source, ``redirect``, ``static_file``, ``template`` and ``HTTPResponse`` the sinks.

Expected to remain red until both plugins exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.source import SourceManager

REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"
MISSING = [n for n in ("tornado", "bottle") if not (PLUGINS / "models" / n / "plugin.toml").is_file()] or None


@pytest.fixture(autouse=True)
def require_models() -> None:
    if MISSING is not None:
        pytest.fail(f"model plugins are not written yet: {MISSING}")


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("app.py", text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[str]:
    return sorted(f.rule_id for f in findings)


TORNADO = "import os\nimport tornado.web\nfrom tornado import escape\n\n"


def test_inherited_request_methods_of_tornado_handlers_are_sources() -> None:
    text = TORNADO + "class Run(tornado.web.RequestHandler):\n    def get(self):\n        os.system(self.get_argument('cmd'))\n"
    assert rules(check(text)) == ["command-injection"]
    text = TORNADO + "class Run(tornado.web.RequestHandler):\n    def post(self):\n        os.system(self.request.body)\n"
    assert rules(check(text)) == ["command-injection"]


def test_handler_method_parameters_are_http_input() -> None:
    text = TORNADO + "class File(tornado.web.RequestHandler):\n    def get(self, name):\n        open(name).read()\n"
    assert rules(check(text)) == ["path-traversal"]


def test_tornado_responses_and_redirects_are_sinks_and_escape_sanitises() -> None:
    text = TORNADO + "class Page(tornado.web.RequestHandler):\n    def get(self):\n        self.write(self.get_argument('name'))\n"
    assert rules(check(text)) == ["xss"]
    text = TORNADO + "class Go(tornado.web.RequestHandler):\n    def get(self):\n        self.redirect(self.get_argument('next'))\n"
    assert rules(check(text)) == ["open-redirect"]
    text = TORNADO + "class Page(tornado.web.RequestHandler):\n    def get(self):\n        self.write(escape.xhtml_escape(self.get_argument('name')))\n"
    assert check(text) == ()


def test_methods_the_class_defines_itself_are_not_inherited() -> None:
    text = TORNADO + (
        "class Run(tornado.web.RequestHandler):\n"
        "    def get_argument(self, name):\n        return 'ls'\n"
        "    def get(self):\n        os.system(self.get_argument('cmd'))\n"
    )
    assert check(text) == ()


def test_container_literals_are_serialised_not_rendered() -> None:
    text = TORNADO + "class Api(tornado.web.RequestHandler):\n    def get(self):\n        self.write({'name': self.get_argument('name')})\n"
    assert check(text) == ()


def test_static_methods_have_no_receiver() -> None:
    text = (
        "from typing import NamedTuple\nfrom aiopg.connection import Connection\nfrom aiohttp.web import Request\n\n"
        "class Student(NamedTuple):\n    id: int\n\n    @staticmethod\n"
        "    async def create(conn: Connection, name):\n        async with conn.cursor() as cur:\n"
        "            await cur.execute('INSERT INTO s VALUES (%s)' % name)\n\n"
        "async def view(request: Request):\n    await Student.create(request.app['db'], (await request.post())['name'])\n"
    )
    assert rules(check(text)) == ["sql-injection"]


def test_tornado_http_client_is_an_ssrf_sink() -> None:
    text = (
        "import tornado.web\nfrom tornado.httpclient import AsyncHTTPClient\n\n"
        "class Fetch(tornado.web.RequestHandler):\n    async def get(self):\n"
        "        await AsyncHTTPClient().fetch(self.get_argument('url'))\n"
    )
    assert rules(check(text)) == ["ssrf"]


def test_django_class_based_views_read_self_request_through_the_base() -> None:
    text = (
        "import os\nfrom django.views import View\n\n"
        "class Run(View):\n    def get(self, request):\n        os.system(self.request.GET['cmd'])\n"
    )
    assert rules(check(text)) == ["command-injection"]


BOTTLE = "import os\nfrom bottle import Bottle, route, get, request, redirect, static_file, template, html_escape\n\n"


def test_bottle_routes_are_entry_points_and_request_is_the_source() -> None:
    assert rules(check(BOTTLE + "@route('/run')\ndef run():\n    os.system(request.query.cmd)\n")) == ["command-injection"]
    assert rules(check(BOTTLE + "@get('/run')\ndef run():\n    os.system(request.forms.get('cmd'))\n")) == ["command-injection"]
    assert rules(check(BOTTLE + "app = Bottle()\n\n@app.post('/run')\ndef run():\n    os.system(request.json['cmd'])\n")) == [
        "command-injection"
    ]
    assert check(BOTTLE + "def helper(value):\n    os.system(value)\n") == ()


def test_bottle_sinks_and_sanitizer() -> None:
    assert rules(check(BOTTLE + "@route('/go')\ndef go():\n    redirect(request.query.next)\n")) == ["open-redirect"]
    assert rules(check(BOTTLE + "@route('/f')\ndef f():\n    return static_file(request.query.name, root='/srv/files')\n")) == [
        "path-traversal"
    ]
    assert rules(check(BOTTLE + "@route('/t')\ndef t():\n    return template(request.query.tpl)\n")) == ["xss"]
    assert check(BOTTLE + "@route('/t')\ndef t():\n    return template('page', name=html_escape(request.query.name))\n") == ()
