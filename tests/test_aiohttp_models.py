"""Acceptance tests for the aiohttp and database-driver models (issue #70).

dvpwa, the intentionally vulnerable aiohttp application of the regression corpus, was
silent: no model gave its handlers HTTP input nor its aiopg cursors a SQL sink. The
``aiohttp-models`` plugin makes ``web.Request`` parameters, registered handlers and
``RouteTableDef`` decorated functions HTTP entry points, ``web.Response``,
``FileResponse`` and the redirect exceptions sinks, and ``ClientSession`` requests SSRF
sinks whose responses are untrusted. The ``db-driver-models`` plugin gives aiopg,
asyncpg, psycopg2 and PyMySQL cursors SQL sinks on the statement argument only.

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
MISSING = [
    name
    for name in ("aiohttp", "db_drivers")
    if not (PLUGINS / "models" / name / "plugin.toml").is_file()
] or None


@pytest.fixture(autouse=True)
def require_models() -> None:
    if MISSING is not None:
        pytest.fail(f"model plugins are not written yet: {MISSING}")


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("views.py", text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[str]:
    return sorted(f.rule_id for f in findings)


DAO = (
    "from aiopg.connection import Connection\n\n"
    "async def create(conn: Connection, name):\n"
    "    q = \"INSERT INTO students (name) VALUES ('%(name)s')\" % {'name': name}\n"
    "    async with conn.cursor() as cur:\n"
    "        await cur.execute(q)\n\n"
)


def test_the_plugins_load_with_their_names() -> None:
    manager = engine.build_manager(engine.build_hir(SourceManager().add_source("e.py", "")))
    names = {loaded.manifest.name for loaded in engine.load_plugins([PLUGINS], manager)}

    assert {"aiohttp-models", "db-driver-models"} <= names


def test_an_annotated_request_reaches_an_aiopg_statement() -> None:
    text = DAO + (
        "from aiohttp.web import Request\n\n"
        "async def students(request: Request):\n"
        "    data = await request.post()\n"
        "    await create(request.app['db'], data['name'])\n"
    )
    assert rules(check(text)) == ["sql-injection"]


def test_parameterised_aiopg_queries_are_safe() -> None:
    text = (
        "from aiopg.connection import Connection\nfrom aiohttp.web import Request\n\n"
        "async def get(conn: Connection, request: Request):\n"
        "    async with conn.cursor() as cur:\n"
        "        await cur.execute('SELECT id FROM students WHERE id = %s', (request.match_info['id'],))\n"
    )
    assert check(text) == ()


def test_handlers_registered_on_the_router_receive_http_input() -> None:
    text = (
        "import os\nfrom aiohttp.web import Application\n\n"
        "async def run(request):\n    os.system(request.query['cmd'])\n\n"
        "def setup_routes(app: Application):\n    app.router.add_route('GET', '/run', run)\n"
    )
    assert rules(check(text)) == ["command-injection"]
    text = (
        "import os\nfrom aiohttp import web\n\n"
        "async def run(request):\n    os.system(request.query['cmd'])\n\n"
        "app = web.Application()\napp.add_routes([web.get('/run', run)])\n"
    )
    assert rules(check(text)) == ["command-injection"]


def test_route_table_decorators_are_entry_points() -> None:
    text = (
        "import os\nfrom aiohttp import web\n\nroutes = web.RouteTableDef()\n\n"
        "@routes.post('/run')\nasync def run(request):\n    os.system(request.query['cmd'])\n"
    )
    assert rules(check(text)) == ["command-injection"]


def test_unregistered_functions_are_not_entry_points() -> None:
    text = "import os\n\nasync def helper(request):\n    os.system(request.query['cmd'])\n"
    assert check(text) == ()


def test_responses_files_and_redirects_are_sinks() -> None:
    text = (
        "from aiohttp import web\n\n"
        "async def page(request: web.Request):\n"
        "    return web.Response(text=request.query['name'], content_type='text/html')\n"
    )
    assert rules(check(text)) == ["xss"]
    text = "from aiohttp import web\n\nasync def download(request: web.Request):\n    return web.FileResponse(request.query['path'])\n"
    assert rules(check(text)) == ["path-traversal"]
    text = "from aiohttp import web\n\nasync def go(request: web.Request):\n    raise web.HTTPFound(request.query['next'])\n"
    assert rules(check(text)) == ["open-redirect"]
    text = "import html\nfrom aiohttp import web\n\nasync def page(request: web.Request):\n    return web.Response(text=html.escape(request.query['name']))\n"
    assert check(text) == ()


def test_client_sessions_are_ssrf_sinks_with_untrusted_responses() -> None:
    text = (
        "import os\nimport aiohttp\nfrom aiohttp import web\n\n"
        "async def fetch(request: web.Request):\n"
        "    async with aiohttp.ClientSession() as session:\n"
        "        await session.get(request.query['url'])\n"
        "        async with session.get('https://example.com/feed') as response:\n"
        "            os.system(await response.text())\n"
    )
    findings = check(text)
    assert rules(findings) == ["command-injection", "ssrf"]
    assert {f.metadata["source_label"] for f in findings} == {"http", "http-response"}


def test_other_database_drivers_have_statement_sinks() -> None:
    for module, connect in (("psycopg2", "psycopg2.connect(dsn)"), ("pymysql", "pymysql.connect()")):
        text = (
            f"import {module}\nfrom aiohttp.web import Request\n\n"
            f"def run(request: Request, dsn):\n    cur = {connect}.cursor()\n"
            "    cur.execute('SELECT * FROM t WHERE a = ' + request.query['a'])\n"
            "    cur.execute('SELECT * FROM t WHERE a = %s', (request.query['a'],))\n"
        )
        assert rules(check(text)) == ["sql-injection"], module
    text = (
        "import asyncpg\nfrom aiohttp.web import Request\n\n"
        "async def run(request: Request):\n    conn = await asyncpg.connect()\n"
        "    await conn.fetch('SELECT * FROM t WHERE a = ' + request.query['a'])\n"
    )
    assert rules(check(text)) == ["sql-injection"]
