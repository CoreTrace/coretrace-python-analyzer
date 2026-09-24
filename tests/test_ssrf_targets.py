"""SSRF sinks of the HTTP clients read the URL only: where the request goes.

``requests.get(url, ...)`` and its siblings take the URL first; ``requests.request(method,
url)`` and ``httpx.stream(method, url)`` take it second; each accepts ``url=``. Attacker
data in the body, the JSON, the headers or the query parameters does not choose the host
the server connects to, so it is not a server-side request forgery. A summary keeps which
keyword a parameter reaches, so a project function forwarding ``url=`` still is one.
"""

from __future__ import annotations

import pytest

from coretrace_python import engine
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import Sink, TaintKind

PREFIX = (
    "import httpx\nimport requests\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n"
    "@app.route('/proxy')\ndef proxy():\n"
)


def ssrf(source: str) -> list[int]:
    findings = engine.check(SourceManager().add_source("app.py", source), [engine.BUNDLED_PLUGINS])
    return sorted(f.span.start_line for f in findings if f.rule_id == "ssrf")


def sink(name: str) -> Sink:
    manager = engine.build_manager(engine.build_hir(SourceManager().add_source("e.py", "")))
    table = engine.plugin_models(loaded.plugin for loaded in engine.load_plugins([engine.BUNDLED_PLUGINS], manager))
    found = table.sink(SymbolId(f"python.{name}"))
    assert found is not None, name
    return found


def test_a_kind_restricted_to_a_position_and_a_keyword_reaches_those_arguments_only() -> None:
    fetch = Sink(
        SymbolId("python.http.fetch"),
        TaintKind.SSRF | TaintKind.ADVISORY,
        positions=((TaintKind.SSRF, (0,)),),
        keywords=((TaintKind.SSRF, ("url",)),),
    )

    assert fetch.kinds_at(0) == fetch.kinds_at(None, "url") == TaintKind.SSRF | TaintKind.ADVISORY
    assert fetch.kinds_at(1) == fetch.kinds_at(None, "data") == TaintKind.ADVISORY
    # A starred argument or ``**kwargs`` may hold anything: unknown is not the URL.
    assert fetch.kinds_at(None) == TaintKind.ADVISORY
    merged = fetch.merged(Sink(fetch.symbol, TaintKind.COMMAND))
    assert merged.kinds_at(None, "url") == TaintKind.SSRF | TaintKind.ADVISORY | TaintKind.COMMAND


@pytest.mark.parametrize(
    "name, position, keyword",
    [
        ("requests.get", 0, "url"),
        ("requests.post", 0, "url"),
        ("requests.request", 1, "url"),
        ("requests.api.request", 1, "url"),
        ("requests.Session.get", 0, "url"),
        ("requests.Session.request", 1, "url"),
        ("requests.Session.send", 0, "request"),
        ("httpx.get", 0, "url"),
        ("httpx.request", 1, "url"),
        ("httpx.stream", 1, "url"),
        ("httpx.Client.stream", 1, "url"),
        ("httpx.AsyncClient.send", 0, "request"),
    ],
)
def test_each_client_function_names_its_url_by_its_signature(name: str, position: int, keyword: str) -> None:
    found = sink(name)

    assert found.positions == ((TaintKind.SSRF, (position,)),)
    assert found.keywords == ((TaintKind.SSRF, (keyword,)),)


@pytest.mark.parametrize(
    "call",
    [
        "requests.get(request.args['u'], timeout=5)",
        "requests.get(url=request.args['u'], timeout=5)",
        "requests.post(request.args['u'], data='x', timeout=5)",
        "requests.request('GET', request.args['u'], timeout=5)",
        "requests.request('GET', url=request.args['u'], timeout=5)",
        "requests.Session().get(request.args['u'], timeout=5)",
        "requests.Session().request('GET', request.args['u'], timeout=5)",
        "httpx.get(request.args['u'], timeout=5)",
        "httpx.Client().post(url=request.args['u'], timeout=5)",
        "httpx.stream('GET', request.args['u'], timeout=5)",
    ],
)
def test_a_tainted_url_is_a_server_side_request_forgery(call: str) -> None:
    assert ssrf(PREFIX + f"    return {call}\n") == [9]


@pytest.mark.parametrize(
    "call",
    [
        "requests.post('https://api.example.com/x', data=request.args['d'], timeout=5)",
        "requests.post('https://api.example.com/x', json={'k': request.args['d']}, timeout=5)",
        "requests.get('https://api.example.com/x', params={'q': request.args['q']}, timeout=5)",
        "requests.get('https://api.example.com/x', headers={'X-Id': request.args['h']}, timeout=5)",
        "requests.request('PATCH', 'https://api.example.com/x', data={'t': request.args['t']}, timeout=5)",
        "requests.request(request.args['m'], 'https://api.example.com/x', timeout=5)",
        "httpx.Client().post('https://api.example.com/x', content=request.args['b'], timeout=5)",
    ],
)
def test_attacker_data_that_does_not_choose_the_destination_is_no_ssrf(call: str) -> None:
    assert ssrf(PREFIX + f"    return {call}\n") == []


def test_a_project_function_keeps_which_keyword_its_parameters_reach() -> None:
    source = (
        "import requests\nfrom flask import Flask, request\n\napp = Flask(__name__)\n\n"
        "def send(target, payload):\n"
        "    return requests.post(url=target, data=payload, timeout=5)\n\n"
        "@app.route('/proxy')\n"
        "def proxy():\n"
        "    send(request.args['u'], 'x')\n"
        "    send('https://api.example.com/x', request.args['d'])\n"
    )

    assert ssrf(source) == [11]
