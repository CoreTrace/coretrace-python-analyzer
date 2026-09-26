"""An SSRF flow is judged on how its URL is built, with ``+`` and f-strings only.

A fixed host is a limited proof. When constant text fixes ``scheme://host`` and ends the
authority with ``/``, ``?`` or ``#`` before any input, the input cannot choose the host;
it still chooses the path, which may reach a sensitive resource of that host, and a
redirect may lead elsewhere. The flow is a hotspot. It is refuted only when the constant
text fixes the path too, the input reaching the query or the fragment, and the call
disables redirects (``allow_redirects=False``, ``follow_redirects=False``): the
destination is then fixed.

Every other URL stays a vulnerability: a base of unknown value (an import, a call
result), which may leave the authority open (``BASE_URL = "https:/"``); a constant that
leaves it open (no ``/`` after the host, a variable port, no scheme); ``urljoin``; a URL
built in a helper function. A module-level name is known text only when the module binds
it once, to a string literal, and never rebinds it. The advisory correlation keeps its
own verdict.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.dependency import Advisory, AdvisoryEntryPoint, dump_advisories
from coretrace_python.findings import Finding, Severity
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager

PLUGINS = [engine.BUNDLED_PLUGINS]

APP = (
    "import httpx\nimport requests\nfrom urllib.parse import urljoin\nfrom flask import Flask, request\n\n"
    "app = Flask(__name__)\n"
    "API = 'https://api.example.com/'\n\n"
    "@app.route('/users/<uid>')\n"
    "def fetch(uid):\n"
    "    return {call}\n"
)


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("app.py", text), PLUGINS)


def ssrf(text: str) -> list[tuple[int, str]]:
    return [(f.span.start_line, f.metadata["verdict"]) for f in check(text) if f.rule_id == "ssrf"]


@pytest.mark.parametrize(
    "call, verdict",
    [
        ("requests.get('https://api.example.com/users/' + uid, timeout=5)", "hotspot"),
        ("requests.get(f'https://api.example.com/users/{uid}', timeout=5)", "hotspot"),
        ("requests.get(API + 'users/' + uid, timeout=5)", "hotspot"),
        # ``path='@evil.com'`` makes ``https://api.example.com@evil.com``: evil.com is the host.
        ("requests.get('https://api.example.com' + request.args['path'], timeout=5)", "vulnerability"),
        # An absolute or scheme-relative ``path`` replaces the host.
        ("requests.get(urljoin('https://api.example.com/', request.args['path']), timeout=5)", "vulnerability"),
        ("requests.get(request.args['url'], timeout=5)", "vulnerability"),
    ],
)
def test_constant_text_fixing_the_host_makes_the_flow_a_hotspot(call: str, verdict: str) -> None:
    assert ssrf(APP.format(call=call)) == [(11, verdict)]


@pytest.mark.parametrize(
    "prelude, call",
    [
        # An imported base may be anything: ``"https:/"`` would let ``uid`` choose the host.
        ("from settings import BASE_URL\n", "requests.get(f'{BASE_URL}/users/{uid}', timeout=5)"),
        ("BASE = 'https:/'\n", "requests.get(f'{BASE}/{uid}', timeout=5)"),
        ("BASE = get_base()\n", "requests.get(BASE + '/users/' + uid, timeout=5)"),
        ("\n", "requests.get('https://api.example.com:' + uid + '/users/', timeout=5)"),
        ("\n", "requests.get('//api.example.com/users/' + uid, timeout=5)"),
        ("\n", "requests.get('https://api.example.com/users/%s' % uid, timeout=5)"),
    ],
)
def test_an_unknown_or_incomplete_base_stays_a_vulnerability(prelude: str, call: str) -> None:
    text = APP.format(call=call).replace("API = 'https://api.example.com/'\n", prelude)

    assert ssrf(text) == [(11, "vulnerability")]


@pytest.mark.parametrize(
    "rebinding",
    [
        "API = 'https://b.example.com/'\n",
        "def configure():\n    global API\n    API = input()\n",
        "for API in ('https://a.example.com/', 'https://b.example.com/'):\n    pass\n",
        "def API():\n    return 'https://a.example.com/'\n",
    ],
)
def test_a_module_string_bound_more_than_once_is_unknown(rebinding: str) -> None:
    text = APP.format(call="requests.get(API + 'users/' + uid, timeout=5)") + "\n" + rebinding

    assert ssrf(text) == [(11, "vulnerability")]


@pytest.mark.parametrize(
    "call, verdict",
    [
        ("requests.get('https://api.example.com/search?q=' + request.args['q'], allow_redirects=False, timeout=5)", None),
        ("httpx.get(f'https://api.example.com/search?q={uid}', follow_redirects=False, timeout=5)", None),
        ("requests.get('https://api.example.com/search#' + uid, allow_redirects=False, timeout=5)", None),
        # Redirects followed: the fixed destination may send the request elsewhere.
        ("requests.get('https://api.example.com/search?q=' + request.args['q'], timeout=5)", "hotspot"),
        # Redirects disabled, but the input chooses the path.
        ("requests.get('https://api.example.com/users/' + uid, allow_redirects=False, timeout=5)", "hotspot"),
        # Unpacked options may enable redirects again.
        ("requests.get('https://api.example.com/search?q=' + uid, **{'allow_redirects': True})", "hotspot"),
    ],
)
def test_only_a_fixed_destination_without_redirects_is_refuted(call: str, verdict: str | None) -> None:
    assert ssrf(APP.format(call=call)) == ([(11, verdict)] if verdict else [])


def test_the_evidence_names_the_fixed_text_and_what_the_input_still_chooses() -> None:
    (finding,) = [
        f for f in check(APP.format(call="requests.get('https://api.example.com/users/' + uid, timeout=5)"))
        if f.rule_id == "ssrf"
    ]

    assert "'https://api.example.com/'" in finding.metadata["evidence"]
    assert "path" in finding.metadata["evidence"] and "redirect" in finding.metadata["evidence"]


def test_a_url_built_in_a_helper_function_stays_a_vulnerability() -> None:
    text = APP.format(call="get(uid)") + "\ndef get(path):\n    return requests.get('https://api.example.com/' + path, timeout=5)\n"

    assert ssrf(text) == [(11, "vulnerability")]


def test_the_advisory_correlation_keeps_its_own_verdict(tmp_path: Path) -> None:
    advisory = Advisory(
        "CVE-2099-0801",
        "requests",
        "<3",
        "get sends credentials to the host of a crafted URL",
        Severity.HIGH,
        entry_points=(AdvisoryEntryPoint(SymbolId("python.requests.get"), "commit abc1234"),),
        modules=("requests",),
    )
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask==3.0.0\n", encoding="utf-8")
    (tmp_path / "advisories.json").write_text(dump_advisories((advisory,)), encoding="utf-8")
    (tmp_path / "app.py").write_text(
        APP.format(call="requests.get('https://api.example.com/users/' + uid, timeout=5)"), encoding="utf-8"
    )

    findings = engine.analyze_project(tmp_path, PLUGINS).findings

    verdicts = {f.rule_id: f.metadata["verdict"] for f in findings if f.rule_id in ("ssrf", "exploitable-vulnerability")}
    assert verdicts == {"ssrf": "hotspot", "exploitable-vulnerability": "vulnerability"}
