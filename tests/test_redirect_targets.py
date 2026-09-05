"""Acceptance tests for redirect sinks reading their target only (issue #71).

Django's ``redirect("url-name", arg)`` resolves a URL pattern with ``arg`` as a route
parameter; ``HttpResponseRedirect(to)`` and Flask's ``redirect(location, code)`` take the
target first too. Only the first argument is a redirect target, so attacker-controlled
data in the other arguments is not an open redirect: 58 of the 77 ``open-redirect``
findings on healthchecks were of that shape.

Expected to remain red until the redirect sinks restrict ``REDIRECT`` to argument 0.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import TaintKind

REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"


def sinks() -> dict[str, tuple[tuple[TaintKind, tuple[int, ...]], ...]]:
    manager = engine.build_manager(engine.build_hir(SourceManager().add_source("e.py", "")))
    loaded = engine.load_plugins([PLUGINS], manager)
    table = engine.plugin_models(l.plugin for l in loaded)
    names = ("django.shortcuts.redirect", "django.http.HttpResponseRedirect", "flask.redirect")
    return {n: table.sink(SymbolId(f"python.{n}")).positions for n in names}  # type: ignore[union-attr]


MISSING = None if all(sinks().values()) else "redirect sinks have no positions"


@pytest.fixture(autouse=True)
def require_positions() -> None:
    if MISSING is not None:
        pytest.fail(f"redirect targets are not restricted yet: {MISSING}")


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("views.py", text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[str]:
    return sorted(f.rule_id for f in findings)


DJANGO = "from django.http import HttpRequest\nfrom django.shortcuts import redirect\n\n"


def test_redirect_sinks_read_their_first_argument_only() -> None:
    for positions in sinks().values():
        assert positions == ((TaintKind.REDIRECT, (0,)),)


def test_a_url_name_with_a_tainted_route_argument_is_not_an_open_redirect() -> None:
    assert check(DJANGO + "def details(request: HttpRequest, code):\n    return redirect('hc-details', code)\n") == ()
    assert check(DJANGO + "def details(request: HttpRequest):\n    return redirect('hc-details', request.GET['code'])\n") == ()


def test_a_tainted_target_is_still_an_open_redirect() -> None:
    assert rules(check(DJANGO + "def go(request: HttpRequest):\n    return redirect(request.GET['next'])\n")) == ["open-redirect"]
    assert rules(
        check(
            "from django.http import HttpRequest, HttpResponseRedirect\n\n"
            "def go(request: HttpRequest):\n    return HttpResponseRedirect(request.GET['next'])\n"
        )
    ) == ["open-redirect"]


def test_flask_redirect_status_code_is_not_a_target() -> None:
    flask = "from flask import Flask, redirect, request\napp = Flask(__name__)\n\n"
    assert rules(check(flask + "@app.route('/go')\ndef go():\n    return redirect(request.args['next'])\n")) == ["open-redirect"]
    assert check(flask + "@app.route('/go')\ndef go():\n    return redirect('/home', int(request.args['code']))\n") == ()
