"""Django values attacker input cannot shape, whatever reaches their arguments.

``django.middleware.csrf.get_token(request)`` returns the masked CSRF secret, built from
ASCII letters and digits only (``CSRF_ALLOWED_CHARS``): a cookie of another shape is
replaced before it is used. ``django.urls.reverse`` builds a path of the project's URL
configuration and never a scheme-relative one (``escape_leading_slashes``), so attacker
data in its arguments or its query reaches no other host through a redirect.
"""

from __future__ import annotations

from coretrace_python import engine
from coretrace_python.source import SourceManager

DJANGO = (
    "from django.http import HttpRequest, HttpResponse\n"
    "from django.middleware import csrf\n"
    "from django.middleware.csrf import get_token\n"
    "from django.shortcuts import redirect\n"
    "from django.urls import reverse, reverse_lazy\n\n"
)


def rules(body: str) -> list[tuple[str, int]]:
    findings = engine.check(SourceManager().add_source("views.py", DJANGO + body), [engine.BUNDLED_PLUGINS])
    return sorted((f.rule_id, f.span.start_line) for f in findings)


def test_the_csrf_token_of_a_request_is_no_injection() -> None:
    body = (
        "def token(request: HttpRequest):\n"
        "    return HttpResponse(csrf.get_token(request))\n\n"
        "def other(request: HttpRequest):\n"
        "    return HttpResponse('<i>' + get_token(request) + '</i>')\n"
    )

    assert rules(body) == []


def test_a_reversed_url_with_attacker_data_is_no_open_redirect() -> None:
    body = (
        "def login(request: HttpRequest):\n"
        "    path = reverse('hc-login-totp', query={'next': request.GET['next']})\n"
        "    return redirect(path)\n\n"
        "def details(request: HttpRequest):\n"
        "    return redirect(reverse_lazy('details', args=[request.GET['code']]))\n"
    )

    assert rules(body) == []


def test_what_reverse_returns_still_carries_other_kinds() -> None:
    # ``reverse`` leaves ``'`` unquoted (an RFC 3986 sub-delimiter): not a redirect, still SQL.
    body = (
        "import sqlite3\n\n"
        "def page(request: HttpRequest):\n"
        "    sqlite3.connect('app.db').execute(\"SELECT '\" + reverse('page', args=[request.GET['name']]) + \"'\")\n"
    )

    assert rules(body) == [("sql-injection", 10)]


def test_a_redirect_to_raw_attacker_input_stays_an_open_redirect() -> None:
    body = "def go(request: HttpRequest):\n    return redirect(request.GET['next'] + reverse('home'))\n"

    assert rules(body) == [("open-redirect", 8)]
