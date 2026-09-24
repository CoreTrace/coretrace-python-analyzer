"""A sanitizer called inside a project function protects the flows through it.

A function summary says which parameters reach which external calls and the return value.
It also keeps, for each parameter, the taint kinds cleared on every path from it:
``escape`` clears ``HTML``, ``reverse`` clears ``REDIRECT``, and rendering a template the
project shows escaping clears ``HTML``. A caller's data then reaches the sink, or comes
back, without those kinds. A path that skips the sanitizer, or a kind the sanitizer does
not clear, still reaches it. Stores into objects and ``nonlocal`` writes clear nothing.
"""

from __future__ import annotations

from pathlib import Path

from coretrace_python import engine
from coretrace_python.interprocedural.summaries import Dep
from coretrace_python.source import SourceManager

DJANGO = (
    "import os\n"
    "from django.http import HttpRequest, HttpResponse\n"
    "from django.shortcuts import redirect\n"
    "from django.urls import reverse\n"
    "from django.utils.html import escape\n\n"
)


def rules(body: str) -> list[tuple[str, int]]:
    findings = engine.check(SourceManager().add_source("views.py", DJANGO + body), [engine.BUNDLED_PLUGINS])
    return sorted((f.rule_id, f.span.start_line) for f in findings)


def test_two_paths_keep_only_what_both_cleared() -> None:
    sanitized = Dep(frozenset({0, 1}), cleared=((0, 0b110), (1, 0b010)))
    raw = Dep(frozenset({0}), cleared=((0, 0b011),))

    assert (sanitized | raw).cleared == ((0, 0b010), (1, 0b010))
    assert Dep(frozenset({0, 2})).clearing(0b100).cleared == ((0, 0b100), (2, 0b100))
    assert (Dep(frozenset({0})) | Dep(frozenset({1}))).cleared == ()


def test_a_sink_behind_a_sanitizer_in_a_helper_is_not_reached() -> None:
    body = (
        "def page(value):\n"
        "    return HttpResponse(escape(value))\n\n"
        "def view(request: HttpRequest):\n"
        "    return page(request.GET['name'])\n"
    )

    assert rules(body) == []


def test_a_value_a_helper_returns_sanitized_stays_sanitized() -> None:
    body = (
        "def clean(value):\n"
        "    return escape(value)\n\n"
        "def view(request: HttpRequest):\n"
        "    return HttpResponse(clean(request.GET['name']))\n"
    )

    assert rules(body) == []


def test_a_sanitizer_two_calls_deep_still_protects() -> None:
    body = (
        "def clean(value):\n"
        "    return escape(value)\n\n"
        "def page(value):\n"
        "    return HttpResponse(clean(value))\n\n"
        "def view(request: HttpRequest):\n"
        "    return page(request.GET['name'])\n"
    )

    assert rules(body) == []


def test_a_reversed_url_through_a_helper_is_no_open_redirect() -> None:
    # healthchecks' ``_check_2fa``: ``next`` only ends up in the query of a local path.
    body = (
        "def finish(request):\n"
        "    return redirect(reverse('home', query={'next': request.GET['next']}))\n\n"
        "def login(request: HttpRequest):\n"
        "    return finish(request)\n"
    )

    assert rules(body) == []


def test_a_path_around_the_sanitizer_still_reaches_the_sink() -> None:
    body = (
        "def page(value, trusted):\n"
        "    shown = value if trusted else escape(value)\n"
        "    return HttpResponse(shown)\n\n"
        "def view(request: HttpRequest):\n"
        "    return page(request.GET['name'], False)\n"
    )

    assert rules(body) == [("xss", 12)]


def test_a_sanitizer_clears_only_its_own_kinds() -> None:
    body = (
        "def run(value):\n"
        "    os.system(escape(value))\n\n"
        "def view(request: HttpRequest):\n"
        "    run(request.GET['cmd'])\n"
        "    return HttpResponse('ok')\n"
    )

    assert rules(body) == [("command-injection", 11)]


def test_a_template_rendered_in_a_helper_escapes_for_its_callers(tmp_path: Path) -> None:
    files = {
        "app/views.py": (
            "from django.http import HttpRequest, HttpResponse\n"
            "from django.template.loader import render_to_string\n\n"
            "def card(name):\n"
            "    return render_to_string('app/card.html', {'name': name})\n\n"
            "def view(request: HttpRequest):\n"
            "    return HttpResponse(card(request.GET['name']))\n"
        ),
        "app/templates/app/card.html": "<p>{{ name }}</p>",
        "app/templates/app/raw.html": "<p>{{ name|safe }}</p>",
    }
    for relative, text in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    escaped = engine.analyze_project(tmp_path, [engine.BUNDLED_PLUGINS]).findings
    (tmp_path / "app/views.py").write_text(files["app/views.py"].replace("card.html", "raw.html"), encoding="utf-8")
    raw = engine.analyze_project(tmp_path, [engine.BUNDLED_PLUGINS]).findings

    assert [f.rule_id for f in escaped if f.rule_id == "xss"] == []
    assert [(f.rule_id, f.span.start_line) for f in raw if f.rule_id == "xss"] == [("xss", 8)]
