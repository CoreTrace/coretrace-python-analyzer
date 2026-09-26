"""Template filters as calls to the functions behind them.

A Django template applying ``{{ bio|striptags }}`` runs
``django.template.defaultfilters.striptags`` whenever it is rendered, though no Python
call names it. Every filter of Django's own libraries that a project template applies,
in a variable, a tag argument or a ``{% filter %}`` block, therefore counts as a call to
the function behind it, at the template's line, whether or not a Python call names the
template: a class-based view renders its ``template_name`` inside Django. Comments,
``{% comment %}`` and ``{% verbatim %}`` blocks, quoted text and custom filters apply
none.

A template the engine cannot read may apply any filter. When the project names one — a
render call or an ``{% include %}`` or ``{% extends %}`` naming it by an expression, or
naming a template found under no ``templates`` directory — an advisory whose entry
points a template can reach stays ``under_investigation`` in the VEX report rather than
``not_affected``. Advisories no template can reach are not concerned.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from coretrace_python import engine
from coretrace_python.dependency import Advisory, AdvisoryEntryPoint, dump_advisories, render_vex
from coretrace_python.findings import Severity
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import project_templates

NOW = datetime(2026, 9, 26, 12, 0, tzinfo=UTC)
STRIPTAGS = "python.django.template.defaultfilters.striptags"
STRIP_TAGS = Advisory(
    "CVE-2099-5301",
    "django",
    "<4.2.17",
    "strip_tags is quadratic in nested incomplete tags",
    Severity.MEDIUM,
    entry_points=(
        AdvisoryEntryPoint(SymbolId("python.django.utils.html.strip_tags"), "changed by the fix"),
        AdvisoryEntryPoint(SymbolId(STRIPTAGS), "the striptags filter calls strip_tags"),
    ),
)
SIGNING = Advisory(
    "CVE-2099-5302",
    "django",
    "<4.2.17",
    "signing.loads decompresses without a limit",
    Severity.MEDIUM,
    entry_points=(AdvisoryEntryPoint(SymbolId("python.django.core.signing.loads"), "changed by the fix"),),
)
LOCK = """version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "django" }]

[[package]]
name = "django"
version = "4.2.16"
source = { registry = "https://pypi.org/simple" }
"""
VIEW = (
    "from django.http import HttpResponse\n"
    "from django.shortcuts import render\n"
    "from django.template.loader import render_to_string\n"
    "from django.template.response import TemplateResponse\n\n"
    "def profile(request):\n"
    "    return {call}\n"
)
RENDER = "render(request, {name}, {{'bio': request.POST['bio']}})"
PAGE = "app/templates/app/profile.html"


def check(root: Path, files: dict[str, str], advisories: tuple[Advisory, ...] = (STRIP_TAGS,)) -> engine.ProjectAnalysis:
    for relative, text in {"uv.lock": LOCK, "app/__init__.py": "", **files}.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories(advisories), encoding="utf-8")
    return engine.analyze_project(root, [engine.BUNDLED_PLUGINS])


def project(root: Path, template: str, name: str = "'app/profile.html'", **files: str) -> dict[str, str]:
    return {"app/views.py": VIEW.format(call=RENDER.format(name=name)), PAGE: template, **files}


def reached(root: Path, analysis: engine.ProjectAnalysis) -> list[tuple[str, int, str]]:
    return [
        (Path(str(f.span.source_id)).relative_to(root).as_posix(), f.span.start_line, f.metadata["symbol"])
        for f in analysis.findings
        if f.rule_id == "reachable-vulnerability"
    ]


def vex(root: Path, analysis: engine.ProjectAnalysis, name: str) -> dict[str, Any]:
    evidence = (*analysis.findings, *analysis.suppressed, *analysis.accepted)
    document = render_vex(
        analysis.dependencies, analysis.advisories, evidence, analysis.coverage, root, "coretrace", "0.16.0", NOW
    )
    return next(s for s in json.loads(document)["statements"] if s["vulnerability"]["name"] == name)


# --------------------------------------------------------------------------- calls


def test_a_filter_a_project_template_applies_is_a_call_to_the_function_behind_it(tmp_path: Path) -> None:
    analysis = check(tmp_path, project(tmp_path, "<h1>Profile</h1>\n<p>\n  {{ bio|striptags }}\n</p>\n"))

    assert reached(tmp_path, analysis) == [(PAGE, 3, STRIPTAGS)]
    finding = next(f for f in analysis.findings if f.rule_id == "reachable-vulnerability")
    assert (finding.span.start_column, finding.function) == (10, None)
    assert finding.metadata["entry_point"] == STRIPTAGS
    assert finding.metadata["level"] == "reachable"


@pytest.mark.parametrize(
    "template",
    [
        "{{ bio | striptags }}",
        "{{ bio|lower|striptags }}",
        "{{ bio|default:'none'|striptags }}",
        "{% if bio|striptags %}yes{% endif %}",
        "{% with text=bio|striptags %}{{ text }}{% endwith %}",
        "{% filter lower|striptags %}{{ bio }}{% endfilter %}",
        "{% include 'app/card.html' with text=bio|striptags %}",
    ],
)
def test_a_filter_in_a_variable_a_tag_or_a_filter_block_is_a_call(tmp_path: Path, template: str) -> None:
    analysis = check(tmp_path, project(tmp_path, f"<p>\n{template}\n</p>\n", **{"app/templates/app/card.html": ""}))

    assert reached(tmp_path, analysis) == [(PAGE, 2, STRIPTAGS)]


@pytest.mark.parametrize(
    "template",
    [
        "{# {{ bio|striptags }} #}",
        "{% comment %}\n{{ bio|striptags }}\n{% endcomment %}",
        "{% verbatim %}\n{{ bio|striptags }}\n{% endverbatim %}",
        "{{ 'a|striptags' }}",
        "{% load text %}{{ bio|strip_html }}",
        "<p>bio|striptags</p>",
    ],
)
def test_comments_verbatim_text_quoted_text_and_custom_filters_call_nothing(tmp_path: Path, template: str) -> None:
    analysis = check(tmp_path, project(tmp_path, template))

    assert reached(tmp_path, analysis) == []


@pytest.mark.parametrize(
    "applied, function",
    [
        ("escape", "python.django.template.defaultfilters.escape_filter"),
        ("slice:':2'", "python.django.template.defaultfilters.slice_filter"),
        ("urlizetrunc:15", "python.django.template.defaultfilters.urlizetrunc"),
        ("timezone:'UTC'", "python.django.templatetags.tz.do_timezone"),
        ("unlocalize", "python.django.templatetags.l10n.unlocalize"),
        ("language_name", "python.django.templatetags.i18n.language_name"),
        ("intcomma", "python.django.contrib.humanize.templatetags.humanize.intcomma"),
    ],
)
def test_each_filter_calls_the_function_django_registers_it_from(tmp_path: Path, applied: str, function: str) -> None:
    advisory = Advisory(
        "CVE-2099-5303",
        "django",
        "<4.2.17",
        "a filter misbehaves",
        Severity.LOW,
        entry_points=(AdvisoryEntryPoint(SymbolId(function), "registered as a filter"),),
    )

    analysis = check(tmp_path, project(tmp_path, f"{{{{ value|{applied} }}}}\n"), (advisory,))

    assert reached(tmp_path, analysis) == [(PAGE, 1, function)]


def test_a_template_no_python_call_names_still_calls_its_filters(tmp_path: Path) -> None:
    view = (
        "from django.views.generic import TemplateView\n\n"
        "class Profile(TemplateView):\n"
        "    template_name = 'app/profile.html'\n"
    )

    analysis = check(tmp_path, {"app/views.py": view, PAGE: "{{ bio|striptags }}\n"})

    assert reached(tmp_path, analysis) == [(PAGE, 1, STRIPTAGS)]


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs a file its owner cannot read")
def test_a_template_file_that_cannot_be_read_is_unread(tmp_path: Path) -> None:
    page = tmp_path / PAGE
    page.parent.mkdir(parents=True)
    page.write_text("{{ bio|striptags }}\n", encoding="utf-8")
    page.chmod(0)
    try:
        templates = project_templates(tmp_path)
    finally:
        page.chmod(0o644)

    assert (templates.calls, templates.unread) == ((), (f"{PAGE}, unreadable",))


# --------------------------------------------------------------------------- VEX


def test_a_template_applying_an_entry_point_makes_the_project_affected(tmp_path: Path) -> None:
    analysis = check(tmp_path, project(tmp_path, "<p>\n{{ bio|striptags }}\n</p>\n"))

    found = vex(tmp_path, analysis, "CVE-2099-5301")

    assert found["status"] == "affected"
    assert found["status_notes"] == f"Reached by the project's code at {PAGE}:2 {STRIPTAGS} (reachable)."


def test_templates_applying_no_entry_point_leave_the_project_not_affected(tmp_path: Path) -> None:
    base = {"app/templates/app/base.html": "{% block body %}{% endblock %}\n"}

    analysis = check(tmp_path, project(tmp_path, "{% extends 'app/base.html' %}{{ bio|lower }}\n", **base))

    assert vex(tmp_path, analysis, "CVE-2099-5301")["status"] == "not_affected"


UNREAD = [
    (VIEW.format(call=RENDER.format(name="request.GET['page']")), {}, "app.views:7 names a template by an expression"),
    (
        VIEW.format(call="HttpResponse(render_to_string(request.GET['page']))"),
        {},
        "app.views:7 names a template by an expression",
    ),
    (
        VIEW.format(call="TemplateResponse(request, template=request.GET['page'])"),
        {},
        "app.views:7 names a template by an expression",
    ),
    (VIEW.format(call=RENDER.format(name="'app/other.html'")), {}, "app.views:7 names 'app/other.html', not found"),
    (
        VIEW.format(call=RENDER.format(name="'app/profile.html'")),
        {PAGE: "<p>\n{% include 'app/other.html' %}\n</p>\n"},
        f"{PAGE}:2 names 'app/other.html', not found",
    ),
    (
        VIEW.format(call=RENDER.format(name="'app/profile.html'")),
        {PAGE: "{% extends layout %}\n"},
        f"{PAGE}:1 names a template by an expression",
    ),
]


@pytest.mark.parametrize(
    "view, templates, unread",
    UNREAD,
    ids=["render", "render-to-string", "template-response", "not-found", "include-not-found", "extends-expression"],
)
def test_a_template_the_engine_cannot_read_keeps_it_under_investigation(
    tmp_path: Path, view: str, templates: dict[str, str], unread: str
) -> None:
    files = {"app/views.py": view, PAGE: "{{ bio|lower }}\n", **templates}

    found = vex(tmp_path, check(tmp_path, files), "CVE-2099-5301")

    assert found["status"] == "under_investigation"
    assert found["status_notes"] == (
        "No analysed code reaches the entry points of CVE-2099-5301 (python.django.template.defaultfilters.striptags, "
        "python.django.utils.html.strip_tags), but a template can reach them, and the engine could not read every "
        f"template the project names: {unread}."
    )


def test_a_template_the_engine_cannot_read_leaves_advisories_no_template_reaches_alone(tmp_path: Path) -> None:
    view = VIEW.format(call=RENDER.format(name="request.GET['page']"))

    found = vex(tmp_path, check(tmp_path, {"app/views.py": view}, (STRIP_TAGS, SIGNING)), "CVE-2099-5302")

    assert found["status"] == "not_affected"
