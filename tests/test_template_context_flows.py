"""Render context data reaching template filters.

``render(request, "app/profile.html", {"bio": request.POST["bio"]})`` renders a template
applying ``{{ bio|striptags }}``: attacker input reaches ``striptags`` through the context,
so an advisory whose entry point is the filter is exploitable at the render call, not
only reachable at the template's line.

The engine links a filter to the context only where it is certain of the value:

- the context is a dict literal with constant keys, used by the render call and nothing
  else, inline or through a variable; a dict mutated or passed elsewhere, one unpacking
  another (``**extra``), or a context built any other way leaves the filter reachable;
- the filter's value is a context variable, directly or through ``{% for %}`` and
  ``{% with %}``, the templates it includes or extends by a constant name, the arguments
  of the filters before it, or the output of a ``{% filter %}`` block; a name a tag
  binds shadows the context, and ``{% include ... only %}`` passes none of it;
- a template name found in one file only: of two files of the same name, which one
  renders depends on the loaders.

A filter's argument (``cut:bio``) is its second argument, so an advisory naming only the
value as attacker argument is not exploitable through it. The same holds when a project
function renders the template with the values it receives.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from coretrace_python import engine
from coretrace_python.cache import ProjectCache
from coretrace_python.dependency import (
    Advisory,
    AdvisoryEntryPoint,
    AttackerArgument,
    dump_advisories,
    render_vex,
)
from coretrace_python.findings import Severity
from coretrace_python.semantic.symbols import SymbolId

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
STRIPTAGS = "python.django.template.defaultfilters.striptags"
CUT = "python.django.template.defaultfilters.cut"
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
HEADER = (
    "from django.http import HttpRequest, HttpResponse\n"
    "from django.shortcuts import render\n"
    "from django.template.loader import render_to_string\n"
    "from django.template.response import TemplateResponse\n\n"
    "def profile(request: HttpRequest):\n"
)
LINE = 7
PAGE = "app/templates/app/profile.html"
POSTED = "{'bio': request.POST['bio']}"


def advisory(*symbols: str, attacker: tuple[AttackerArgument, ...] = ()) -> Advisory:
    return Advisory(
        "CVE-2099-5401",
        "django",
        "<4.2.17",
        "a filter is quadratic in its input",
        Severity.MEDIUM,
        entry_points=tuple(AdvisoryEntryPoint(SymbolId(s), "a template filter", (), False, attacker) for s in symbols),
    )


def check(
    root: Path, body: str, templates: dict[str, str], advisories: tuple[Advisory, ...] | None = None, **options: Any
) -> engine.ProjectAnalysis:
    files = {"uv.lock": LOCK, "app/__init__.py": "", "app/views.py": HEADER + body, **templates}
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    chosen = advisories if advisories is not None else (advisory(STRIPTAGS),)
    (root / "advisories.json").write_text(dump_advisories(chosen), encoding="utf-8")
    return engine.analyze_project(root, [engine.BUNDLED_PLUGINS], **options)


def exploitable(analysis: engine.ProjectAnalysis) -> list[tuple[int, str, str, str]]:
    return [
        (f.span.start_line, f.metadata["symbol"], f.metadata["through"], f.metadata["sink_line"])
        for f in analysis.findings
        if f.rule_id == "exploitable-vulnerability"
    ]


def render(context: str = POSTED, name: str = "'app/profile.html'") -> str:
    return f"    return render(request, {name}, {context})\n"


# --------------------------------------------------------------------------- flows


def test_attacker_input_in_the_context_reaches_the_filter_the_template_applies(tmp_path: Path) -> None:
    analysis = check(tmp_path, render(), {PAGE: "<h1>Profile</h1>\n{{ bio|striptags }}\n"})

    assert exploitable(analysis) == [(LINE, STRIPTAGS, "app/profile.html", "2")]
    finding = next(f for f in analysis.findings if f.rule_id == "exploitable-vulnerability")
    assert finding.metadata["source_label"] == "http"
    assert Path(str(finding.span.source_id)).relative_to(tmp_path).as_posix() == "app/views.py"


@pytest.mark.parametrize(
    "body, line",
    [
        (f"    context = {POSTED}\n    return render(request, 'app/profile.html', context)\n", LINE + 1),
        (f"    return render(request, 'app/profile.html', context={POSTED})\n", LINE),
        (f"    return HttpResponse(render_to_string('app/profile.html', {POSTED}))\n", LINE),
        (f"    return TemplateResponse(request, 'app/profile.html', {POSTED})\n", LINE),
        ("    bio = request.POST['bio']\n    return render(request, 'app/profile.html', {'title': 'Me', 'bio': bio})\n", LINE + 1),
    ],
    ids=["variable", "keyword", "render-to-string", "template-response", "among-other-keys"],
)
def test_a_dict_literal_used_only_by_the_render_is_the_context(tmp_path: Path, body: str, line: int) -> None:
    analysis = check(tmp_path, body, {PAGE: "{{ bio|striptags }}\n"})

    assert [(found[0], found[1]) for found in exploitable(analysis)] == [(line, STRIPTAGS)]


CARD = "app/templates/app/card.html"
BASE = "app/templates/app/base.html"


@pytest.mark.parametrize(
    "templates",
    [
        {PAGE: "{{ bio|lower|striptags }}"},
        {PAGE: "{{ ''|default:bio|striptags }}"},
        {PAGE: "{% if bio|striptags %}yes{% endif %}"},
        {PAGE: "{% with text=bio %}{{ text|striptags }}{% endwith %}"},
        {PAGE: "{% with bio as text %}{{ text|striptags }}{% endwith %}"},
        {PAGE: "{% for line in bio.splitlines %}{{ line|striptags }}{% endfor %}"},
        {PAGE: "{% filter striptags %}<p>{{ bio }}</p>{% endfilter %}"},
        {PAGE: "{% include 'app/card.html' %}", CARD: "{{ bio|striptags }}"},
        {PAGE: "{% include 'app/card.html' with text=bio %}", CARD: "{{ text|striptags }}"},
        {PAGE: "{% for b in bio.split %}{% include 'app/card.html' %}{% endfor %}", CARD: "{{ b|striptags }}"},
        {PAGE: "{% extends 'app/base.html' %}", BASE: "{{ bio|striptags }}"},
        {PAGE: "{% with bio='Hello' %}{{ bio }}{% endwith %}{% for bio in 'ab' %}{% endfor %}{{ bio|striptags }}"},
    ],
    ids=[
        "chained", "earlier-argument", "tag-argument", "with", "with-as", "for", "filter-block", "include",
        "include-with", "include-in-loop", "extends", "after-shadowing-blocks",
    ],
)
def test_template_scopes_carry_the_context_value_to_the_filter(tmp_path: Path, templates: dict[str, str]) -> None:
    analysis = check(tmp_path, render(), templates)

    assert [(found[0], found[1]) for found in exploitable(analysis)] == [(LINE, STRIPTAGS)]


@pytest.mark.parametrize(
    "body, templates",
    [
        (render("{'bio': 'Hello', 'other': request.POST['bio']}"), {PAGE: "{{ bio|striptags }}"}),
        (render(), {PAGE: "{% with bio='Hello' %}{{ bio|striptags }}{% endwith %}"}),
        (render(), {PAGE: "{% for bio in 'ab' %}{{ bio|striptags }}{% endfor %}"}),
        (render(), {PAGE: "{% now 'Y' as bio %}{{ bio|striptags }}"}),
        (render(), {PAGE: "{% include 'app/card.html' only %}", CARD: "{{ bio|striptags }}"}),
        (render(), {PAGE: "{% include 'app/card.html' with bio='Hello' %}", CARD: "{{ bio|striptags }}"}),
        (render(), {PAGE: "{# {{ bio|striptags }} #}{{ bio }}"}),
        (
            f"    context = {POSTED}\n    context['bio'] = 'Hello'\n    return render(request, 'app/profile.html', context)\n",
            {PAGE: "{{ bio|striptags }}"},
        ),
        (
            f"    context = {POSTED}\n    log(context)\n    return render(request, 'app/profile.html', context)\n",
            {PAGE: "{{ bio|striptags }}"},
        ),
        (render("{**request.session, 'bio': request.POST['bio']}"), {PAGE: "{{ bio|striptags }}"}),
        (render("dict(bio=request.POST['bio'])"), {PAGE: "{{ bio|striptags }}"}),
        (
            render(),
            {PAGE: "{{ bio|striptags }}", "other/templates/app/profile.html": "{{ bio|striptags }}"},
        ),
    ],
    ids=[
        "other-key", "with-shadows", "for-shadows", "as-shadows", "include-only", "include-with-shadows",
        "comment", "mutated", "passed-elsewhere", "unpacked", "not-a-literal", "two-files",
    ],
)
def test_a_value_the_engine_cannot_link_to_the_filter_leaves_it_reachable(
    tmp_path: Path, body: str, templates: dict[str, str]
) -> None:
    analysis = check(tmp_path, body, templates)

    assert exploitable(analysis) == []


def test_a_filter_argument_is_its_second_argument(tmp_path: Path) -> None:
    value_only = (AttackerArgument("value", 0),)
    templates = {PAGE: "{{ 'Hello'|cut:bio }}\n{{ bio|striptags }}\n"}

    through_any = check(tmp_path / "any", render(), templates, (advisory(CUT),))
    through_value = check(tmp_path / "value", render(), templates, (advisory(CUT, STRIPTAGS, attacker=value_only),))

    assert [found[:2] for found in exploitable(through_any)] == [(LINE, CUT)]
    assert [found[:2] for found in exploitable(through_value)] == [(LINE, STRIPTAGS)]


def test_a_project_function_rendering_what_it_receives_carries_it_to_the_filter(tmp_path: Path) -> None:
    helpers = (
        "from django.shortcuts import render\n\n"
        "def show(request, bio):\n"
        "    return render(request, 'app/profile.html', {'bio': bio})\n"
    )
    views = (
        "from django.http import HttpRequest\n\n"
        "from app.helpers import show\n\n"
        "def profile(request: HttpRequest):\n"
        "    return show(request, request.POST['bio'])\n"
    )
    templates = {PAGE: "<p>\n{{ bio|striptags }}\n</p>\n", "app/helpers.py": helpers, "app/views.py": views}

    analysis = check(tmp_path, "", templates)

    assert exploitable(analysis) == [(6, STRIPTAGS, "app.helpers.show", "2")]


# --------------------------------------------------------------------------- engine


def test_the_vex_report_names_the_render_call_as_exploitable(tmp_path: Path) -> None:
    analysis = check(tmp_path, render(), {PAGE: "{{ bio|striptags }}\n"})
    evidence = (*analysis.findings, *analysis.suppressed, *analysis.accepted)

    document = render_vex(
        analysis.dependencies, analysis.advisories, evidence, analysis.coverage, tmp_path, "coretrace", "0.16.0", NOW
    )

    statement = json.loads(document)["statements"][0]
    assert statement["status"] == "affected"
    assert statement["status_notes"] == (
        f"Reached by the project's code at {PAGE}:1 {STRIPTAGS} (reachable); app/views.py:{LINE} {STRIPTAGS} (exploitable)."
    )


def test_a_template_losing_its_filter_invalidates_the_cached_results(tmp_path: Path) -> None:
    cache = ProjectCache(tmp_path / "cache")
    root = tmp_path / "src"

    first = check(root, render(), {PAGE: "{{ bio|striptags }}\n"}, cache=cache)
    (root / PAGE).write_text("{{ bio|lower }}\n", encoding="utf-8")
    second = engine.analyze_project(root, [engine.BUNDLED_PLUGINS], cache=cache)

    assert [found[1] for found in exploitable(first)] == [STRIPTAGS]
    assert second.reused == ()
    assert exploitable(second) == []


def test_modules_analysed_in_other_processes_see_the_template_filters(tmp_path: Path) -> None:
    analysis = check(tmp_path, render(), {PAGE: "{{ bio|striptags }}\n", "app/other.py": "X = 1\n"}, jobs=2)

    assert [found[1] for found in exploitable(analysis)] == [STRIPTAGS]
