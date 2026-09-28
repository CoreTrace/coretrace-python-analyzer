"""Project tag libraries overriding the filters of Django's own libraries (issue #183).

A project library, ``app/templatetags/custom.py``, registering a filter named
``striptags`` replaces ``django.template.defaultfilters.striptags`` in every template
loading it before applying the filter: ``{% load custom %}{{ bio|striptags }}`` calls
the project's function, so it is no evidence of a call to the vulnerable built-in, at
the template's line or from the render's context. The engine reads what a library
registers with its own semantic layers, whatever the import spelling and the
registration form, and follows Django's parse-time rules: a load affects only the
filters after it, a later load overrides an earlier one, ``{% load a from lib %}``
selects, and Django's own libraries change nothing.

Where the engine cannot tell what a library registers, because no file gives the
library, it cannot read or understand the file, or several apps give the name and
disagree, the filter's identity is uncertain: it claims no call, and lists the load
among the templates the project names but it could not read, so an advisory naming
the filter stays ``under_investigation``. A library that registers no filter of the
built-in's name leaves the built-in what it was.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from coretrace_python import engine
from coretrace_python.dependency import Advisory, AdvisoryEntryPoint, dump_advisories, render_vex
from coretrace_python.findings import Severity
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import project_templates
from coretrace_python.taint.templates import escaped_templates

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)
STRIPTAGS = "python.django.template.defaultfilters.striptags"
STRIP_TAGS = "python.django.utils.html.strip_tags"
ADVISORY = Advisory(
    "CVE-2099-5301",
    "django",
    "<4.2.17",
    "strip_tags is quadratic in nested incomplete tags",
    Severity.MEDIUM,
    entry_points=(
        AdvisoryEntryPoint(SymbolId(STRIP_TAGS), "changed by the fix"),
        AdvisoryEntryPoint(SymbolId(STRIPTAGS), "the striptags filter calls strip_tags"),
    ),
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
    "from django.http import HttpRequest, HttpResponse\n"
    "from django.shortcuts import render\n"
    "from django.template.loader import render_to_string\n"
    "from django.template.response import TemplateResponse\n\n"
    "def profile(request: HttpRequest):\n"
    "    return {call}\n"
)
RENDER = "render(request, {name}, {{'bio': request.POST['bio']}})"
PAGE = "app/templates/app/profile.html"
LIBRARY = "app/templatetags/custom.py"
REGISTER = "from django import template\n\nregister = template.Library()\n\n"
REPLACE = '@register.filter(name="striptags")\ndef replace(value):\n    return "constant"\n'
SHOUT = '@register.filter\ndef shout(value):\n    return value.upper()\n'
LOADED = "{% load custom %}\n{{ bio|striptags }}\n"
NOT_FOUND = f"{PAGE}:1 loads 'crispy_forms_tags', not found"


def write(root: Path, files: dict[str, str]) -> None:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def check(root: Path, files: dict[str, str]) -> engine.ProjectAnalysis:
    write(root, {"uv.lock": LOCK, "app/__init__.py": "", **files})
    (root / "advisories.json").write_text(dump_advisories((ADVISORY,)), encoding="utf-8")
    return engine.analyze_project(root, [engine.BUNDLED_PLUGINS])


def project(template: str, name: str = "'app/profile.html'", **files: str) -> dict[str, str]:
    return {"app/views.py": VIEW.format(call=RENDER.format(name=name)), PAGE: template, **files}


def library(body: str = REPLACE, name: str = "custom", app: str = "app") -> dict[str, str]:
    """A tag library ``name`` of ``app`` registering what ``body`` registers."""

    return {f"{app}/__init__.py": "", f"{app}/templatetags/__init__.py": "", f"{app}/templatetags/{name}.py": REGISTER + body}


def reached(root: Path, analysis: engine.ProjectAnalysis) -> list[tuple[str, int, str]]:
    return [
        (Path(str(f.span.source_id)).relative_to(root).as_posix(), f.span.start_line, f.metadata["symbol"])
        for f in analysis.findings
        if f.rule_id == "reachable-vulnerability"
    ]


def exploitable(analysis: engine.ProjectAnalysis) -> list[tuple[int, str, str, str]]:
    return [
        (f.span.start_line, f.metadata["symbol"], f.metadata["through"], f.metadata["sink_line"])
        for f in analysis.findings
        if f.rule_id == "exploitable-vulnerability"
    ]


def vex(root: Path, analysis: engine.ProjectAnalysis) -> dict[str, Any]:
    evidence = (*analysis.findings, *analysis.suppressed, *analysis.accepted)
    document = render_vex(
        analysis.dependencies, analysis.advisories, evidence, analysis.coverage, root, "coretrace", "0.18.0", NOW
    )
    return next(s for s in json.loads(document)["statements"] if s["vulnerability"]["name"] == ADVISORY.id)


# --------------------------------------------------------------------------- overrides


def test_a_project_filter_registered_under_a_built_in_name_replaces_the_built_in(tmp_path: Path) -> None:
    analysis = check(tmp_path, project(LOADED, **library()))

    assert reached(tmp_path, analysis) == []
    assert exploitable(analysis) == []
    assert vex(tmp_path, analysis)["status"] == "not_affected"
    assert analysis.coverage.unread_templates == ()


@pytest.mark.parametrize(
    "registration",
    [
        REPLACE,
        '@register.filter("striptags")\ndef replace(value):\n    return "constant"\n',
        '@register.filter\ndef striptags(value):\n    return "constant"\n',
        '@register.filter()\ndef striptags(value):\n    return "constant"\n',
        '@register.filter(is_safe=True)\ndef striptags(value):\n    return "constant"\n',
        '@register.filter("striptags", is_safe=True)\ndef replace(value):\n    return "constant"\n',
        '@register.filter(name="striptags", is_safe=True)\ndef replace(value):\n    return "constant"\n',
        (
            "from django.template.defaultfilters import stringfilter\n\n"
            '@register.filter\n@stringfilter\ndef striptags(value):\n    return "constant"\n'
        ),
        'def replace(value):\n    return "constant"\n\nregister.filter("striptags", replace)\n',
        'def replace(value):\n    return "constant"\n\nregister.filter(name="striptags", filter_func=replace)\n',
        'def replace(value):\n    return "constant"\n\nregister.filter("striptags", filter_func=replace)\n',
        'def striptags(value):\n    return "constant"\n\nregister.filter(striptags)\n',
        'def striptags(value):\n    return "constant"\n\nregister.filter(striptags, is_safe=True)\n',
        'register.filter("striptags", lambda value: "constant")\n',
        'if True:\n    @register.filter(name="striptags")\n    def replace(value):\n        return "constant"\n',
        (
            'try:\n    @register.filter(name="striptags")\n    def replace(value):\n        return "constant"\n'
            "except ImportError:\n    pass\n"
        ),
        'def setup():\n    @register.filter(name="striptags")\n    def replace(value):\n        return "constant"\n\nsetup()\n',
    ],
    ids=[
        "name-keyword", "name-positional", "bare", "empty-call", "flags-only", "name-and-flag",
        "name-keyword-and-flag", "stringfilter", "call-positional", "call-keywords", "call-mixed",
        "call-function", "call-function-and-flag", "call-lambda", "in-if", "in-try", "in-function",
    ],
)
def test_every_registration_form_overrides(tmp_path: Path, registration: str) -> None:
    analysis = check(tmp_path, project(LOADED, **library(registration)))

    assert reached(tmp_path, analysis) == []
    assert analysis.coverage.unread_templates == ()


@pytest.mark.parametrize(
    "binding",
    [
        "from django import template\n\nregister = template.Library()\n",
        "from django.template import Library\n\nregister = Library()\n",
        "from django.template.library import Library\n\nregister = Library()\n",
        "import django.template\n\nregister = django.template.Library()\n",
        "from django import template as t\n\nregister = t.Library()\n",
        "from django.template import Library as L\n\nregister = L()\n",
        "from django.template import Library\n\nregister: Library = Library()\n",
    ],
    ids=["from-django", "from-template", "from-library", "import", "module-alias", "class-alias", "annotated"],
)
def test_every_import_spelling_of_the_library_class_is_recognised(tmp_path: Path, binding: str) -> None:
    files = {**library(), LIBRARY: binding + "\n" + REPLACE}

    analysis = check(tmp_path, project(LOADED, **files))

    assert reached(tmp_path, analysis) == []
    assert analysis.coverage.unread_templates == ()


@pytest.mark.parametrize(
    "template, files, line",
    [
        (LOADED, library(SHOUT), 2),
        ("{{ bio|striptags }}\n", library(), 1),
        ("{% load humanize %}\n{{ bio|striptags }}\n", {}, 2),
    ],
    ids=["another-filter", "not-loaded", "django-library"],
)
def test_without_an_overriding_load_the_built_in_is_called(
    tmp_path: Path, template: str, files: dict[str, str], line: int
) -> None:
    analysis = check(tmp_path, project(template, **files))

    assert reached(tmp_path, analysis) == [(PAGE, line, STRIPTAGS)]
    assert analysis.coverage.unread_templates == ()


def test_a_load_affects_only_the_filters_after_it(tmp_path: Path) -> None:
    template = "{{ bio|striptags }}\n{% load custom %}\n{{ bio|striptags }}\n"

    analysis = check(tmp_path, project(template, **library()))

    assert reached(tmp_path, analysis) == [(PAGE, 1, STRIPTAGS)]


@pytest.mark.parametrize(
    "loads, unread",
    [
        ("{% load custom %}{% load humanize %}", ()),
        ("{% load humanize %}{% load custom %}", ()),
        ("{% load other %}{% load custom %}", ()),
        ("{% load custom %}{% load other %}", ()),
        ("{% load crispy_forms_tags %}{% load custom %}", ()),
        ("{% load custom %}{% load crispy_forms_tags %}", (NOT_FOUND,)),
        ("{% load crispy_forms_tags %}{% load other %}", (NOT_FOUND,)),
    ],
    ids=[
        "django-after", "django-before", "another-before", "another-after", "unknown-before",
        "unknown-after", "unknown-then-another",
    ],
)
def test_later_loads_override_earlier_ones(tmp_path: Path, loads: str, unread: tuple[str, ...]) -> None:
    files = {**library(), **library(SHOUT, name="other")}

    analysis = check(tmp_path, project(loads + "\n{{ bio|striptags }}\n", **files))

    assert reached(tmp_path, analysis) == []
    assert analysis.coverage.unread_templates == unread


@pytest.mark.parametrize(
    "load, calls, unread",
    [
        ("{% load striptags from custom %}", [], ()),
        ("{% load shout striptags from custom %}", [], ()),
        ("{% load shout from custom %}", [(PAGE, 2, STRIPTAGS)], ()),
        ("{% load striptags from crispy_forms_tags %}", [], (NOT_FOUND,)),
        ("{% load shout from crispy_forms_tags %}", [(PAGE, 2, STRIPTAGS)], ()),
    ],
    ids=["selected", "among-selected", "not-selected", "selected-unknown", "not-selected-unknown"],
)
def test_a_selective_load_overrides_only_the_filters_it_names(
    tmp_path: Path, load: str, calls: list[tuple[str, int, str]], unread: tuple[str, ...]
) -> None:
    analysis = check(tmp_path, project(load + "\n{{ bio|striptags }}\n", **library(REPLACE + "\n" + SHOUT)))

    assert reached(tmp_path, analysis) == calls
    assert analysis.coverage.unread_templates == unread


# --------------------------------------------------------------------------- uncertainty


def test_an_unknown_library_leaves_the_filter_uncertain(tmp_path: Path) -> None:
    analysis = check(tmp_path, project("{% load crispy_forms_tags %}\n{{ bio|striptags }}\n"))

    assert reached(tmp_path, analysis) == []
    assert exploitable(analysis) == []
    assert analysis.coverage.unread_templates == (NOT_FOUND,)
    statement = vex(tmp_path, analysis)
    assert statement["status"] == "under_investigation"
    assert statement["status_notes"] == (
        f"No analysed code reaches the entry points of {ADVISORY.id} ({STRIPTAGS}, {STRIP_TAGS}), but a template "
        f"can reach them, and the engine could not read every template the project names: {NOT_FOUND}."
    )


def test_an_unknown_library_whose_filters_are_no_built_in_adds_nothing(tmp_path: Path) -> None:
    analysis = check(tmp_path, project("{% load crispy_forms_tags %}\n{{ form|crispy }}\n"))

    assert reached(tmp_path, analysis) == []
    assert analysis.coverage.unread_templates == ()
    assert vex(tmp_path, analysis)["status"] == "not_affected"


@pytest.mark.parametrize(
    "text",
    [
        "from django import template\n\nregister = template.Library(\n",
        REGISTER.replace("\n\nregister", '\n\nNAME = "striptags"\nregister') + REPLACE.replace('"striptags"', "NAME"),
        REGISTER + 'def replace(value):\n    return "constant"\n\nregister.filters["striptags"] = replace\n',
        (
            "from django import template\n\n"
            'def replace(value):\n    return "constant"\n\n'
            'register = template.Library(filters={"striptags": replace})\n'
        ),
        REGISTER + "from app.setup import setup\n\nsetup(register)\n",
        REGISTER + 'from app.setup import setup\n\n@setup(register)\ndef replace(value):\n    return "constant"\n',
        REGISTER.replace("register", "library") + REPLACE.replace("register", "library"),
        REGISTER + 'add = register.filter\n\ndef replace(value):\n    return "constant"\n\nadd("striptags", replace)\n',
        REGISTER + 'ARGUMENTS = ("striptags",)\n\n@register.filter(*ARGUMENTS)\ndef replace(value):\n    return "constant"\n',
        REGISTER + 'def replace(value):\n    return "constant"\n\nregister.filter(name="striptags")(replace)\n',
        REGISTER + 'from django.template.defaultfilters import striptags\n\nregister.filter(striptags.__name__, striptags)\n',
    ],
    ids=[
        "syntax-error", "name-variable", "filters-item", "filters-argument", "passed-elsewhere",
        "passed-to-a-decorator", "register-unbound", "filter-as-value", "starred", "chained-call", "attribute-name",
    ],
)
def test_a_library_the_engine_cannot_read_leaves_the_filter_uncertain(tmp_path: Path, text: str) -> None:
    files = {**library(), LIBRARY: text}

    analysis = check(tmp_path, project(LOADED, **files))

    assert reached(tmp_path, analysis) == []
    assert analysis.coverage.unread_templates == (f"{PAGE}:1 loads 'custom', not read",)


@pytest.mark.parametrize(
    "first, second, calls, unread",
    [
        (REPLACE, REPLACE, [], ()),
        (REPLACE, SHOUT, [], (f"{PAGE}:1 loads 'custom', found in several files",)),
        (SHOUT, SHOUT, [(PAGE, 2, STRIPTAGS)], ()),
    ],
    ids=["both-override", "one-overrides", "neither-overrides"],
)
def test_two_apps_sharing_a_library_name_must_agree(
    tmp_path: Path, first: str, second: str, calls: list[tuple[str, int, str]], unread: tuple[str, ...]
) -> None:
    files = {**library(first), **library(second, app="other")}

    analysis = check(tmp_path, project(LOADED, **files))

    assert reached(tmp_path, analysis) == calls
    assert analysis.coverage.unread_templates == unread


# --------------------------------------------------------------------------- consequences


def test_an_override_calling_the_vulnerable_function_is_an_ordinary_call_at_its_line(tmp_path: Path) -> None:
    body = (
        "from django.utils.html import strip_tags\n\n"
        '@register.filter(name="striptags")\ndef replace(value):\n    return strip_tags(value)\n'
    )

    analysis = check(tmp_path, project(LOADED, **library(body)))

    assert reached(tmp_path, analysis) == [(LIBRARY, 9, STRIP_TAGS)]


def test_an_override_removes_the_filter_from_the_template_calls(tmp_path: Path) -> None:
    other = "app/templates/app/other.html"
    views = project(LOADED)["app/views.py"] + "\ndef other(request: HttpRequest):\n    return " + RENDER.format(name="'app/other.html'") + "\n"
    files = {**project(LOADED, **library()), "app/views.py": views, other: "{{ bio|striptags }}\n"}

    analysis = check(tmp_path, files)
    templates = project_templates(tmp_path)

    assert exploitable(analysis) == [(10, STRIPTAGS, "app/other.html", "1")]
    assert [(Path(str(c.span.source_id)).relative_to(tmp_path).as_posix(), c.span.start_line) for c in templates.calls] == [
        (other, 1)
    ]
    assert templates.filters["app/profile.html"] == ()
    assert [(f.template, f.value) for f in templates.filters["app/other.html"]] == [("app/other.html", ("bio",))]


def test_a_template_loading_an_overriding_library_is_not_established_to_escape(tmp_path: Path) -> None:
    write(tmp_path, {"app/__init__.py": "", PAGE: LOADED, **library()})

    assert escaped_templates(tmp_path) == frozenset()
