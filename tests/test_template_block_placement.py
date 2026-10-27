"""Acceptance tests for issue #285: a template's render is put together over its extends
chain as Django puts it.

The root's blocks standing in no other block are placed; a placed block renders its most
derived definition, then, while a definition renders ``{{ block.super }}``, the next one
up; the blocks a rendered definition holds are placed in turn. A filter or an include
renders when the definition of the innermost block it stands in renders. A block no
template of the chain places never renders. When the chain reaches no known root, every
block counts as placed, so that no filter is dropped on a placement the engine cannot
establish. Each expectation below is what Django 5.1.15 applies to the same templates.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.dependency import Advisory, AdvisoryEntryPoint, dump_advisories
from coretrace_python.findings import Severity
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint.templates import project_templates

FILTERS = "python.django.template.defaultfilters"
STRIPTAGS = f"{FILTERS}.striptags"
ADVISORY = Advisory(
    "CVE-2099-8501",
    "django",
    "<4.2.17",
    "striptags is quadratic in its input",
    Severity.MEDIUM,
    entry_points=(AdvisoryEntryPoint(SymbolId(STRIPTAGS), "a template filter"),),
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
    "from django.http import HttpRequest\n"
    "from django.shortcuts import render\n\n"
    "def page(request: HttpRequest):\n"
    "    return render(request, 'page.html', {'v': request.POST['bio']})\n"
)
PAGE = "{% extends 'base.html' %}\n{% block body %}hello{% endblock %}\n{% block extra %}{{ v|striptags }}{% endblock %}\n"


def write(root: Path, templates: dict[str, str]) -> Path:
    for name, text in templates.items():
        path = root / "app" / "templates" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def described(root: Path, name: str) -> list[tuple[str, str, int, int, tuple[str, ...]]]:
    """The filters rendering ``name`` reaches: the function, the template applying it, the
    line and column it is applied at, and the names reaching its value."""

    return [
        (str(f.symbol).rsplit(".", 1)[1], f.template, f.location.start_line, f.location.start_column, f.value)
        for f in project_templates(root).filters[name]
    ]


@pytest.mark.parametrize(
    ("base", "expected"),
    [
        ("<main>{% block body %}{% endblock %}</main>\n", []),
        ("<main>{% block body %}{% endblock %}{% block extra %}{% endblock %}</main>\n", [(5, "page.html", "3")]),
    ],
    ids=["a-block-no-parent-places", "control-the-parent-places-it"],
)
def test_input_reaches_a_filter_only_in_a_block_a_parent_places(
    tmp_path: Path, base: str, expected: list[tuple[int, str, str]]
) -> None:
    # Django renders "<main>hello</main>" without the parent's extra block, and never
    # calls striptags; with it, striptags receives the request's bio.
    root = write(tmp_path, {"base.html": base, "page.html": PAGE})
    for relative, text in {"uv.lock": LOCK, "app/__init__.py": "", "app/views.py": VIEW}.items():
        (root / relative).write_text(text, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories((ADVISORY,)), encoding="utf-8")
    findings = engine.analyze_project(root, [engine.BUNDLED_PLUGINS]).findings

    assert sorted(
        (f.span.start_line, f.metadata["through"], f.metadata["sink_line"])
        for f in findings
        if f.rule_id == "exploitable-vulnerability" and f.metadata["advisory"] == ADVISORY.id
    ) == expected


BASE = "{% block content %}{% block main %}{{ v|upper }}{% endblock %}{% endblock %}\n"
FORM = "{% extends 'base.html' %}\n{% block main %}{{ v|striptags }}{% endblock %}\n"


@pytest.mark.parametrize(
    ("page", "expected"),
    [
        ("{% extends 'form.html' %}\n{% block content %}hello{% endblock %}\n", []),
        ("{% extends 'form.html' %}\n{% block title %}hello{% endblock %}\n", [("striptags", "form.html", 2, 22, ("v",))]),
    ],
    ids=["the-placeholder-replaced", "control-content-kept"],
)
def test_a_block_whose_only_placeholder_a_child_replaces_does_not_render(
    tmp_path: Path, page: str, expected: list[tuple[str, str, int, int, tuple[str, ...]]]
) -> None:
    # page.html replaces content, which held the only main placeholder: Django renders
    # "hello", and form.html's main never; without that, it applies striptags.
    root = write(tmp_path, {"base.html": BASE, "form.html": FORM, "page.html": page})

    assert described(root, "page.html") == expected


HEADER_BASE = "{% block content %}{% block header %}{% block main_header %}{% include 'header.html' %}{% endblock %}{% endblock %}{% endblock %}\n"


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("{{ block.super }}", [("upper", "header.html", 1, 6, ("v",))]),
        ("hello", []),
    ],
    ids=["block-super-inside-a-replaced-block", "control-without-block-super"],
)
def test_a_parent_block_rendered_through_block_super_inside_a_replaced_block_renders(
    tmp_path: Path, header: str, expected: list[tuple[str, str, int, int, tuple[str, ...]]]
) -> None:
    # page.html replaces content but defines header inside it: through {{ block.super }},
    # Django renders the parent's header, its main_header and the include it holds.
    page = "{% extends 'base.html' %}\n{% block content %}{% block header %}" + header + "{% endblock %}{% endblock %}\n"
    root = write(tmp_path, {"base.html": HEADER_BASE, "page.html": page, "header.html": "{{ v|upper }}\n"})

    assert described(root, "page.html") == expected


def test_a_chain_of_three_templates_renders_what_each_level_places(tmp_path: Path) -> None:
    # base.html places content; mid.html's content places side; page.html extends side
    # through {{ block.super }}. Its aside, which no template of the chain places, never
    # renders: Django applies striptags, then mid.html's upper.
    root = write(
        tmp_path,
        {
            "base.html": "<main>{% block content %}{% endblock %}</main>\n",
            "mid.html": "{% extends 'base.html' %}\n{% block content %}{% block side %}{{ v|upper }}{% endblock %}{% endblock %}\n",
            "page.html": (
                "{% extends 'mid.html' %}\n"
                "{% block side %}{{ block.super }}{{ v|striptags }}{% endblock %}\n"
                "{% block aside %}{{ v|upper }}{% endblock %}\n"
            ),
        },
    )

    assert described(root, "page.html") == [("striptags", "page.html", 2, 39, ("v",)), ("upper", "mid.html", 2, 41, ("v",))]


@pytest.mark.parametrize(
    ("parent", "unread"),
    [
        ("parent", "app/templates/page.html:1 names a template by an expression"),
        ("'missing.html'", "app/templates/page.html:1 names 'missing.html', not found"),
    ],
    ids=["named-by-an-expression", "not-found"],
)
def test_a_parent_the_engine_cannot_follow_keeps_every_block_placed(tmp_path: Path, parent: str, unread: str) -> None:
    # The text outside the blocks of a template extending another never renders.
    root = write(tmp_path, {"page.html": "{% extends " + parent + " %}\n{% block body %}{{ v|upper }}{% endblock %}{{ v|striptags }}\n"})

    assert described(root, "page.html") == [("upper", "page.html", 2, 22, ("v",))]
    assert project_templates(root).unread == (unread,)


def test_an_extends_cycle_keeps_every_block_placed(tmp_path: Path) -> None:
    # Django refuses to render either template; the engine keeps their filters.
    root = write(
        tmp_path,
        {
            "a.html": "{% extends 'b.html' %}\n{% block body %}{{ v|upper }}{% endblock %}\n",
            "b.html": "{% extends 'a.html' %}\n{% block side %}{{ v|striptags }}{% endblock %}\n",
        },
    )

    assert described(root, "a.html") == [("upper", "a.html", 2, 22, ("v",)), ("striptags", "b.html", 2, 22, ("v",))]
    assert described(root, "b.html") == [("striptags", "b.html", 2, 22, ("v",)), ("upper", "a.html", 2, 22, ("v",))]



def test_a_chain_lists_its_filters_in_the_order_of_a_walk_through_its_extends(tmp_path: Path) -> None:
    # What the chain applies from the template up, then what it includes from the root
    # down: base.html's include comes before page.html's.
    root = write(
        tmp_path,
        {
            "base.html": "{% include 'b.html' %}{% block body %}{% endblock %}\n",
            "page.html": "{% extends 'base.html' %}\n{% block body %}{% include 'a.html' %}{% endblock %}\n",
            "a.html": "{{ v|upper }}\n",
            "b.html": "{{ v|striptags }}\n",
        },
    )

    assert described(root, "page.html") == [("striptags", "b.html", 1, 6, ("v",)), ("upper", "a.html", 1, 6, ("v",))]
