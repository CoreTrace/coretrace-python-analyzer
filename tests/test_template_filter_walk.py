"""Acceptance tests for issue #279: the filters a template's render reaches are collected
once for each template and set of blocks the templates extending it override.

They are the same as before, in the same order: which filters, where they stand, the
template applying each, and the names of the render reaching its value and argument. The
results are kept for one analysis only, so that projects analysed one after the other do
not share them, and a result cut short by a cycle of includes is not reused.
"""

from __future__ import annotations

from pathlib import Path

from coretrace_python.taint.templates import project_templates

FILTERS = "python.django.template.defaultfilters"


def write(root: Path, templates: dict[str, str]) -> Path:
    for name, text in templates.items():
        path = root / "app" / "templates" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def described(root: Path) -> dict[str, list[tuple[str, str, int, int, str, tuple[str, ...], tuple[str, ...]]]]:
    """Each template's filters, in order: the function, the file and the line and column it
    is applied at, the template applying it, and the names reaching its value and argument."""

    return {
        name: [
            (
                str(f.symbol),
                Path(str(f.location.source_id)).name,
                f.location.start_line,
                f.location.start_column,
                f.template,
                f.value,
                f.argument,
            )
            for f in found
        ]
        for name, found in project_templates(root).filters.items()
    }


FIRST = {"page.html": "{{ bio|striptags }}\n{% include 'part.html' with note=bio %}\n", "part.html": "<p>{{ note|upper }}</p>\n"}
FIRST_FILTERS = {
    "page.html": [
        (f"{FILTERS}.striptags", "page.html", 1, 8, "page.html", ("bio",), ()),
        (f"{FILTERS}.upper", "part.html", 1, 12, "part.html", ("bio",), ()),
    ],
    "part.html": [(f"{FILTERS}.upper", "part.html", 1, 12, "part.html", ("note",), ())],
}
# The same names, other templates.
SECOND = {"page.html": "{% include 'part.html' %}\n{{ title|lower }}\n", "part.html": "{{ other|title }}\n"}
SECOND_FILTERS = {
    "page.html": [
        (f"{FILTERS}.lower", "page.html", 2, 10, "page.html", ("title",), ()),
        (f"{FILTERS}.title", "part.html", 1, 10, "part.html", ("other",), ()),
    ],
    "part.html": [(f"{FILTERS}.title", "part.html", 1, 10, "part.html", ("other",), ())],
}


def test_projects_analysed_one_after_the_other_each_get_their_own_filters(tmp_path: Path) -> None:
    first, second, again = (write(tmp_path / key, files) for key, files in (("first", FIRST), ("second", SECOND), ("again", FIRST)))

    assert described(first) == FIRST_FILTERS
    assert described(second) == SECOND_FILTERS
    assert described(again) == FIRST_FILTERS
    assert described(second) == SECOND_FILTERS


def test_a_template_reached_directly_and_through_a_child_overriding_its_block(tmp_path: Path) -> None:
    # child.html renders base.html with its own body: base.html's upper is not reached
    # through it, though it is through the direct include.
    root = write(
        tmp_path,
        {
            "base.html": "{% block body %}{{ a|upper }}{% endblock %}{{ b|lower }}\n",
            "child.html": "{% extends 'base.html' %}{% block body %}{{ c|title }}{% endblock %}\n",
            "page.html": "{% include 'base.html' %}{% include 'child.html' %}\n",
        },
    )

    assert described(root) == {
        "base.html": [
            (f"{FILTERS}.upper", "base.html", 1, 22, "base.html", ("a",), ()),
            (f"{FILTERS}.lower", "base.html", 1, 49, "base.html", ("b",), ()),
        ],
        "child.html": [
            (f"{FILTERS}.title", "child.html", 1, 47, "child.html", ("c",), ()),
            (f"{FILTERS}.lower", "base.html", 1, 49, "base.html", ("b",), ()),
        ],
        "page.html": [
            (f"{FILTERS}.upper", "base.html", 1, 22, "base.html", ("a",), ()),
            (f"{FILTERS}.lower", "base.html", 1, 49, "base.html", ("b",), ()),
            (f"{FILTERS}.title", "child.html", 1, 47, "child.html", ("c",), ()),
        ],
    }


def test_a_template_reached_inside_a_cycle_and_from_outside_it(tmp_path: Path) -> None:
    # a.html is walked first: inside it, b.html's walk stops at a.html and misses its
    # upper. c.html reaches b.html from outside the cycle, and gets a.html's upper.
    root = write(
        tmp_path,
        {
            "a.html": "{{ x|upper }}{% include 'b.html' %}\n",
            "b.html": "{{ y|lower }}{% include 'a.html' %}\n",
            "c.html": "{% include 'b.html' %}\n",
        },
    )

    assert described(root) == {
        "a.html": [(f"{FILTERS}.upper", "a.html", 1, 6, "a.html", ("x",), ()), (f"{FILTERS}.lower", "b.html", 1, 6, "b.html", ("y",), ())],
        "b.html": [(f"{FILTERS}.lower", "b.html", 1, 6, "b.html", ("y",), ()), (f"{FILTERS}.upper", "a.html", 1, 6, "a.html", ("x",), ())],
        "c.html": [(f"{FILTERS}.lower", "b.html", 1, 6, "b.html", ("y",), ()), (f"{FILTERS}.upper", "a.html", 1, 6, "a.html", ("x",), ())],
    }
