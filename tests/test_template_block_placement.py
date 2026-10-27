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

from coretrace_python.taint.templates import project_templates


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
