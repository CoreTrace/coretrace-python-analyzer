"""A template file the engine cannot read proves nothing about escaping.

The analyzer establishes that a Django template escapes everything it renders only from
its text. A template file it cannot read, because of its permissions, is not assumed to
escape, no more than a template it cannot find: the flow through ``render_to_string``
stays ``xss``, and a template extending or including the unreadable one is not
established either.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.taint.templates import escaped_templates

VIEW = (
    "from django.http import HttpRequest, HttpResponse\n"
    "from django.template.loader import render_to_string\n\n"
    "def page(request: HttpRequest):\n"
    "    return HttpResponse(render_to_string('app/page.html', {'name': request.GET['name']}))\n"
)
ESCAPING = "<p>{{ name }}</p>\n"

pytestmark = pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs a file its owner cannot read")


def write(root: Path, files: dict[str, str]) -> None:
    for relative, text in files.items():
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_text(text, encoding="utf-8")


def unreadable(path: Path) -> None:
    path.chmod(0)


@pytest.fixture
def readable_again(tmp_path: Path):  # type: ignore[no-untyped-def]
    yield
    for path in tmp_path.rglob("*"):
        if path.is_file():
            path.chmod(0o644)


def test_a_template_file_that_cannot_be_read_is_not_escaped(tmp_path: Path, readable_again: None) -> None:
    write(tmp_path, {"app/templates/app/page.html": ESCAPING, "app/templates/app/other.html": ESCAPING})
    unreadable(tmp_path / "app/templates/app/page.html")

    assert escaped_templates(tmp_path) == frozenset({"app/other.html"})


def test_rendering_a_template_that_cannot_be_read_stays_cross_site_scripting(tmp_path: Path, readable_again: None) -> None:
    write(tmp_path, {"app/views.py": VIEW, "app/templates/app/page.html": ESCAPING})
    unreadable(tmp_path / "app/templates/app/page.html")

    findings = engine.analyze_project(tmp_path, [engine.BUNDLED_PLUGINS]).findings

    assert [f.span.start_line for f in findings if f.rule_id == "xss"] == [5]


@pytest.mark.parametrize("tag", ["{% extends 'app/base.html' %}", "{% include 'app/base.html' %}"])
def test_a_template_needing_one_that_cannot_be_read_is_not_escaped(tmp_path: Path, readable_again: None, tag: str) -> None:
    write(tmp_path, {"app/templates/app/page.html": tag + ESCAPING, "app/templates/app/base.html": ESCAPING})
    unreadable(tmp_path / "app/templates/app/base.html")

    assert escaped_templates(tmp_path) == frozenset()
