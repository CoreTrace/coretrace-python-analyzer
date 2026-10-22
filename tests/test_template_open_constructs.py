"""Acceptance tests for issue #272: what a template leaves open, and a template tag inside a
comment, are read as the browser receives the rendered page.

Every construct is read once, so the inspection is linear in the size of the template.
Each inspection and analysis runs in a subprocess with a timeout, so that one that does
not end fails instead of hanging the suite.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

TIMEOUT = 60
# Far beyond what a quadratic inspection reads within the timeout; a linear one takes
# well under a second.
SIZE = 3_000_000

ESCAPED_TEMPLATES = (
    "import json, sys\n"
    "from pathlib import Path\n"
    "from coretrace_python.taint.templates import escaped_templates\n"
    "print(json.dumps(sorted(escaped_templates(Path(sys.argv[1])))))\n"
)

VIEW = (
    "from django.http import HttpRequest, HttpResponse\n"
    "from django.template.loader import render_to_string\n\n"
    "def page(request: HttpRequest):\n"
    "    return HttpResponse(render_to_string('page.html', {'name': request.GET['name']}))\n"
)


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        pytest.fail(f"{command[1:3]} did not end within {TIMEOUT} s")


def project(tmp_path: Path, templates: dict[str, str]) -> Path:
    root = tmp_path / "project"
    (root / "app" / "templates").mkdir(parents=True, exist_ok=True)
    (root / "app" / "views.py").write_text(VIEW, encoding="utf-8")
    for name, content in templates.items():
        (root / "app" / "templates" / name).write_text(content, encoding="utf-8")
    return root


def escaped(tmp_path: Path, templates: dict[str, str]) -> list[str]:
    completed = run([sys.executable, "-c", ESCAPED_TEMPLATES, str(project(tmp_path, templates))])
    assert completed.returncode == 0, completed.stderr
    names: list[str] = json.loads(completed.stdout)
    return names


def xss(tmp_path: Path, templates: dict[str, str]) -> list[tuple[str, int]]:
    root = project(tmp_path, templates)
    completed = run([sys.executable, "-m", "coretrace_python", "--check", str(root), "--format", "json"])
    findings = json.loads(completed.stdout)["findings"]
    return [(f["location"]["path"], f["location"]["line"]) for f in findings if f["rule_id"] == "xss"]


# The reproductions of #272, rendered with Django and run in a browser: the variable runs
# as script in each (in C, the browser never runs a script left open at the end of the
# document, but a template cannot tell whether it is rendered alone).
@pytest.mark.parametrize(
    "templates",
    [
        {"page.html": "<script>var name = {{ name }};</script>\n"},
        {"page.html": '<!-- {% include "close.html" %}<script>var name = {{ name }};</script>\n', "close.html": "-->"},
    ],
    ids=[
        "B-closed-in-same-template",
        "D-comment-closed-by-include",
    ],
)
def test_a_variable_the_rendered_page_runs_as_script_is_cross_site_scripting(
    tmp_path: Path, templates: dict[str, str]
) -> None:
    assert xss(tmp_path, templates) == [("app/views.py", 5)]


def test_a_variable_in_a_comment_holding_no_template_tag_stays_escaped(tmp_path: Path) -> None:
    templates = {"page.html": "<p>hello</p><!-- {{ name }} -->\n"}

    assert escaped(tmp_path, templates) == ["page.html"]
    assert xss(tmp_path, templates) == []


@pytest.mark.parametrize(
    "template",
    [
        '{% if debug %}<!--{% endif %}<a onclick="{{ name }}">',
        '<!--><a onclick="{{ name }}">',
        '<!---><a onclick="{{ name }}">',
        '<!-- note --!><a onclick="{{ name }}">',
    ],
    ids=["condition-around-the-opener", "abrupt-empty", "abrupt-dash", "bang-close"],
)
def test_a_comment_ends_at_its_close_or_at_a_template_tag_inside_it(tmp_path: Path, template: str) -> None:
    assert escaped(tmp_path, {"page.html": template, "x.html": ""}) == ["x.html"]


def test_including_a_template_that_ends_inside_a_comment_stays_established(tmp_path: Path) -> None:
    templates = {"fragment.html": "<!-- note", "page.html": "{% include 'fragment.html' %} -->\n<p>{{ name }}</p>\n"}

    assert escaped(tmp_path, templates) == ["fragment.html", "page.html"]


def test_extending_a_template_that_ends_inside_a_script_stays_established(tmp_path: Path) -> None:
    # A child's blocks stand where the parent places them, before the parent's end.
    templates = {
        "base.html": "<p>{% block body %}{% endblock %}</p><script>\n",
        "page.html": "{% extends 'base.html' %}{% block body %}{{ name }}{% endblock %}\n",
    }

    assert escaped(tmp_path, templates) == ["base.html", "page.html"]