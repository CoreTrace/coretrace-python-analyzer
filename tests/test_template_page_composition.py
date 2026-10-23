"""Acceptance tests for issue #273: a page is read as Django puts it together.

A ``{% block %}`` takes the definition the rendered page gives it, which may stand in the
parent's ``<script>``; an ``{% include %}`` puts the included template's markup where it
stands, which may be inside an attribute value and end it. Each template file read on
its own sees neither, so each page is also put together, its blocks and includes in
place, and read once. Each inspection and analysis runs in a subprocess with a timeout,
so that one that does not end fails instead of hanging the suite.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

TIMEOUT = 60

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
    """A project rendering ``page.html`` with the request's ``name``; a template given by
    its name lies under ``app/templates``, one given by a path under that path."""

    root = tmp_path / "project"
    (root / "app" / "templates").mkdir(parents=True, exist_ok=True)
    (root / "app" / "views.py").write_text(VIEW, encoding="utf-8")
    for name, content in templates.items():
        path = root / name if "/templates/" in name else root / "app" / "templates" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
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


BASE_WITH_SCRIPT_BLOCK = "<html><head><script>{% block js %}{% endblock %}</script></head><body>{% block body %}{% endblock %}</body></html>\n"


# The reproductions of #273, rendered with Django 5.1.15: the variable runs as script in
# F, as an event handler in H, and in H's variant when other/templates comes first.
@pytest.mark.parametrize(
    "templates",
    [
        {
            "base.html": "<html><head><script>{% block js %}{% endblock %}</script></head><body></body></html>\n",
            "page.html": "{% extends 'base.html' %}{% block js %}var name = {{ name }};{% endblock %}\n",
        },
        {"page.html": '<a title="{% include "q.html" %}{{ name }}">x</a>\n', "q.html": '" onclick="\n'},
        {
            "page.html": '<a title="{% include "q.html" %}{{ name }}">x</a>\n',
            "q.html": "quote: \n",
            "other/templates/q.html": '" onclick="\n',
        },
    ],
    ids=["F-block-inside-parent-script", "H-include-inside-attribute-value", "H-include-of-a-name-two-files-have"],
)
def test_markup_a_block_or_an_include_puts_inside_a_construct_is_read_there(
    tmp_path: Path, templates: dict[str, str]
) -> None:
    assert xss(tmp_path, templates) == [("app/views.py", 5)]


def test_only_the_page_printing_inside_the_parent_script_is_refused(tmp_path: Path) -> None:
    templates = {
        "base.html": BASE_WITH_SCRIPT_BLOCK,
        "page.html": "{% extends 'base.html' %}{% block body %}<p>{{ name }}</p>{% endblock %}\n",
        "inert.html": "{% extends 'base.html' %}{% block js %}var count = 1;{% endblock %}\n",
        "script.html": "{% extends 'base.html' %}{% block js %}var name = {{ name }};{% endblock %}\n",
    }

    assert escaped(tmp_path, templates) == ["base.html", "inert.html", "page.html"]


@pytest.mark.parametrize(
    "templates",
    [
        {
            "base.html": '<body class="{% block bodyclass %}{% endblock %}">{% block content %}{% endblock %}</body>\n',
            "page.html": "{% extends 'base.html' %}{% block bodyclass %}{{ name }} change-form{% endblock %}\n",
        },
        {
            "base.html": "<script>{% block js %}var count = 1;{% endblock %}</script>\n",
            "page.html": "{% extends 'base.html' %}{% block js %}{{ block.super }} var total = 2;{% endblock %}\n",
        },
        {"page.html": '<a title="{% include "q.html" %}{{ name }}">x</a>\n', "q.html": "prefix \n"},
        {
            "base.html": "<p>{% block body %}{% endblock %}</p>\n",
            "middle.html": "{% extends 'base.html' %}{% block body %}<b>{% block inner %}{% endblock %}</b>{% endblock %}\n",
            "page.html": "{% extends 'middle.html' %}{% block inner %}{{ name }}{% endblock %}\n",
        },
    ],
    ids=["variable-in-a-quoted-class", "block-super-in-a-script", "include-without-a-quote-in-a-title", "nested-blocks"],
)
def test_a_page_whose_parts_stay_escaped_once_put_together_is_established(
    tmp_path: Path, templates: dict[str, str]
) -> None:
    assert escaped(tmp_path, templates) == sorted(templates)


@pytest.mark.parametrize(
    "templates",
    [
        {
            "page.html": "{% include 'self.html' %}",
            "self.html": '<a title="{% if more %}{% include \'self.html\' %}{% endif %}{{ name }}">x</a>',
        },
        {
            "page.html": "{% include 'a.html' %}",
            "a.html": "<script>{% if more %}{% include 'b.html' %}{% endif %}</script>",
            "b.html": "{{ name }}{% include 'a.html' %}",
        },
    ],
    ids=["itself-inside-an-attribute", "through-another-inside-a-script"],
)
def test_a_template_including_itself_inside_a_construct_is_not_established(
    tmp_path: Path, templates: dict[str, str]
) -> None:
    # Rendered twice, self.html puts an <a title="…"> inside the title it is in, whose quote
    # ends that title before the variable; b.html's variable lands inside a.html's script.
    assert escaped(tmp_path, templates) == []


def test_a_page_beyond_eight_mebibytes_is_not_established(tmp_path: Path) -> None:
    # level{n}.html holds 2 ** n characters once put together: level23.html is 8 MiB,
    # level24.html beyond, and the page including it is put together no further.
    templates = {"level0.html": "x"}
    for level in range(1, 25):
        templates[f"level{level}.html"] = f"{{% include 'level{level - 1}.html' %}}" * 2
    templates["page.html"] = "{% include 'level24.html' %}"

    assert escaped(tmp_path, templates) == sorted(f"level{level}.html" for level in range(24))
