"""Acceptance tests for issue #278: every continuation of a comment holding template tags.

Rendered, such a comment may end at any of its tags, an include closing it or a condition
leaving out its opener, or run to its close when its tags render nothing. The reading
resumed after its first tag (#272) is kept. At every other point where a reading may
resume, right after each later tag of the comment and right after its close, that reading
must be in HTML data, where every other continuation reads what it reads; elsewhere, the
template is refused. Each inspection and analysis runs in a subprocess with a timeout, so
that one that does not end fails instead of hanging the suite.
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


def test_a_comment_holding_tags_left_open_does_not_end_in_html_data(tmp_path: Path) -> None:
    # Its tags may render nothing: the comment then hides what follows the include.
    templates = {
        "part.html": "x\n",
        "other/templates/part.html": "y <!-- {% if a %}{% endif %}",
        "page.html": "<div>{% include 'part.html' %}</div>\n",
    }

    assert escaped(tmp_path, templates) == ["part.html"]
