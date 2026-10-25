"""Acceptance tests for issue #284: a cycle of includes does not stop the collection of the
filters a template's render reaches.

A template reached again on the way contributes what it reaches, as Django renders it
when the project's conditions let the cycle turn: the filters of each template, with the
blocks the templates extending it override, are the least fixpoint of what it applies and
what its references reach through their bindings. Each expectation below is what Django
5.1.15 applies when it renders the same templates.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.dependency import Advisory, AdvisoryEntryPoint, dump_advisories
from coretrace_python.findings import Severity
from coretrace_python.semantic.symbols import SymbolId

FILTERS = "python.django.template.defaultfilters"
STRIPTAGS = f"{FILTERS}.striptags"
ADVISORY = Advisory(
    "CVE-2099-8401",
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
# The child extends the parent and overrides its body; the parent includes the child in
# that body, binding v to other. Django renders b.html as striptags of v, then, through
# a.html, b.html again with the body overridden: striptags of other, then upper of other.
CYCLE = {
    "app/templates/a.html": "{% extends 'b.html' %}\n{% block body %}{{ v|upper }}{% endblock %}\n",
    "app/templates/b.html": "{{ v|striptags }}\n{% block body %}{% include 'a.html' with v=other %}{% endblock %}\n",
}


def write(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def exploitable(root: Path, context: str) -> list[tuple[int, str, str]]:
    """The exploitable striptags calls a view rendering b.html with ``context`` makes: the
    render line, the template holding the filter, and the line of the filter there."""

    view = (
        "from django.http import HttpRequest\n"
        "from django.shortcuts import render\n\n"
        "def page(request: HttpRequest):\n"
        f"    return render(request, 'b.html', {context})\n"
    )
    write(root, {"uv.lock": LOCK, "app/__init__.py": "", "app/views.py": view, **CYCLE})
    (root / "advisories.json").write_text(dump_advisories((ADVISORY,)), encoding="utf-8")
    findings = engine.analyze_project(root, [engine.BUNDLED_PLUGINS]).findings
    return sorted(
        (f.span.start_line, f.metadata["through"], f.metadata["sink_line"])
        for f in findings
        if f.rule_id == "exploitable-vulnerability" and f.metadata["advisory"] == ADVISORY.id
    )


@pytest.mark.parametrize(
    "context",
    ["{'v': 'fixed', 'other': request.POST['bio']}", "{'v': request.POST['bio'], 'other': 'fixed'}"],
    ids=["through-the-cycle", "control"],
)
def test_input_the_parent_passes_its_child_reaches_the_parent_filter_django_applies(tmp_path: Path, context: str) -> None:
    assert exploitable(tmp_path, context) == [(5, "b.html", "1")]
