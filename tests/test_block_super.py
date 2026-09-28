"""``{{ block.super }}`` keeps the parent block's filters in the render context flow.

A template extending another renders only its blocks, which replace the blocks of that
name in the parent. A block that renders ``{{ block.super }}`` extends the parent's
block instead of replacing it: Django executes the parent's content, so the filters it
applies stay fed by the render context, with the parent template as the place of the
call. A block without ``block.super`` still replaces the parent's whole block, other
overridden blocks stay excluded, and a chain of templates keeps exactly the parents each
level renders, without duplicate findings.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.dependency import Advisory, AdvisoryEntryPoint, dump_advisories
from coretrace_python.findings import Severity
from coretrace_python.semantic.symbols import SymbolId

STRIPTAGS = "python.django.template.defaultfilters.striptags"
ADVISORY = Advisory(
    "CVE-2099-5701",
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
    "def profile(request: HttpRequest):\n"
    "    return render(request, 'app/profile.html', {'bio': request.POST['bio']})\n"
)
LINE = 5
BASE = "app/templates/app/base.html"
MIDDLE = "app/templates/app/middle.html"
PAGE = "app/templates/app/profile.html"


def exploitable(root: Path, templates: dict[str, str]) -> list[tuple[int, str, str]]:
    """The exploitable striptags calls the render makes: the render line, the template
    holding the filter, and the line of the filter there."""

    files = {"uv.lock": LOCK, "app/__init__.py": "", "app/views.py": VIEW, **templates}
    for relative, text in files.items():
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_text(text, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories((ADVISORY,)), encoding="utf-8")
    findings = engine.analyze_project(root, [engine.BUNDLED_PLUGINS]).findings
    return sorted(
        (f.span.start_line, f.metadata["through"], f.metadata["sink_line"])
        for f in findings
        if f.rule_id == "exploitable-vulnerability" and f.metadata["advisory"] == ADVISORY.id
    )


def test_a_block_rendering_block_super_keeps_the_parent_flow(tmp_path: Path) -> None:
    templates = {
        BASE: "{% block body %}{{ bio|striptags }}{% endblock %}\n",
        PAGE: "{% extends 'app/base.html' %}\n{% block body %}{{ block.super }}{% endblock %}\n",
    }

    assert exploitable(tmp_path, templates) == [(LINE, "app/base.html", "1")]


def test_a_block_may_add_its_own_filters_beside_block_super(tmp_path: Path) -> None:
    templates = {
        BASE: "{% block body %}{{ bio|striptags }}{% endblock %}\n",
        PAGE: "{% extends 'app/base.html' %}\n{% block body %}<p>{{ bio|striptags }}</p>\n{{ block.super }}{% endblock %}\n",
    }

    assert exploitable(tmp_path, templates) == [(LINE, "app/base.html", "1"), (LINE, "app/profile.html", "2")]


def test_a_replacement_without_block_super_still_excludes_the_parent(tmp_path: Path) -> None:
    templates = {
        BASE: "{% block body %}{{ bio|striptags }}{% endblock %}\n",
        PAGE: "{% extends 'app/base.html' %}\n{% block body %}{{ bio }}{% endblock %}\n",
    }

    assert exploitable(tmp_path, templates) == []


def test_another_block_does_not_come_back_through_one_block_super(tmp_path: Path) -> None:
    templates = {
        BASE: "{% block body %}{{ bio|striptags }}{% endblock %}\n{% block aside %}{{ bio|striptags }}{% endblock %}\n",
        PAGE: (
            "{% extends 'app/base.html' %}\n"
            "{% block body %}{{ block.super }}{% endblock %}\n"
            "{% block aside %}{{ bio }}{% endblock %}\n"
        ),
    }

    assert exploitable(tmp_path, templates) == [(LINE, "app/base.html", "1")]


def test_block_super_at_each_level_keeps_the_whole_chain_once(tmp_path: Path) -> None:
    templates = {
        BASE: "{% block body %}{{ bio|striptags }}{% endblock %}\n",
        MIDDLE: "{% extends 'app/base.html' %}\n{% block body %}{{ block.super }}<i>{{ bio|striptags }}</i>{% endblock %}\n",
        PAGE: "{% extends 'app/middle.html' %}\n{% block body %}{{ block.super }}{% endblock %}\n",
    }

    assert exploitable(tmp_path, templates) == [(LINE, "app/base.html", "1"), (LINE, "app/middle.html", "2")]


def test_a_replacement_in_the_middle_cuts_the_chain_above_it(tmp_path: Path) -> None:
    templates = {
        BASE: "{% block body %}{{ bio|striptags }}{% endblock %}\n",
        MIDDLE: "{% extends 'app/base.html' %}\n{% block body %}<i>{{ bio|striptags }}</i>{% endblock %}\n",
        PAGE: "{% extends 'app/middle.html' %}\n{% block body %}{{ block.super }}{% endblock %}\n",
    }

    assert exploitable(tmp_path, templates) == [(LINE, "app/middle.html", "2")]


def test_a_replacement_at_the_end_cuts_the_whole_chain(tmp_path: Path) -> None:
    templates = {
        BASE: "{% block body %}{{ bio|striptags }}{% endblock %}\n",
        MIDDLE: "{% extends 'app/base.html' %}\n{% block body %}{{ block.super }}<i>{{ bio|striptags }}</i>{% endblock %}\n",
        PAGE: "{% extends 'app/middle.html' %}\n{% block body %}{{ bio }}{% endblock %}\n",
    }

    assert exploitable(tmp_path, templates) == []


@pytest.mark.parametrize(
    "child_block",
    ["{{ block.super|lower }}", "{% if bio %}{{ block.super }}{% endif %}", "{{ block.super }}{{ block.super }}"],
    ids=["filtered", "conditional", "twice"],
)
def test_block_super_counts_however_it_is_rendered(tmp_path: Path, child_block: str) -> None:
    templates = {
        BASE: "{% block body %}{{ bio|striptags }}{% endblock %}\n",
        PAGE: "{% extends 'app/base.html' %}\n{% block body %}" + child_block + "{% endblock %}\n",
    }

    assert exploitable(tmp_path, templates) == [(LINE, "app/base.html", "1")]
