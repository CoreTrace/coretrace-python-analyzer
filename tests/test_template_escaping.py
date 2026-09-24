"""Django templates escape what they render, where the engine can establish it.

``render_to_string(name, context)`` returns HTML in which autoescaping has escaped every
variable, so attacker data reaching ``HttpResponse`` through it is no cross-site
scripting, provided the template really escapes. The engine establishes that only when
all of these hold:

- it finds every template of that name under a ``templates`` directory, and everything
  those templates extend or include;
- none of them marks output safe (``|safe``, ``|safeseq``, ``{% autoescape off %}``);
- none uses a tag beyond Django's own, or loads a tag library beyond its built-ins;
- none places a variable where HTML escaping does not protect it: a ``<script>`` or
  ``<style>`` block, an event handler, a ``style`` attribute, a URL attribute not fixed
  by a relative or ``http(s)`` prefix, an unquoted attribute, or an attribute name;
- no settings turn autoescaping off.

Otherwise the flow is reported as before. A template the engine cannot read, such as one
under a ``DIRS`` entry that is not a ``templates`` directory, is not assumed safe.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cache import ProjectCache
from coretrace_python.source import SourceManager
from coretrace_python.taint.templates import escaped_templates

VIEW = (
    "from django.http import HttpRequest, HttpResponse\n"
    "from django.template.loader import render_to_string\n\n"
    "def page(request: HttpRequest):\n"
    "    return HttpResponse(render_to_string({name}, {{'name': request.GET['name']}}))\n"
)


def write(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def xss(root: Path, template: str, name: str = "'app/page.html'", files: dict[str, str] | None = None) -> list[int]:
    write(root, {"app/views.py": VIEW.format(name=name), "app/templates/app/page.html": template, **(files or {})})
    findings = engine.analyze_project(root, [engine.BUNDLED_PLUGINS]).findings
    return [f.span.start_line for f in findings if f.rule_id == "xss"]


# --------------------------------------------------------------------------- inspection


def test_a_template_escaping_every_variable_in_text_and_quoted_attributes_is_escaped(tmp_path: Path) -> None:
    template = (
        "{% load static i18n %}<p title=\"{{ name }}\">{% trans 'Hello' %} {{ name|upper }}</p>\n"
        "<a href=\"/users/{{ name }}/\">{{ name }}</a> <a href='https://example.com/?q={{ name }}'>x</a>\n"
        "<img src=\"{% static 'logo.png' %}\" alt=\"{{ name }}\"><!-- {{ name }} -->\n"
        "{% for item in items %}{{ item }}{% empty %}-{% endfor %}{% comment %}{{ x|safe }}{% endcomment %}"
    )

    assert escaped_templates(write(tmp_path, {"app/templates/app/page.html": template})) == {"app/page.html"}


@pytest.mark.parametrize(
    "template",
    [
        "{{ name|safe }}",
        "{{ items|safeseq|join:', ' }}",
        "{% autoescape off %}{{ name }}{% endautoescape %}",
        "<script>var n = '{{ name }}';</script>",
        "<style>p { color: {{ color }} }</style>",
        "<a href=\"{{ url }}\">x</a>",
        "<a href=\"javascript:go('{{ name }}')\">x</a>",
        "<div onclick=\"go('{{ name }}')\">x</div>",
        "<div style=\"width: {{ width }}\">x</div>",
        "<div title={{ name }}>x</div>",
        "<div {{ attributes }}>x</div>",
        "{% load custom_tags %}<p>{{ name }}</p>",
        "{% custom_tag name %}",
        "{% include template_name %}",
        "{% extends base_name %}",
        "{% include 'app/missing.html' %}",
    ],
)
def test_a_template_that_may_output_unescaped_data_is_not_escaped(tmp_path: Path, template: str) -> None:
    assert escaped_templates(write(tmp_path, {"app/templates/app/page.html": template})) == frozenset()


def test_a_template_escapes_no_better_than_what_it_extends_and_includes(tmp_path: Path) -> None:
    files = {
        "app/templates/base.html": (
            "{% load static %}<html><body>{% block content %}{% endblock %}"
            "<script src=\"{% static 'app.js' %}\"></script></body></html>"
        ),
        "app/templates/app/page.html": (
            "{% extends 'base.html' %}{% block content %}<p>{{ name }}</p>{% include 'app/part.html' %}{% endblock %}"
        ),
        "app/templates/app/part.html": "<span>{{ name }}</span>",
        "app/templates/raw.html": "{% block content %}{% endblock %}<p>{{ name|safe }}</p>",
        "app/templates/app/on_raw.html": "{% extends 'raw.html' %}{% block content %}{{ name }}{% endblock %}",
    }

    assert escaped_templates(write(tmp_path, files)) == {"base.html", "app/page.html", "app/part.html"}


def test_every_template_of_a_name_must_escape(tmp_path: Path) -> None:
    files = {"one/templates/page.html": "<p>{{ name }}</p>", "two/templates/page.html": "<p>{{ name|safe }}</p>"}

    assert escaped_templates(write(tmp_path, files)) == frozenset()


def test_settings_disabling_autoescape_leave_no_template_escaped(tmp_path: Path) -> None:
    files = {
        "app/templates/app/page.html": "<p>{{ name }}</p>",
        "site/settings.py": "TEMPLATES = [{'BACKEND': 'x', 'OPTIONS': {'autoescape': False}}]\n",
    }

    assert escaped_templates(write(tmp_path, files)) == frozenset()


# --------------------------------------------------------------------------- analysis


def test_rendering_an_escaped_template_is_not_cross_site_scripting(tmp_path: Path) -> None:
    assert xss(tmp_path, "<p>Hello {{ name }}</p>") == []


def test_rendering_a_template_that_marks_the_value_safe_stays_cross_site_scripting(tmp_path: Path) -> None:
    assert xss(tmp_path, "<p>Hello {{ name|safe }}</p>") == [5]


def test_a_template_named_by_an_expression_stays_cross_site_scripting(tmp_path: Path) -> None:
    assert xss(tmp_path, "<p>Hello {{ name }}</p>", name="'app/' + 'page.html'") == [5]


def test_a_template_outside_a_templates_directory_is_not_assumed_escaped(tmp_path: Path) -> None:
    # Django finds it through a DIRS entry the engine does not read: a known limitation.
    view = VIEW.format(name="'page.html'")
    write(tmp_path, {"app/views.py": view, "frontend/page.html": "<p>Hello {{ name }}</p>"})

    findings = engine.analyze_project(tmp_path, [engine.BUNDLED_PLUGINS]).findings

    assert [f.span.start_line for f in findings if f.rule_id == "xss"] == [5]


def test_a_single_file_check_assumes_no_template_escaped() -> None:
    findings = engine.check(
        SourceManager().add_source("views.py", VIEW.format(name="'app/page.html'")), [engine.BUNDLED_PLUGINS]
    )

    assert [f.rule_id for f in findings] == ["xss"]


def test_a_template_gaining_safe_invalidates_the_cached_results(tmp_path: Path) -> None:
    cache = ProjectCache(tmp_path / "cache")
    root = write(tmp_path / "src", {"app/views.py": VIEW.format(name="'app/page.html'")})
    page = write(root, {"app/templates/app/page.html": "<p>{{ name }}</p>"}) / "app/templates/app/page.html"

    first = engine.analyze_project(root, [engine.BUNDLED_PLUGINS], cache=cache)
    page.write_text("<p>{{ name|safe }}</p>", encoding="utf-8")
    second = engine.analyze_project(root, [engine.BUNDLED_PLUGINS], cache=cache)

    assert [f.rule_id for f in first.findings if f.rule_id == "xss"] == []
    assert second.reused == ()
    assert [f.span.start_line for f in second.findings if f.rule_id == "xss"] == [5]


def test_modules_analysed_in_other_processes_see_the_escaped_templates(tmp_path: Path) -> None:
    root = write(tmp_path, {"app/views.py": VIEW.format(name="'app/page.html'"), "app/other.py": "X = 1\n"})
    write(root, {"app/templates/app/page.html": "<p>{{ name }}</p>"})

    findings = engine.analyze_project(root, [engine.BUNDLED_PLUGINS], jobs=2).findings

    assert [f.rule_id for f in findings if f.rule_id == "xss"] == []
