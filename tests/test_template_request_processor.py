"""The request a context processor adds to what a template renders.

With ``django.template.context_processors.request`` enabled, a template rendered with the
request reads it as ``request``: ``{{ request.GET.q|striptags }}`` passes attacker input
to ``striptags`` though no context entry carries it. The engine counts it only where it
is certain:

- the project's settings assign ``TEMPLATES`` a literal list, every
  ``DjangoTemplates`` engine of it lists the processor in a literal
  ``context_processors``, and no other code of the project names ``TEMPLATES``; a mere
  mention of the processor elsewhere proves nothing;
- the render call passes the request: ``render`` and ``TemplateResponse`` always do,
  ``render_to_string`` when given ``request``, ``SimpleTemplateResponse`` never;
- the render's context is certain, so it cannot hide a ``request`` entry: absent, or a
  dict literal only that call uses; an entry of that name, a name a tag binds, or
  ``{% include ... only %}`` shadows the processor's request;
- the template reads text the user controls: an attribute the request object lists
  among its text attributes, such as ``GET``, ``POST``, ``COOKIES`` or ``headers``, not
  ``user`` or ``session``.

Otherwise the filter stays reachable. Through a project function, only the context
entries are followed.
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
    "CVE-2099-5501",
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
PROCESSOR = "django.template.context_processors.request"
DJANGO = "django.template.backends.django.DjangoTemplates"
JINJA = "django.template.backends.jinja2.Jinja2"


def engine_settings(processors: str = f"'{PROCESSOR}', 'django.contrib.auth.context_processors.auth'", backend: str = DJANGO) -> str:
    return f"{{'BACKEND': '{backend}', 'APP_DIRS': True, 'OPTIONS': {{'context_processors': [{processors}]}}}}"


SETTINGS = f"TEMPLATES = [{engine_settings()}]\n"
HEADER = (
    "from django.http import HttpRequest, HttpResponse\n"
    "from django.shortcuts import render\n"
    "from django.template.loader import render_to_string\n"
    "from django.template.response import SimpleTemplateResponse, TemplateResponse\n\n"
    "def search(request: HttpRequest):\n"
)
LINE = 7
PAGE = "app/templates/app/search.html"
RENDER = "    return render(request, 'app/search.html')\n"
READS = "{{ request.GET.q|striptags }}\n"


def exploitable(root: Path, body: str = RENDER, template: str = READS, **files: str) -> list[int]:
    files = {
        "uv.lock": LOCK,
        "app/__init__.py": "",
        "app/settings.py": SETTINGS,
        "app/views.py": HEADER + body,
        PAGE: template,
        **files,
    }
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories((ADVISORY,)), encoding="utf-8")
    findings = engine.analyze_project(root, [engine.BUNDLED_PLUGINS]).findings
    return [f.span.start_line for f in findings if f.rule_id == "exploitable-vulnerability"]


# --------------------------------------------------------------------------- reached


@pytest.mark.parametrize(
    "body",
    [
        RENDER,
        "    return render(request, 'app/search.html', {'title': 'Search'})\n",
        "    return HttpResponse(render_to_string('app/search.html', request=request))\n",
        "    return HttpResponse(render_to_string('app/search.html', {'title': 'Search'}, request))\n",
        "    return TemplateResponse(request, 'app/search.html')\n",
    ],
    ids=["render", "render-with-context", "render-to-string", "render-to-string-positional", "template-response"],
)
def test_a_render_passing_the_request_gives_it_to_the_template(tmp_path: Path, body: str) -> None:
    assert exploitable(tmp_path, body) == [LINE]


@pytest.mark.parametrize(
    "template",
    [
        "{{ request.POST.bio|striptags }}",
        "{{ request.headers.referer|striptags }}",
        "{% with q=request.GET.q %}{{ q|striptags }}{% endwith %}",
        "{% with query=request.GET %}{{ query.q|striptags }}{% endwith %}",
        "{% for value in request.GET.values %}{{ value|striptags }}{% endfor %}",
        "{% include 'app/card.html' %}",
    ],
    ids=["post", "headers", "with", "with-attribute", "for", "include"],
)
def test_text_the_user_controls_reaches_the_filter(tmp_path: Path, template: str) -> None:
    card = {"app/templates/app/card.html": READS}

    assert exploitable(tmp_path, template=template, **card) == [LINE]


def test_only_django_engines_need_the_processor(tmp_path: Path) -> None:
    settings = f"TEMPLATES = [{engine_settings()}, {engine_settings('', JINJA)}]\n"

    assert exploitable(tmp_path, **{"app/settings.py": settings}) == [LINE]


# --------------------------------------------------------------------------- uncertain


@pytest.mark.parametrize(
    "settings",
    [
        f"TEMPLATES = [{engine_settings(repr('django.contrib.auth.context_processors.auth'))}]\n",
        "DEBUG = True\n",
        f"TEMPLATES = [{engine_settings()}, {engine_settings('')}]\n",
        f"PROCESSORS = [{PROCESSOR!r}]\nTEMPLATES = [{engine_settings('*PROCESSORS')}]\n",
        f"PROCESSORS = [{PROCESSOR!r}]\nTEMPLATES = [{{'BACKEND': {DJANGO!r}, 'OPTIONS': {{'context_processors': PROCESSORS}}}}]\n",
        f"TEMPLATES = [{engine_settings()}]\nTEMPLATES[0]['OPTIONS']['context_processors'].pop(0)\n",
        f"TEMPLATES = [{engine_settings()}]\nif DEBUG:\n    TEMPLATES = []\n",
        f"# {PROCESSOR}\nNOTE = {PROCESSOR!r}\n",
    ],
    ids=[
        "not-listed", "no-templates", "one-engine-without", "unpacked", "not-a-literal", "mutated",
        "reassigned", "mentioned-only",
    ],
)
def test_settings_that_do_not_prove_the_processor_leave_the_filter_reachable(tmp_path: Path, settings: str) -> None:
    assert exploitable(tmp_path, **{"app/settings.py": settings}) == []


def test_settings_named_in_other_code_leave_the_filter_reachable(tmp_path: Path) -> None:
    local = "from app.settings import *\n\nTEMPLATES[0]['OPTIONS']['debug'] = True\n"

    assert exploitable(tmp_path, **{"app/local.py": local}) == []


@pytest.mark.parametrize(
    "body",
    [
        "    return HttpResponse(render_to_string('app/search.html'))\n",
        "    return HttpResponse(render_to_string('app/search.html', request=None))\n",
        "    return SimpleTemplateResponse('app/search.html')\n",
        "    return render(request, 'app/search.html', {'request': 'none'})\n",
        "    context = {'title': 'Search'}\n    context.update(extra())\n    return render(request, 'app/search.html', context)\n",
        "    return render(request, 'app/search.html', build())\n",
    ],
    ids=["no-request", "request-none", "simple-template-response", "shadowed-entry", "mutated-context", "unknown-context"],
)
def test_a_render_that_does_not_certainly_pass_the_request_leaves_the_filter_reachable(
    tmp_path: Path, body: str
) -> None:
    assert exploitable(tmp_path, body) == []


@pytest.mark.parametrize(
    "template, files",
    [
        ("{{ request.user.username|striptags }}", {}),
        ("{{ request.session.q|striptags }}", {}),
        ("{{ request|striptags }}", {}),
        ("{% with request=other %}{{ request.GET.q|striptags }}{% endwith %}", {}),
        ("{% include 'app/card.html' only %}", {"app/templates/app/card.html": READS}),
    ],
    ids=["user", "session", "whole-request", "shadowed-by-with", "include-only"],
)
def test_what_is_not_user_text_or_is_shadowed_leaves_the_filter_reachable(
    tmp_path: Path, template: str, files: dict[str, str]
) -> None:
    assert exploitable(tmp_path, template=template, **files) == []


def test_a_project_function_rendering_with_the_request_follows_context_entries_only(tmp_path: Path) -> None:
    helpers = "from django.shortcuts import render\n\ndef show(request):\n    return render(request, 'app/search.html')\n"
    views = (
        "from django.http import HttpRequest\n\n"
        "from app.helpers import show\n\n"
        "def search(request: HttpRequest):\n"
        "    return show(request)\n"
    )

    assert exploitable(tmp_path, **{"app/helpers.py": helpers, "app/views.py": views}) == []
