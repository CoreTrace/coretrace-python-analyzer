"""Only module-level settings configure Django.

The request context processor is taken as active only from the settings a project
assigns at module level: a ``TEMPLATES`` assigned inside a function, called or not,
binds a local name and configures nothing, and so does a class attribute. A function
that reads or rebinds the module's ``TEMPLATES`` (through ``global``, or by mutating
it) may change the effective settings, so it leaves the activation uncertain, as any
other mention does. Uncertain activation leaves the filter reachable, neither
exploitable through the processor nor declared absent.
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
    "CVE-2099-5601",
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
ENGINE = (
    "{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'APP_DIRS': True, "
    "'OPTIONS': {'context_processors': ['django.template.context_processors.request']}}"
)
VIEW = (
    "from django.http import HttpRequest\n"
    "from django.shortcuts import render\n\n"
    "def search(request: HttpRequest):\n"
    "    return render(request, 'app/search.html')\n"
)
PAGE = "app/templates/app/search.html"


def levels(root: Path, settings: str) -> list[str]:
    files = {
        "uv.lock": LOCK,
        "app/__init__.py": "",
        "app/settings.py": settings,
        "app/views.py": VIEW,
        PAGE: "{{ request.GET.q|striptags }}\n",
    }
    for relative, text in files.items():
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_text(text, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories((ADVISORY,)), encoding="utf-8")
    findings = engine.analyze_project(root, [engine.BUNDLED_PLUGINS]).findings
    reached = ("reachable-vulnerability", "exploitable-vulnerability")
    return sorted(f.metadata["level"] for f in findings if f.rule_id in reached and f.metadata["advisory"] == ADVISORY.id)


def test_module_level_settings_activate_the_processor(tmp_path: Path) -> None:
    assert levels(tmp_path, f"TEMPLATES = [{ENGINE}]\n") == ["exploitable", "reachable"]


@pytest.mark.parametrize(
    "settings",
    [
        f"def never_called():\n    TEMPLATES = [{ENGINE}]\n",
        f"def configure():\n    TEMPLATES = [{ENGINE}]\n    return TEMPLATES\n\nconfigure()\n",
        f"class Settings:\n    TEMPLATES = [{ENGINE}]\n",
        f"def build():\n    templates = [{ENGINE}]\n    return templates\n",
    ],
    ids=["uncalled-function", "called-function", "class-attribute", "other-local-name"],
)
def test_settings_bound_below_the_module_do_not_configure_django(tmp_path: Path, settings: str) -> None:
    assert levels(tmp_path, settings) == ["reachable"]


@pytest.mark.parametrize(
    "settings",
    [
        f"TEMPLATES = [{ENGINE}]\n\ndef tweak():\n    TEMPLATES[0]['OPTIONS']['context_processors'].pop(0)\n",
        f"TEMPLATES = [{ENGINE}]\n\ndef reset():\n    global TEMPLATES\n    TEMPLATES = []\n",
        f"TEMPLATES = [{ENGINE}]\n\ndef read():\n    return TEMPLATES\n",
    ],
    ids=["mutated-in-a-function", "rebound-through-global", "read-in-a-function"],
)
def test_a_function_touching_the_module_settings_leaves_activation_uncertain(tmp_path: Path, settings: str) -> None:
    assert levels(tmp_path, settings) == ["reachable"]


def test_a_local_name_beside_module_settings_changes_nothing(tmp_path: Path) -> None:
    settings = f"TEMPLATES = [{ENGINE}]\n\ndef helper():\n    TEMPLATES = []\n    return TEMPLATES\n"

    assert levels(tmp_path, settings) == ["exploitable", "reachable"]
