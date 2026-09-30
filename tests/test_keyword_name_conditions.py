"""An advisory condition of kind ``keyword_name`` names the keyword names of a call.

Django's ORM takes column aliases and lookups as keyword names, ``annotate(**{alias:
expr})``, and several advisories are SQL injections through a name the attacker chooses.
The engine decides the condition from the keys of what the call expands with ``**``,
apart from the mapping's values: keys carrying attacker input meet it and the call is
exploitable; constant keys, a dict literal with string keys, ``dict(a=...)`` or plain
keywords, contradict it and the call is ruled out, so a project passing only those stays
``not_affected``; keys the engine cannot establish, a parameter, a mapping built
elsewhere, ``dict(zip(...))``, leave it pending review as any unknown argument does.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from coretrace_python import engine
from coretrace_python.dependency import (
    Advisory,
    AdvisoryEntryPoint,
    AdvisoryFileError,
    Condition,
    dump_advisories,
    load_advisories,
    render_vex,
)
from coretrace_python.engine import ProjectAnalysis
from coretrace_python.findings import Finding, Severity
from coretrace_python.semantic.symbols import SymbolId

PLUGINS = engine.BUNDLED_PLUGINS
NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)

# ``Item.objects.annotate`` derives its symbol from the project's model class.
ANNOTATE = "python.app.models.Item.objects.annotate"
TEXT = "the alias is a keyword name the attacker chooses"
CONDITION = Condition("keyword_name", TEXT)
ADVISORY = Advisory(
    "CVE-2025-57833",
    "django",
    "<4.2.24 || >=5.0,<5.1.12 || >=5.2,<5.2.6",
    "FilteredRelation alias through annotate()/alias() allows SQL injection",
    Severity.HIGH,
    entry_points=(
        AdvisoryEntryPoint(SymbolId(ANNOTATE), "FilteredRelation alias through annotate()/alias()", (CONDITION,)),
    ),
    modules=("django",),
)

LOCK = """version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "django" }]

[[package]]
name = "django"
version = "5.2.5"
source = { registry = "https://pypi.org/simple" }
"""
MODELS = "from django.db import models\n\n\nclass Item(models.Model):\n    pass\n"
VIEWS = "from django.db.models import F\nfrom django.http import HttpRequest\n\nfrom .models import Item\n\n\n"
ISSUE = VIEWS + (
    "def listing(request: HttpRequest):\n"
    '    return Item.objects.annotate(**{request.GET["alias"]: F("id")})  # the alias is the attacker\'s\n'
    "\n\n"
    "def fixed(request: HttpRequest):\n"
    '    return Item.objects.annotate(**{"total": F("id")})  # constant key\n'
)
FIXED = VIEWS + 'def fixed(request: HttpRequest):\n    return Item.objects.annotate(**{"total": F("id")})\n'
RULED_OUT = f"app.views:8 {ANNOTATE}(keywords=total)"


def analyse(root: Path, views: str) -> ProjectAnalysis:
    files = {"uv.lock": LOCK, "app/__init__.py": "", "app/models.py": MODELS, "app/views.py": views}
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories((ADVISORY,)), encoding="utf-8")
    return engine.analyze_project(root, [PLUGINS])


def of_rule(analysis: ProjectAnalysis, rule_id: str) -> list[Finding]:
    return sorted((f for f in analysis.findings if f.rule_id == rule_id), key=lambda f: f.span.start_line)


def statement(analysis: ProjectAnalysis, root: Path) -> dict[str, Any]:
    evidence = (*analysis.findings, *analysis.suppressed, *analysis.accepted)
    document = render_vex(
        analysis.dependencies, analysis.advisories, evidence, analysis.coverage, root, "coretrace", "0.6.0", NOW
    )
    return next(s for s in json.loads(document)["statements"] if s["vulnerability"]["name"] == ADVISORY.id)


def calling(call: str, before: str = "") -> str:
    return VIEWS + f"def listing(request: HttpRequest):\n{before}    return Item.objects.annotate({call})\n"


# --------------------------------------------------------------------------- the reproduction


def test_keys_the_attacker_chooses_meet_the_condition_and_make_the_project_affected(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, ISSUE)

    (found,) = of_rule(analysis, "exploitable-vulnerability")
    assert found.span.start_line == 8
    assert found.metadata["symbol"] == ANNOTATE
    assert found.metadata["conditions_met"] == TEXT
    assert "conditions_pending_review" not in found.metadata
    assert statement(analysis, tmp_path)["status"] == "affected"


def test_constant_keys_rule_the_call_out_and_leave_the_project_not_affected(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, FIXED)

    assert of_rule(analysis, "reachable-vulnerability") == []
    assert of_rule(analysis, "exploitable-vulnerability") == []
    (declared,) = of_rule(analysis, "vulnerable-dependency")
    assert declared.metadata["level"] == "imported"
    assert declared.metadata["ruled_out"] == RULED_OUT
    found = statement(analysis, tmp_path)
    assert found["status"] == "not_affected"
    assert found["impact_statement"].endswith(f" Calls ruled out by their arguments: {RULED_OUT}.")


@pytest.mark.parametrize(
    "views",
    [
        VIEWS + "def listing(request: HttpRequest, **extra):\n    return Item.objects.annotate(**extra)\n",
        VIEWS + (
            "def options():\n    return {}\n\n\n"
            "def listing(request: HttpRequest):\n    opts = options()\n    return Item.objects.annotate(**opts)\n"
        ),
    ],
    ids=["parameter", "built-elsewhere"],
)
def test_a_mapping_whose_keys_are_not_established_leaves_the_condition_pending(tmp_path: Path, views: str) -> None:
    analysis = analyse(tmp_path, views)

    (reached,) = of_rule(analysis, "reachable-vulnerability")
    assert reached.metadata["symbol"] == ANNOTATE
    assert reached.metadata["conditions_pending_review"] == TEXT
    assert "conditions_met" not in reached.metadata
    assert of_rule(analysis, "exploitable-vulnerability") == []
    assert statement(analysis, tmp_path)["status"] == "affected"


# --------------------------------------------------------------------------- constant keys


@pytest.mark.parametrize(
    "call",
    [
        '**{"total": F(request.GET["x"])}',
        'total=F("id")',
        'total=F(request.GET["x"])',
    ],
    ids=["literal-with-tainted-value", "keyword", "keyword-with-tainted-value"],
)
def test_constant_keys_are_ruled_out_whatever_the_values_carry(tmp_path: Path, call: str) -> None:
    analysis = analyse(tmp_path, calling(call))

    assert of_rule(analysis, "reachable-vulnerability") == []
    assert of_rule(analysis, "exploitable-vulnerability") == []
    (declared,) = of_rule(analysis, "vulnerable-dependency")
    assert declared.metadata["ruled_out"] == RULED_OUT
    assert statement(analysis, tmp_path)["status"] == "not_affected"


# --------------------------------------------------------------------------- key taint


ALIAS = '    alias = request.GET["alias"]\n'


@pytest.mark.parametrize(
    "call, before",
    [
        ('**{alias: F("id")}', ALIAS),
        ('**dict([(alias, F("id"))])', ALIAS),
        ('**{k: F("id") for k in request.GET}', ""),
        ("**m", ALIAS + '    m = {}\n    m[alias] = F("id")\n'),
        ("**{**m}", ALIAS + '    m = {alias: F("id")}\n'),
        ("**dict(m)", ALIAS + '    m = {alias: F("id")}\n'),
        ('**dict(a=F("id"), **m)', ALIAS + '    m = {alias: F("id")}\n'),
    ],
    ids=["literal", "pairs", "comprehension", "subscript-assignment", "unpacked", "dict-copy", "dict-with-keywords"],
)
def test_every_construction_carrying_attacker_keys_meets_the_condition(tmp_path: Path, call: str, before: str) -> None:
    analysis = analyse(tmp_path, calling(call, before))

    (found,) = of_rule(analysis, "exploitable-vulnerability")
    assert found.metadata["symbol"] == ANNOTATE
    assert found.metadata["conditions_met"] == TEXT
    assert "conditions_pending_review" not in found.metadata
    # A call the taint engine finds exploitable is not one the call site rules out.
    (declared,) = of_rule(analysis, "vulnerable-dependency")
    assert "ruled_out" not in declared.metadata
    assert statement(analysis, tmp_path)["status"] == "affected"


def test_keys_zipped_from_input_are_pending_not_met(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, calling('**dict(zip(request.GET, [F("id")]))'))

    (found,) = of_rule(analysis, "exploitable-vulnerability")
    assert found.metadata["conditions_pending_review"] == TEXT
    assert "conditions_met" not in found.metadata
    assert statement(analysis, tmp_path)["status"] == "affected"


# --------------------------------------------------------------------------- advisory files


def test_the_condition_round_trips_through_advisory_files(tmp_path: Path) -> None:
    path = tmp_path / "advisories.json"
    path.write_text(dump_advisories((ADVISORY,)), encoding="utf-8")

    assert load_advisories(path) == (ADVISORY,)
    (entry,) = json.loads(path.read_text())["advisories"][0]["entry_points"]
    assert entry["conditions"] == [{"kind": "keyword_name", "text": TEXT}]


@pytest.mark.parametrize(
    "extra",
    [{"argument": "alias"}, {"position": 0}, {"values": ["total"]}, {"default": True}],
    ids=["argument", "position", "values", "default"],
)
def test_a_keyword_name_condition_carrying_more_than_its_text_is_rejected(tmp_path: Path, extra: dict[str, Any]) -> None:
    document = json.loads(dump_advisories((ADVISORY,)))
    document["advisories"][0]["entry_points"][0]["conditions"] = [{"kind": "keyword_name", "text": TEXT, **extra}]
    path = tmp_path / "advisories.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(AdvisoryFileError):
        load_advisories(path)
