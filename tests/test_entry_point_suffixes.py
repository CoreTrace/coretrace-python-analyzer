"""A curated entry point matched by a suffix of the derived symbol.

A curated advisory names its entry points by canonical symbol,
``python.django.db.models.QuerySet.annotate``, but a project reaches the method through
a manager the engine cannot type: ``Item.objects.annotate(...)`` derives
``python.app.models.Item.objects.annotate``, the project's own symbol, and the entry
point never matches. An entry point may therefore declare ``suffixes``: a symbol of the
project's own modules ending with a dot plus the suffix reaches the entry point, as a
``SuffixSink`` matches a sink. A queryset chain is declared explicitly
(``objects.filter.annotate``); another package's symbol never matches; the finding names
the advisory's symbol as ``entry_point`` and the derived one as ``symbol``.
"""

from __future__ import annotations

import json
from dataclasses import replace
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
from coretrace_python.dependency.correlation import affected_entries, suffix_index
from coretrace_python.engine import ProjectAnalysis
from coretrace_python.findings import Finding, Severity
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import ModelTable, Sink, SuffixSink, TaintKind

PLUGINS = engine.BUNDLED_PLUGINS
NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)

QUERYSET = "python.django.db.models.QuerySet.annotate"
DERIVED = "python.app.models.Item.objects.annotate"
TEXT = "the alias is a keyword name the attacker chooses"
CONDITION = Condition("keyword_name", TEXT)


def advisory(*suffixes: str) -> Advisory:
    return Advisory(
        "CVE-2025-57833",
        "django",
        "<4.2.24 || >=5.0,<5.1.12 || >=5.2,<5.2.6",
        "FilteredRelation alias through annotate()/alias() allows SQL injection",
        Severity.HIGH,
        entry_points=(
            AdvisoryEntryPoint(
                SymbolId(QUERYSET),
                "FilteredRelation alias through annotate()/alias()",
                (CONDITION,),
                suffixes=suffixes,
            ),
        ),
        modules=("django",),
    )


ADVISORY = advisory("objects.annotate", "objects.filter.annotate")

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
    '    return Item.objects.annotate(**{request.GET["alias"]: F("id")})\n'
)
CHAIN = VIEWS + (
    "def listing(request: HttpRequest):\n"
    '    return Item.objects.filter(name="x").annotate(**{request.GET["alias"]: F("id")})\n'
)
OTHER = (
    "import other_lib\n"
    "from django.http import HttpRequest\n\n\n"
    "def listing(request: HttpRequest):\n"
    '    return other_lib.objects.annotate(**{request.GET["alias"]: 1})\n'
)
FIXED = VIEWS + 'def fixed(request: HttpRequest):\n    return Item.objects.annotate(**{"total": F("id")})\n'
PENDING = VIEWS + (
    "def options():\n    return {}\n\n\n"
    "def listing(request: HttpRequest):\n    opts = options()\n    return Item.objects.annotate(**opts)\n"
)
RULED_OUT = f"app.views:8 {DERIVED}(keywords=total)"


def analyse(root: Path, views: str, curated: Advisory = ADVISORY) -> ProjectAnalysis:
    files = {"uv.lock": LOCK, "app/__init__.py": "", "app/models.py": MODELS, "app/views.py": views}
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories((curated,)), encoding="utf-8")
    return engine.analyze_project(root, [PLUGINS])


def of_rule(analysis: ProjectAnalysis, rule_id: str) -> list[Finding]:
    return sorted((f for f in analysis.findings if f.rule_id == rule_id), key=lambda f: f.span.start_line)


def statement(analysis: ProjectAnalysis, root: Path) -> dict[str, Any]:
    evidence = (*analysis.findings, *analysis.suppressed, *analysis.accepted)
    document = render_vex(
        analysis.dependencies, analysis.advisories, evidence, analysis.coverage, root, "coretrace", "0.6.0", NOW
    )
    return next(s for s in json.loads(document)["statements"] if s["vulnerability"]["name"] == ADVISORY.id)


# --------------------------------------------------------------------------- the reproduction


def test_a_suffix_matches_the_receiver_the_engine_cannot_type(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, ISSUE)

    (found,) = of_rule(analysis, "exploitable-vulnerability")
    assert found.metadata["symbol"] == DERIVED
    assert found.metadata["entry_point"] == QUERYSET
    assert found.metadata["conditions_met"] == TEXT
    assert statement(analysis, tmp_path)["status"] == "affected"


def test_a_declared_queryset_chain_matches_through_its_own_suffix(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, CHAIN)

    (found,) = of_rule(analysis, "exploitable-vulnerability")
    assert found.metadata["symbol"].endswith("objects.filter.annotate")
    assert found.metadata["entry_point"] == QUERYSET
    assert statement(analysis, tmp_path)["status"] == "affected"


def test_a_chain_not_declared_does_not_match(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, CHAIN, advisory("objects.annotate"))

    assert of_rule(analysis, "reachable-vulnerability") == []
    assert of_rule(analysis, "exploitable-vulnerability") == []


def test_another_packages_receiver_never_matches(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, OTHER)

    assert of_rule(analysis, "reachable-vulnerability") == []
    assert of_rule(analysis, "exploitable-vulnerability") == []
    (declared,) = of_rule(analysis, "vulnerable-dependency")
    assert declared.metadata["advisory"] == ADVISORY.id


# --------------------------------------------------------------------------- conditions through the suffix


def test_constant_keys_through_the_suffix_rule_the_call_out(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, FIXED)

    assert of_rule(analysis, "reachable-vulnerability") == []
    assert of_rule(analysis, "exploitable-vulnerability") == []
    (declared,) = of_rule(analysis, "vulnerable-dependency")
    assert declared.metadata["ruled_out"] == RULED_OUT
    assert statement(analysis, tmp_path)["status"] == "not_affected"


def test_an_unknown_mapping_reaches_with_the_condition_pending(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, PENDING)

    (reached,) = of_rule(analysis, "reachable-vulnerability")
    assert reached.metadata["symbol"] == DERIVED
    assert reached.metadata["entry_point"] == QUERYSET
    assert reached.metadata["conditions_pending_review"] == TEXT
    assert of_rule(analysis, "exploitable-vulnerability") == []


# --------------------------------------------------------------------------- advisory files


def test_suffixes_round_trip_through_advisory_files(tmp_path: Path) -> None:
    path = tmp_path / "advisories.json"
    path.write_text(dump_advisories((ADVISORY,)), encoding="utf-8")

    assert load_advisories(path) == (ADVISORY,)
    (entry,) = json.loads(path.read_text())["advisories"][0]["entry_points"]
    assert entry["suffixes"] == ["objects.annotate", "objects.filter.annotate"]


def test_an_entry_point_without_suffixes_dumps_no_suffixes_key() -> None:
    (entry,) = json.loads(dump_advisories((advisory(),)))["advisories"][0]["entry_points"]
    assert "suffixes" not in entry


@pytest.mark.parametrize(
    "value",
    [42, "", "annotate", ".objects.annotate", "objects..annotate", "objects.annotate."],
    ids=["not-a-string", "empty", "one-name", "leading-dot", "empty-segment", "trailing-dot"],
)
def test_an_invalid_suffix_is_rejected(tmp_path: Path, value: Any) -> None:
    document = json.loads(dump_advisories((ADVISORY,)))
    document["advisories"][0]["entry_points"][0]["suffixes"] = [value]
    path = tmp_path / "advisories.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(AdvisoryFileError):
        load_advisories(path)


# --------------------------------------------------------------------------- the shared matching machinery


def test_an_exact_advisory_sink_composes_with_a_suffix_sink() -> None:
    table = ModelTable((), (), (), suffix_sinks=(SuffixSink("objects.extra", TaintKind.SQL),))
    extended = table.extended(Sink(SymbolId("python.app.models.Item.objects.extra"), TaintKind.ADVISORY))

    found = extended.sink(SymbolId("python.app.models.Item.objects.extra"))
    assert found is not None and found.kinds == TaintKind.SQL | TaintKind.ADVISORY


def test_extended_takes_suffix_sinks_that_resolve_derived_symbols() -> None:
    table = ModelTable((), (), ()).extended(suffixes=(SuffixSink("objects.annotate", TaintKind.ADVISORY),))

    found = table.sink(SymbolId(DERIVED))
    assert found is not None and found.kinds == TaintKind.ADVISORY


def test_a_suffix_matches_project_symbols_on_dot_boundaries_only() -> None:
    affected = {SymbolId(QUERYSET): (ADVISORY,)}
    index = suffix_index(affected, ("app", "app.models", "app.views"))

    (match,) = index.matches(SymbolId(DERIVED))
    assert match == (ADVISORY, ADVISORY.entry_points[0])
    assert index.matches(SymbolId("python.app.models.Item.myobjects.annotate")) == ()
    assert index.matches(SymbolId("python.other_lib.objects.annotate")) == ()


def test_two_advisories_declaring_the_same_suffix_both_match() -> None:
    other = replace(advisory("objects.annotate"), id="CVE-2026-0001")
    affected = {SymbolId(QUERYSET): (ADVISORY, other)}
    index = suffix_index(affected, ("app",))

    found = affected_entries(SymbolId(DERIVED), affected, index)
    assert [(a.id, None if e is None else str(e.symbol)) for a, e in found] == [
        (ADVISORY.id, QUERYSET),
        (other.id, QUERYSET),
    ]
