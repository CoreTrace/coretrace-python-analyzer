"""An advisory condition may require an argument to be passed, whatever its value.

Several aiohttp advisories ride on an argument the project passes: a ``\\r`` in
``web.Response(reason=...)`` splits the status line whatever the value denotes, so a
call giving ``reason`` — positionally, by keyword, or through a folded ``**`` literal —
meets the condition, a call without it is ruled out (``(reason absent)``) and the
project stays ``not_affected``, and a call the engine cannot read (``*args``, an unknown
``**mapping``) leaves it pending review. The form is exclusive with ``values`` and
``default``: the argument being passed is the whole condition.
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
from coretrace_python.dependency.correlation import check_conditions
from coretrace_python.engine import ProjectAnalysis
from coretrace_python.findings import Finding, Severity
from coretrace_python.semantic.symbols import SymbolId

PLUGINS = engine.BUNDLED_PLUGINS
NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)

RESPONSE = "python.aiohttp.web.Response"
TEXT = "reason is passed"
CONDITION = Condition("argument", TEXT, argument="reason", position=1, present=True)
ADVISORY = Advisory(
    "CVE-2026-34519",
    "aiohttp",
    "<3.13.4",
    "a carriage return in the reason splits the status line",
    Severity.HIGH,
    entry_points=(AdvisoryEntryPoint(SymbolId(RESPONSE), "the reason is written into the status line", (CONDITION,)),),
    modules=("aiohttp",),
)

HANDLERS = "from aiohttp import web\n\n\n"
ISSUE = HANDLERS + (
    "async def status(request: web.Request) -> web.Response:\n"
    '    return web.Response(status=400, reason=request.query["r"])\n'
    "\n\n"
    "async def plain(request: web.Request) -> web.Response:\n"
    '    return web.Response(text="ok")\n'
)
PLAIN = HANDLERS + 'async def plain(request: web.Request) -> web.Response:\n    return web.Response(text="ok")\n'

# The lock file shows no other package requires aiohttp, so a project whose calls are
# all ruled out can reach ``not_affected`` in the VEX document.
LOCK = """version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "aiohttp" }]

[[package]]
name = "aiohttp"
version = "3.13.2"
source = { registry = "https://pypi.org/simple" }
"""


def analyse(root: Path, source: str) -> ProjectAnalysis:
    for relative, text in {"requirements.txt": "aiohttp==3.13.2\n", "uv.lock": LOCK, "app.py": source}.items():
        (root / relative).write_text(text, encoding="utf-8")
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


def handler(call: str) -> str:
    return HANDLERS + f"async def status(request: web.Request) -> web.Response:\n    return web.Response({call})\n"


# --------------------------------------------------------------------------- the reproduction


def test_a_call_passing_the_argument_meets_the_condition_and_is_exploitable(tmp_path: Path) -> None:
    analysis = analyse(tmp_path, ISSUE)

    (found,) = of_rule(analysis, "exploitable-vulnerability")
    assert found.span.start_line == 5
    assert found.metadata["symbol"] == RESPONSE
    assert found.metadata["conditions_met"] == TEXT
    assert "conditions_pending_review" not in found.metadata
    assert statement(analysis, tmp_path)["status"] == "affected"


def test_a_call_without_the_argument_is_ruled_out_and_the_project_not_affected(tmp_path: Path) -> None:
    ruled_out = f"app:5 {RESPONSE}(reason absent)"

    analysis = analyse(tmp_path, PLAIN)

    assert of_rule(analysis, "reachable-vulnerability") == []
    assert of_rule(analysis, "exploitable-vulnerability") == []
    (declared,) = of_rule(analysis, "vulnerable-dependency")
    assert declared.metadata["level"] == "imported"
    assert declared.metadata["ruled_out"] == ruled_out
    found = statement(analysis, tmp_path)
    assert found["status"] == "not_affected"
    assert found["impact_statement"].endswith(f" Calls ruled out by their arguments: {ruled_out}.")


# --------------------------------------------------------------------------- how the argument is passed


@pytest.mark.parametrize(
    "call",
    [
        'status=400, reason=request.query["r"]',
        'b"", request.query["r"]',
        '**{"reason": request.query["r"]}',
    ],
    ids=["keyword", "positional", "folded-literal"],
)
def test_the_argument_counts_however_the_call_gives_it(tmp_path: Path, call: str) -> None:
    analysis = analyse(tmp_path, handler(call))

    (found,) = of_rule(analysis, "exploitable-vulnerability")
    assert found.metadata["symbol"] == RESPONSE
    assert found.metadata["conditions_met"] == TEXT
    assert "conditions_pending_review" not in found.metadata


@pytest.mark.parametrize("call", ["**options", "*rest"], ids=["unknown-mapping", "starred"])
def test_a_call_the_engine_cannot_read_leaves_the_condition_pending(tmp_path: Path, call: str) -> None:
    source = f"from aiohttp import web\n\ndef build(options, rest):\n    return web.Response({call})\n"

    analysis = analyse(tmp_path, source)

    (reached,) = of_rule(analysis, "reachable-vulnerability")
    assert reached.metadata["symbol"] == RESPONSE
    assert reached.metadata["conditions_pending_review"] == TEXT
    assert "conditions_met" not in reached.metadata
    assert of_rule(analysis, "exploitable-vulnerability") == []


def test_without_call_arguments_the_condition_stays_pending() -> None:
    check = check_conditions(ADVISORY.entry_points[0], None)

    assert check.met == ()
    assert check.pending == (CONDITION,)
    assert check.contradicted is None


# --------------------------------------------------------------------------- advisory files


def test_the_condition_round_trips_through_advisory_files(tmp_path: Path) -> None:
    path = tmp_path / "advisories.json"
    path.write_text(dump_advisories((ADVISORY,)), encoding="utf-8")

    assert load_advisories(path) == (ADVISORY,)
    (entry,) = json.loads(path.read_text())["advisories"][0]["entry_points"]
    assert entry["conditions"] == [
        {"kind": "argument", "text": TEXT, "argument": "reason", "position": 1, "present": True}
    ]


@pytest.mark.parametrize(
    "condition",
    [
        {"kind": "argument", "text": TEXT, "argument": "reason", "present": True, "values": ["'x'"]},
        {"kind": "argument", "text": TEXT, "argument": "reason", "present": True, "default": True},
        {"kind": "argument", "text": TEXT, "present": True},
        {"kind": "semantic", "text": TEXT, "present": True},
        {"kind": "argument", "text": TEXT, "argument": "reason", "present": "yes"},
    ],
    ids=["values", "default", "no-argument", "not-argument-kind", "not-boolean"],
)
def test_a_malformed_present_condition_is_rejected(tmp_path: Path, condition: dict[str, Any]) -> None:
    document = json.loads(dump_advisories((ADVISORY,)))
    document["advisories"][0]["entry_points"][0]["conditions"] = [condition]
    path = tmp_path / "advisories.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(AdvisoryFileError, match="present"):
        load_advisories(path)
