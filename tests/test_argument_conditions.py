"""Argument conditions are decided at the call site.

An advisory entry point may be affected for some values of one argument only:
``yaml.load`` with ``Loader=FullLoader`` but not with ``SafeLoader``, ``add_static``
with ``follow_symlinks=True`` only. Each call records what its arguments denote — a
symbol, or a constant as Python writes it — so a condition is met, contradicted (the
call does not reach the vulnerability, and the vulnerable requirement says which call
was ruled out and why) or left pending review when the call does not tell.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cache import ProjectCache
from coretrace_python.dependency import (
    Advisory,
    AdvisoryEntryPoint,
    AdvisoryFileError,
    Condition,
    dump_advisories,
    load_advisories,
)
from coretrace_python.findings import Finding, Severity
from coretrace_python.semantic.symbols import SymbolId

REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"

MODE = Condition(
    "argument",
    "mode is UNSAFE, the default",
    argument="mode",
    values=("python.vulnlib.UNSAFE",),
    position=1,
    default=True,
)
TAG = Condition("semantic", "the document carries a custom tag")
FOLLOW = Condition("argument", "follow is True", argument="follow", values=("True",))

PARSE = Advisory(
    "CVE-2099-0101",
    "vulnlib",
    "<1.1",
    "parse runs code from the document in unsafe mode",
    Severity.CRITICAL,
    entry_points=(AdvisoryEntryPoint(SymbolId("python.vulnlib.parse"), "commit 1234abc", (MODE, TAG)),),
    modules=("vulnlib",),
)
SERVE = Advisory(
    "CVE-2099-0102",
    "vulnlib",
    "<1.1",
    "serve follows links out of its root",
    Severity.HIGH,
    entry_points=(AdvisoryEntryPoint(SymbolId("python.vulnlib.serve"), "commit 5678def", (FOLLOW,)),),
    modules=("vulnlib",),
)


def analyse(root: Path, files: dict[str, str], **options: object) -> engine.ProjectAnalysis:
    for relative, text in {"requirements.txt": "vulnlib==1.0\n", **files}.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories((PARSE, SERVE)), encoding="utf-8")
    return engine.analyze_project(root, [PLUGINS], **options)  # type: ignore[arg-type]


def calling(call: str) -> dict[str, str]:
    return {"app.py": f"import vulnlib\n\ndef run(text, path, choice, options, rest):\n    return {call}\n"}


def of_rule(findings: tuple[Finding, ...], rule_id: str) -> list[Finding]:
    return [f for f in findings if f.rule_id == rule_id]


# --------------------------------------------------------------------------- met


@pytest.mark.parametrize(
    "call",
    ["vulnlib.parse(text, mode=vulnlib.UNSAFE)", "vulnlib.parse(text, vulnlib.UNSAFE)", "vulnlib.parse(text)"],
)
def test_a_call_that_meets_the_argument_condition_is_reachable_with_the_condition_met(tmp_path: Path, call: str) -> None:
    (found,) = of_rule(analyse(tmp_path, calling(call)).findings, "reachable-vulnerability")

    assert found.metadata["conditions_met"] == "mode is UNSAFE, the default"
    assert found.metadata["conditions_pending_review"] == "the document carries a custom tag"


def test_a_constant_argument_meets_its_condition_as_python_writes_it(tmp_path: Path) -> None:
    (found,) = of_rule(analyse(tmp_path, calling("vulnlib.serve(path, follow=True)")).findings, "reachable-vulnerability")

    assert found.metadata["conditions_met"] == "follow is True"
    assert "conditions_pending_review" not in found.metadata


# --------------------------------------------------------------------------- contradicted


@pytest.mark.parametrize(
    "call, ruled_out",
    [
        ("vulnlib.parse(text, mode=vulnlib.SAFE)", "app:4 python.vulnlib.parse(mode=python.vulnlib.SAFE)"),
        ("vulnlib.parse(text, vulnlib.SAFE)", "app:4 python.vulnlib.parse(mode=python.vulnlib.SAFE)"),
        ("vulnlib.parse(text, mode=None)", "app:4 python.vulnlib.parse(mode=None)"),
        ("vulnlib.serve(path, follow=False)", "app:4 python.vulnlib.serve(follow=False)"),
        ("vulnlib.serve(path)", "app:4 python.vulnlib.serve(follow absent)"),
    ],
)
def test_a_call_that_contradicts_an_argument_condition_is_ruled_out_with_its_reason(
    tmp_path: Path, call: str, ruled_out: str
) -> None:
    findings = analyse(tmp_path, calling(call)).findings

    assert of_rule(findings, "reachable-vulnerability") == []
    dependencies = of_rule(findings, "vulnerable-dependency")
    assert [f.metadata.get("ruled_out") for f in dependencies if "ruled_out" in f.metadata] == [ruled_out]
    assert {f.metadata["level"] for f in dependencies} == {"imported"}


# --------------------------------------------------------------------------- undecided


@pytest.mark.parametrize(
    "call", ["vulnlib.parse(text, mode=choice)", "vulnlib.parse(text, **options)", "vulnlib.parse(*rest)"]
)
def test_a_call_that_does_not_tell_leaves_the_condition_pending_review(tmp_path: Path, call: str) -> None:
    (found,) = of_rule(analyse(tmp_path, calling(call)).findings, "reachable-vulnerability")

    assert "conditions_met" not in found.metadata
    assert found.metadata["conditions_pending_review"] == "mode is UNSAFE, the default; the document carries a custom tag"


# --------------------------------------------------------------------------- exploitable


def test_attacker_input_is_exploitable_only_through_a_call_that_meets_the_conditions(tmp_path: Path) -> None:
    source = "import vulnlib\n\ndef run():\n    vulnlib.parse(input(), mode=vulnlib.SAFE)\n    vulnlib.parse(input())\n"

    exploitable = of_rule(analyse(tmp_path, {"app.py": source}).findings, "exploitable-vulnerability")

    assert [(f.span.start_line, f.metadata["conditions_met"]) for f in exploitable] == [(5, "mode is UNSAFE, the default")]


def test_the_sink_call_decides_when_the_flow_goes_through_a_function_of_another_module(tmp_path: Path) -> None:
    files = {
        "app/__init__.py": "",
        "app/loader.py": (
            "import vulnlib\n\n"
            "def safe(text):\n    return vulnlib.parse(text, mode=vulnlib.SAFE)\n\n"
            "def unsafe(text):\n    return vulnlib.parse(text)\n"
        ),
        "app/main.py": "from app.loader import safe, unsafe\n\ndef run():\n    safe(input())\n    unsafe(input())\n",
    }

    exploitable = of_rule(analyse(tmp_path, files).findings, "exploitable-vulnerability")

    assert [(Path(str(f.span.source_id)).name, f.span.start_line, f.metadata.get("through")) for f in exploitable] == [
        ("main.py", 5, "app.loader.unsafe")
    ]


# --------------------------------------------------------------------------- cache and files


def test_a_module_served_from_the_cache_decides_the_same(tmp_path: Path) -> None:
    files = {"app.py": "import vulnlib\n\ndef run(text, path):\n    vulnlib.parse(text)\n    vulnlib.serve(path)\n"}
    cache = ProjectCache(tmp_path / "cache")

    first = analyse(tmp_path / "src", files, cache=cache)
    second = analyse(tmp_path / "src", files, cache=cache)

    assert "app" in second.reused
    assert second.findings == first.findings
    assert [f.metadata["advisory"] for f in of_rule(second.findings, "reachable-vulnerability")] == ["CVE-2099-0101"]
    assert "app:5 python.vulnlib.serve(follow absent)" in [f.metadata.get("ruled_out") for f in second.findings]


def test_argument_conditions_round_trip_through_advisory_files(tmp_path: Path) -> None:
    path = tmp_path / "advisories.json"
    path.write_text(dump_advisories((PARSE, SERVE)), encoding="utf-8")

    assert load_advisories(path) == (PARSE, SERVE)
    conditions = [e["conditions"][0] for a in json.loads(path.read_text())["advisories"] for e in a["entry_points"]]
    assert conditions[0] == {
        "kind": "argument",
        "text": "mode is UNSAFE, the default",
        "argument": "mode",
        "values": ["python.vulnlib.UNSAFE"],
        "position": 1,
        "default": True,
    }
    assert "position" not in conditions[1] and "default" not in conditions[1]


@pytest.mark.parametrize("field, value", [("position", "1"), ("default", "yes")])
def test_a_malformed_argument_condition_is_rejected(tmp_path: Path, field: str, value: str) -> None:
    path = tmp_path / "advisories.json"
    document = json.loads(dump_advisories((PARSE,)))
    document["advisories"][0]["entry_points"][0]["conditions"][0][field] = value
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(AdvisoryFileError, match=field):
        load_advisories(path)


def test_a_long_constant_is_not_recorded_and_leaves_the_condition_pending(tmp_path: Path) -> None:
    long = "x" * 100
    (found,) = of_rule(analyse(tmp_path, calling(f"vulnlib.serve(path, follow='{long}')")).findings, "reachable-vulnerability")

    assert found.metadata["conditions_pending_review"] == "follow is True"
