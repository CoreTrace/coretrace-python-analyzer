"""Acceptance tests for the reporter API (``docs/architecture.md`` §23, §28).

Reporters consume a ``Report`` of normalized findings and render text, JSON or SARIF.
They are pure functions of the report: they never run an analysis and import nothing
from the analysis pipeline. Output is deterministic, sorted by location then rule.

Expected to remain red until ``coretrace_python.reporters`` exists.
"""

from __future__ import annotations

import ast
import json
from dataclasses import replace
from pathlib import Path

import pytest

from coretrace_python.findings import (
    FINDING_SCHEMA_VERSION,
    Confidence,
    Finding,
    RelatedLocation,
    Severity,
)
from coretrace_python.source import SourceId, SourceSpan

try:
    from coretrace_python.reporters import (
        FORMATS,
        Report,
        render,
        render_json,
        render_sarif,
        render_text,
    )
except ImportError as error:  # pragma: no cover - red until reporters land
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_reporters() -> None:
    if MISSING is not None:
        pytest.fail(f"reporters are not implemented yet: {MISSING}")


def finding(
    rule: str,
    line: int,
    column: int = 5,
    severity: Severity = Severity.HIGH,
    path: str = "app/views.py",
    function: str | None = "run",
    **metadata: str,
) -> Finding:
    return Finding(
        rule_id=rule,
        message=f"{rule} message",
        severity=severity,
        confidence=Confidence.HIGH,
        span=SourceSpan(SourceId(path), line, column, line, column + 4),
        function=function,
        metadata=metadata,
    )


def report(*findings: Finding) -> Report:
    return Report(findings=findings, tool_name="coretrace-python-analyzer", tool_version="0.1.0")


# --------------------------------------------------------------------------- report


def test_report_sorts_findings_by_location_then_rule() -> None:
    late = finding("b-rule", 9)
    early = finding("z-rule", 2)
    same_line = finding("a-rule", 2)
    other_file = finding("a-rule", 1, path="app/a.py")

    ordered = report(late, early, same_line, other_file).findings

    assert ordered == (other_file, same_line, early, late)


def test_report_is_immutable() -> None:
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        report().findings = ()  # type: ignore[misc]


# --------------------------------------------------------------------------- text


def test_text_reporter_prints_one_line_per_finding_and_a_summary() -> None:
    text = render_text(report(finding("dangerous-eval", 2), finding("sql-injection", 7, severity=Severity.MEDIUM, function=None)))

    assert text == (
        "app/views.py:2:5: high dangerous-eval: dangerous-eval message [run]\n"
        "app/views.py:7:5: medium sql-injection: sql-injection message\n"
        "2 findings\n"
    )


def test_text_reporter_reports_no_findings() -> None:
    assert render_text(report()) == "no findings\n"


# --------------------------------------------------------------------------- json


def test_json_reporter_emits_versioned_normalized_records() -> None:
    document = json.loads(render_json(report(finding("dangerous-eval", 2, symbol="python.builtins.eval"))))

    assert document["schema_version"] == FINDING_SCHEMA_VERSION
    assert document["tool"] == {"name": "coretrace-python-analyzer", "version": "0.1.0"}
    assert document["findings"] == [
        {
            "rule_id": "dangerous-eval",
            "message": "dangerous-eval message",
            "severity": "high",
            "confidence": "high",
            "location": {
                "path": "app/views.py",
                "line": 2,
                "column": 5,
                "end_line": 2,
                "end_column": 9,
            },
            "function": "run",
            "metadata": {"symbol": "python.builtins.eval"},
        }
    ]


def test_json_reporter_is_deterministic() -> None:
    a, b = finding("x", 3), finding("y", 1)
    assert render_json(report(a, b)) == render_json(report(b, a))
    assert render_json(report(a, b)).endswith("\n")


# --------------------------------------------------------------------------- sarif


def test_sarif_reporter_emits_a_single_run_with_rules_and_results() -> None:
    document = json.loads(
        render_sarif(
            report(
                finding("dangerous-eval", 2),
                finding("dangerous-eval", 5, severity=Severity.MEDIUM),
                finding("weak-crypto", 8, severity=Severity.LOW),
            )
        )
    )

    assert document["version"] == "2.1.0"
    assert document["$schema"].startswith("https://")
    (run,) = document["runs"]
    driver = run["tool"]["driver"]
    assert driver["name"] == "coretrace-python-analyzer"
    assert driver["version"] == "0.1.0"
    assert [rule["id"] for rule in driver["rules"]] == ["dangerous-eval", "weak-crypto"]
    assert [r["ruleId"] for r in run["results"]] == ["dangerous-eval", "dangerous-eval", "weak-crypto"]
    assert [r["level"] for r in run["results"]] == ["error", "warning", "note"]
    first = run["results"][0]
    assert first["message"] == {"text": "dangerous-eval message"}
    assert first["ruleIndex"] == 0
    assert first["locations"] == [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "app/views.py"},
                "region": {"startLine": 2, "startColumn": 5, "endLine": 2, "endColumn": 9},
            }
        }
    ]


def test_sarif_rules_carry_a_title_and_a_description() -> None:
    document = json.loads(render_sarif(report(finding("dangerous-eval", 2), finding("weak-crypto", 8))))

    for rule in document["runs"][0]["tool"]["driver"]["rules"]:
        assert rule["shortDescription"]["text"] not in ("", rule["id"])
        assert rule["fullDescription"]["text"]


def test_a_rule_without_a_description_keeps_its_id_alone() -> None:
    document = json.loads(render_sarif(report(finding("from-a-third-party-plugin", 1))))

    assert document["runs"][0]["tool"]["driver"]["rules"] == [{"id": "from-a-third-party-plugin"}]


def documented_rules() -> list[str]:
    """The rule ids the Rules section of the usage guide lists, and ``unsupported-syntax``."""

    usage = (Path(__file__).resolve().parent.parent / "docs" / "usage.md").read_text(encoding="utf-8")
    section = usage.split("\n## Rules\n", 1)[1].split("\n## ", 1)[0]
    rules = {line.split("`")[1] for line in section.splitlines() if line.startswith("| `")}
    return sorted(rules | {"unsupported-syntax"})


@pytest.mark.parametrize("rule", documented_rules())
def test_every_documented_rule_is_described(rule: str) -> None:
    (described,) = json.loads(render_sarif(report(finding(rule, 1))))["runs"][0]["tool"]["driver"]["rules"]

    assert described["shortDescription"]["text"] not in ("", rule)
    assert described["fullDescription"]["text"]


def test_sarif_results_carry_their_confidence() -> None:
    def confidence(level: Confidence) -> object:
        document = json.loads(render_sarif(report(replace(finding("r", 1), confidence=level))))
        return document["runs"][0]["results"][0]["properties"]["confidence"]

    assert confidence(Confidence.HIGH) == "high"
    assert confidence(Confidence.MEDIUM) == "medium"
    assert confidence(Confidence.LOW) == "low"


def test_the_confidence_sits_beside_the_other_properties() -> None:
    document = json.loads(render_sarif(report(finding("command-injection", 1, injection="option"))))

    assert document["runs"][0]["results"][0]["properties"] == {"confidence": "high", "injection": "option"}


def test_sarif_results_point_at_the_other_places_a_finding_involves() -> None:
    sink = SourceSpan(SourceId("app/helpers.py"), 12, 9, 12, 21)
    involved = replace(finding("code-injection", 3), related=(RelatedLocation(sink, "eval runs the input here"),))

    (result,) = json.loads(render_sarif(report(involved)))["runs"][0]["results"]

    assert result["relatedLocations"] == [
        {
            "id": 0,
            "physicalLocation": {
                "artifactLocation": {"uri": "app/helpers.py"},
                "region": {"startLine": 12, "startColumn": 9, "endLine": 12, "endColumn": 21},
            },
            "message": {"text": "eval runs the input here"},
        }
    ]


def test_the_message_links_to_each_related_location() -> None:
    sink = SourceSpan(SourceId("app/helpers.py"), 12, 9, 12, 21)
    involved = replace(
        finding("code-injection", 3),
        message="a[0] reaches eval",
        related=(RelatedLocation(sink, "sink eval"), RelatedLocation(sink, "sink [exec]")),
    )

    (result,) = json.loads(render_sarif(report(involved)))["runs"][0]["results"]

    # SARIF embedded links: [text](id) points at relatedLocations[id], which GitHub code
    # scanning shows as a link; literal brackets and backslashes are escaped around them.
    assert result["message"] == {"text": "a\\[0\\] reaches eval ([sink eval](0), [sink \\[exec\\]](1))"}


def test_a_result_without_other_places_has_no_related_locations() -> None:
    (result,) = json.loads(render_sarif(report(finding("code-injection", 3))))["runs"][0]["results"]

    assert "relatedLocations" not in result


def test_sarif_levels_follow_severity() -> None:
    def level(severity: Severity) -> str:
        document = json.loads(render_sarif(report(finding("r", 1, severity=severity))))
        return str(document["runs"][0]["results"][0]["level"])

    assert level(Severity.CRITICAL) == "error"
    assert level(Severity.HIGH) == "error"
    assert level(Severity.MEDIUM) == "warning"
    assert level(Severity.LOW) == "note"
    assert level(Severity.INFO) == "note"


# --------------------------------------------------------------------------- dispatch and purity


def test_render_dispatches_on_format_name() -> None:
    document = report(finding("r", 1))

    assert set(FORMATS) == {"text", "json", "sarif"}
    assert render("text", document) == render_text(document)
    assert render("json", document) == render_json(document)
    assert render("sarif", document) == render_sarif(document)
    with pytest.raises(KeyError):
        render("xml", document)


def test_reporters_never_touch_the_analysis_pipeline() -> None:
    package = Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "reporters"
    allowed = {"coretrace_python.findings", "coretrace_python.source", "coretrace_python.reporters"}

    for path in package.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("coretrace_python"):
                top = ".".join(node.module.split(".")[:2])
                assert top in allowed, f"{path.name} imports {node.module}"
