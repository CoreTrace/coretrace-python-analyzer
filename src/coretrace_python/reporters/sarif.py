"""SARIF 2.1.0 reporter."""

from __future__ import annotations

import json

from coretrace_python.findings import Finding, Severity
from coretrace_python.reporters.report import Report

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _result(finding: Finding, rule_index: int) -> dict[str, object]:
    span = finding.span
    region: dict[str, int] = {"startLine": span.start_line, "startColumn": span.start_column}
    if span.end_line is not None and span.end_column is not None:
        region["endLine"] = span.end_line
        region["endColumn"] = span.end_column
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVELS[finding.severity],
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": str(span.source_id)},
                    "region": region,
                }
            }
        ],
    }


def render_sarif(report: Report) -> str:
    rule_ids: list[str] = []
    for finding in report.findings:
        if finding.rule_id not in rule_ids:
            rule_ids.append(finding.rule_id)
    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": report.tool_name,
                        "version": report.tool_version,
                        "rules": [
                            {"id": rule_id, "shortDescription": {"text": rule_id}}
                            for rule_id in rule_ids
                        ],
                    }
                },
                "results": [
                    _result(finding, rule_ids.index(finding.rule_id)) for finding in report.findings
                ],
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"
