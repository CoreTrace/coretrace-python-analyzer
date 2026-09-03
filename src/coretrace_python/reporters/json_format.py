"""JSON reporter: versioned normalized finding records."""

from __future__ import annotations

import json

from coretrace_python.findings import FINDING_SCHEMA_VERSION, Finding
from coretrace_python.reporters.report import Report


def finding_record(finding: Finding) -> dict[str, object]:
    span = finding.span
    return {
        "rule_id": finding.rule_id,
        "message": finding.message,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "location": {
            "path": str(span.source_id),
            "line": span.start_line,
            "column": span.start_column,
            "end_line": span.end_line,
            "end_column": span.end_column,
        },
        "function": finding.function,
        "metadata": dict(finding.metadata),
    }


def render_json(report: Report) -> str:
    document = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "tool": {"name": report.tool_name, "version": report.tool_version},
        "findings": [finding_record(finding) for finding in report.findings],
    }
    return json.dumps(document, indent=2) + "\n"
