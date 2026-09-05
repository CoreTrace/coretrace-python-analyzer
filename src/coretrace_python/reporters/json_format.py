"""JSON reporter: versioned normalized finding records."""

from __future__ import annotations

import json

from coretrace_python.findings import FINDING_SCHEMA_VERSION, Finding
from coretrace_python.reporters.report import Report


def finding_record(finding: Finding, report: Report | None = None) -> dict[str, object]:
    span = finding.span
    path = str(span.source_id)
    return {
        "rule_id": finding.rule_id,
        "message": finding.message,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "location": {
            "path": report.locate(path) if report is not None else path,
            "line": span.start_line,
            "column": span.start_column,
            "end_line": span.end_line,
            "end_column": span.end_column,
        },
        "function": finding.function,
        "metadata": dict(finding.metadata),
    }


def render_json(report: Report) -> str:
    document: dict[str, object] = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "tool": {"name": report.tool_name, "version": report.tool_version},
    }
    if report.root is not None:
        document["root"] = str(report.root)
    document["findings"] = [finding_record(finding, report) for finding in report.findings]
    if report.suppressed:
        document["suppressed"] = [finding_record(finding, report) for finding in report.suppressed]
    if report.baselined:
        document["baselined"] = [finding_record(finding, report) for finding in report.baselined]
    if report.coverage is not None:
        coverage = report.coverage
        document["coverage"] = {
            "files": coverage.files,
            "files_analysed": coverage.files_analysed,
            "functions": coverage.functions,
            "functions_analysed": coverage.functions_analysed,
            "details": [
                {
                    "path": report.locate(d.path),
                    "status": d.status,
                    "functions": d.functions,
                    "analysed": d.analysed,
                }
                for d in coverage.details
            ],
        }
    return json.dumps(document, indent=2) + "\n"
