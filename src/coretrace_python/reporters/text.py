"""Plain-text reporter: one ``path:line:column`` line per finding and a summary."""

from __future__ import annotations

from coretrace_python.reporters.report import Report


def render_text(report: Report) -> str:
    lines = []
    for finding in report.findings:
        span = finding.span
        line = (
            f"{report.locate(str(span.source_id))}:{span.start_line}:{span.start_column}: "
            f"{finding.severity.value} {finding.rule_id}: {finding.message}"
        )
        if finding.function is not None:
            line += f" [{finding.function}]"
        lines.append(line)
    count = len(report.findings)
    summary = "no findings" if count == 0 else f"{count} finding{'s' if count > 1 else ''}"
    if report.suppressed:
        summary += f", {len(report.suppressed)} suppressed"
    if report.baselined:
        summary += f", {len(report.baselined)} baselined"
    lines.append(summary)
    if report.coverage is not None:
        lines.append(report.coverage.summary())
    return "\n".join(lines) + "\n"
