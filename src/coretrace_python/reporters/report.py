"""The normalized report every reporter renders (architecture §23, §28)."""

from __future__ import annotations

from dataclasses import dataclass

from coretrace_python.findings import Finding


def _order(finding: Finding) -> tuple[str, int, int, str]:
    span = finding.span
    return (str(span.source_id), span.start_line, span.start_column, finding.rule_id)


@dataclass(frozen=True)
class Report:
    findings: tuple[Finding, ...]
    tool_name: str
    tool_version: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(sorted(self.findings, key=_order)))
