"""The normalized report every reporter renders (architecture §23, §28)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from coretrace_python.findings import Coverage, Finding


def _order(finding: Finding) -> tuple[str, int, int, str]:
    span = finding.span
    return (str(span.source_id), span.start_line, span.start_column, finding.rule_id)


@dataclass(frozen=True)
class Report:
    findings: tuple[Finding, ...]
    tool_name: str
    tool_version: str
    coverage: Coverage | None = None
    # The directory the report is about: paths under it are rendered relative to it.
    root: Path | None = None
    # Findings silenced by an inline suppression; reported apart, never counted.
    suppressed: tuple[Finding, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(sorted(self.findings, key=_order)))
        object.__setattr__(self, "suppressed", tuple(sorted(self.suppressed, key=_order)))

    def locate(self, path: str) -> str:
        """``path`` relative to the root, POSIX style, when it lies under the root."""

        if self.root is None:
            return path
        try:
            return PurePosixPath(Path(path).relative_to(self.root)).as_posix()
        except ValueError:
            return path

    def under_root(self, path: str) -> bool:
        return self.root is not None and self.locate(path) != path
