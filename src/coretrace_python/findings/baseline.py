"""The baseline: findings accepted at a point in time, so only new ones fail a check.

A finding is recognised by its file relative to the root, its rule, its function and the
text of its line, never by its line number: code inserted above it does not make it
new, a change to the line itself does. Entries are counted, so two identical findings on
identical lines need two entries.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from coretrace_python.findings.model import Finding
from coretrace_python.source import decode_text

BASELINE_SCHEMA = 1

Fingerprint = tuple[str, str, str, str]


class BaselineError(Exception):
    """The baseline file cannot be read."""


def fingerprint(finding: Finding, root: Path) -> Fingerprint:
    path = Path(str(finding.span.source_id))
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        relative = path.as_posix()
    return (relative, finding.rule_id, finding.function or "", _line_text(path, finding.span.start_line))


def _line_text(path: Path, line: int) -> str:
    try:
        lines = decode_text(path.read_bytes()).splitlines()
    except (OSError, UnicodeDecodeError):
        return str(line)
    if not 1 <= line <= len(lines):
        return str(line)
    return lines[line - 1].strip()


@dataclass(frozen=True)
class Baseline:
    entries: Counter[Fingerprint] = field(default_factory=Counter)

    @classmethod
    def of(cls, findings: Iterable[Finding], root: Path) -> Baseline:
        return cls(Counter(fingerprint(finding, root) for finding in findings))

    @classmethod
    def load(cls, path: Path) -> Baseline:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            if document.get("schema") != BASELINE_SCHEMA:
                raise BaselineError(f"{path}: unsupported baseline schema {document.get('schema')!r}")
            entries = Counter(
                {
                    (str(e["path"]), str(e["rule"]), str(e["function"]), str(e["line"])): int(e["count"])
                    for e in document["findings"]
                }
            )
        except BaselineError:
            raise
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            raise BaselineError(f"{path}: {error}") from error
        return cls(entries)

    def save(self, path: Path) -> None:
        document = {
            "schema": BASELINE_SCHEMA,
            "findings": [
                {"path": p, "rule": r, "function": f, "line": line, "count": count}
                for (p, r, f, line), count in sorted(self.entries.items())
            ],
        }
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    def partition(
        self, findings: Iterable[Finding], root: Path
    ) -> tuple[tuple[Finding, ...], tuple[Finding, ...]]:
        """The findings not in the baseline, and those it accounts for."""

        remaining = Counter(self.entries)
        new: list[Finding] = []
        baselined: list[Finding] = []
        for finding in findings:
            key = fingerprint(finding, root)
            if remaining[key] > 0:
                remaining[key] -= 1
                baselined.append(finding)
            else:
                new.append(finding)
        return tuple(new), tuple(baselined)
