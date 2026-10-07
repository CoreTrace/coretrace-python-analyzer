"""The baseline: findings accepted at a point in time, so only new ones fail a check.

A finding is recognised by its file relative to the root, its rule, its function and the
text of its line, never by its line number: code inserted above it does not make it
new, a change to the line itself does. A finding with a file location, whose line is not
established, is recognised by the JSON pointer of its value and a digest of the value
instead, never the value itself: a new value there is a new finding. Entries are
counted, so two identical findings on identical lines need two entries.

Baselines are written in schema 2, whose entries carry the pointer. Schema 1 files are
still read, and their entries match exactly as they did. There, a finding in a JSON, TOML
or lock file was recorded with the text of its key's first line, its own only when the
key was not repeated: such an entry still identifies that finding, and no other. A
finding it cannot identify with certainty is new, and ``transition_notice`` asks for the
baseline to be recorded again.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from coretrace_python.findings.model import Finding
from coretrace_python.source import SourceSpan, decode_text, lines_of

BASELINE_SCHEMA = 2
_LEGACY_SCHEMA = 1
# Files whose findings schema 1 placed at their key's first line.
_STRUCTURED = (".json", ".toml", ".lock")

# File, rule, function, text of the line (for a file location, the digest of its
# value), pointer (empty for a line).
Fingerprint = tuple[str, str, str, str, str]


class BaselineError(Exception):
    """The baseline file cannot be read."""


def fingerprint(finding: Finding, root: Path) -> Fingerprint:
    path = Path(str(finding.span.source_id))
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        relative = path.as_posix()
    head = (relative, finding.rule_id, finding.function or "")
    if isinstance(finding.span, SourceSpan):
        return (*head, _line_text(path, finding.span.start_line), "")
    return (*head, finding.span.digest, finding.span.pointer)


def _line_text(path: Path, line: int) -> str:
    """The text of ``line``, lines counted as every line number of the engine counts
    them (``lines_of``)."""

    try:
        lines = lines_of(decode_text(path.read_bytes()))
    except (OSError, UnicodeDecodeError):
        return str(line)
    if not 1 <= line <= len(lines):
        return str(line)
    return lines[line - 1].strip()


@dataclass(frozen=True)
class Baseline:
    entries: Counter[Fingerprint] = field(default_factory=Counter)
    # Read from a schema 1 file, whose entries on structured files may no longer match.
    legacy: bool = False

    @classmethod
    def of(cls, findings: Iterable[Finding], root: Path) -> Baseline:
        return cls(Counter(fingerprint(finding, root) for finding in findings))

    @classmethod
    def load(cls, path: Path) -> Baseline:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            schema = document.get("schema")
            if schema not in (_LEGACY_SCHEMA, BASELINE_SCHEMA):
                raise BaselineError(f"{path}: unsupported baseline schema {schema!r}")
            entries = Counter(
                {
                    (
                        str(e["path"]),
                        str(e["rule"]),
                        str(e["function"]),
                        str(e.get("line", "")),
                        str(e.get("pointer", "")),
                    ): int(e["count"])
                    for e in document["findings"]
                }
            )
        except BaselineError:
            raise
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            raise BaselineError(f"{path}: {error}") from error
        return cls(entries, legacy=schema == _LEGACY_SCHEMA)

    def save(self, path: Path) -> None:
        document = {
            "schema": BASELINE_SCHEMA,
            "findings": [
                {"path": p, "rule": r, "function": f, "line": line, "pointer": pointer, "count": count}
                for (p, r, f, line, pointer), count in sorted(self.entries.items())
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

    def transition_notice(self, new: Iterable[Finding]) -> str | None:
        """What to tell when a schema 1 baseline leaves findings of JSON, TOML or lock
        files new: their old entries may name another line, so the baseline is to be
        recorded again; None otherwise."""

        if not self.legacy or not any(str(finding.span.source_id).endswith(_STRUCTURED) for finding in new):
            return None
        return (
            "schema 1 baseline: findings in JSON, TOML and lock files are now located at their own "
            "line or by their pointer, and an old entry that cannot identify one with certainty no "
            "longer accounts for it; review the new findings, then delete the baseline and run the "
            "check again to record it in schema 2"
        )
