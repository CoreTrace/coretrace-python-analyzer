"""The baseline: findings accepted at a point in time, so only new ones fail a check.

A finding is recognised by its file relative to the root, its rule, its function and a
digest of the text of every line its span covers, never by its line number: code
inserted above it does not make it new, a change to its text does, on any of its lines,
as the body of a secret written over several lines (#223). A finding with a file
location, whose line is not established, is recognised by the JSON pointer of its value
and the value instead. An entry holds digests of them only, never the text, the value or
the pointer, whose keys may be secrets too, so the file, which is meant to be committed,
holds no accepted secret (#224). Entries are counted, so two identical findings on
identical lines need two entries.

Baselines are written in schema 3. Schema 1 and 2 files are still read, and never
rewritten; their entries hold the text of a finding's first line, which identifies a
finding on a single line exactly as it did, and no finding over several lines, whose
other lines it does not hold: such a finding is new. Schema 1 also recorded a finding
in a JSON, TOML or lock file with the text of its key's first line, its own only when
the key was not repeated: such an entry still identifies that finding, and no other.
Reading an old baseline, the check warns, with ``transition_notice``, that it may hold
secrets in plain text and is to be reviewed and recorded again.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from coretrace_python.findings.model import Finding
from coretrace_python.source import SourceSpan, decode_text, lines_of
from coretrace_python.source.positions import text_digest

BASELINE_SCHEMA = 3
# Schemas whose entries hold the text of a finding's first line.
_LEGACY_SCHEMAS = (1, 2)

# File, rule, function, digest of the text of the span's lines (of the value, for a
# file location), digest of the pointer (empty for a span). In schemas 1 and 2, the text
# of the span's first line and the pointer itself.
Fingerprint = tuple[str, str, str, str, str]


class BaselineError(Exception):
    """The baseline file cannot be read."""


def fingerprint(finding: Finding, root: Path) -> Fingerprint:
    path, head = _head(finding, root)
    span = finding.span
    if isinstance(span, SourceSpan):
        return (*head, text_digest(_span_text(path, span)), "")
    # A key above the value may itself be a secret.
    return (*head, span.digest, text_digest(span.pointer))


def legacy_fingerprint(finding: Finding, root: Path) -> Fingerprint | None:
    """The fingerprint of ``finding`` as schemas 1 and 2 recorded it, or None for a
    finding over several lines, which an entry of those schemas cannot identify."""

    path, head = _head(finding, root)
    span = finding.span
    if not isinstance(span, SourceSpan):
        return (*head, span.digest, span.pointer)
    if span.end_line not in (None, span.start_line):
        return None
    return (*head, _span_text(path, span), "")


def _head(finding: Finding, root: Path) -> tuple[Path, tuple[str, str, str]]:
    path = Path(str(finding.span.source_id))
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        relative = path.as_posix()
    return path, (relative, finding.rule_id, finding.function or "")


def _span_text(path: Path, span: SourceSpan) -> str:
    """The text of the lines ``span`` covers, each stripped, lines counted as every line
    number of the engine counts them (``lines_of``); the line number when the file
    cannot be read or does not reach it."""

    try:
        lines = lines_of(decode_text(path.read_bytes()))
    except (OSError, UnicodeDecodeError):
        return str(span.start_line)
    if span.start_line > len(lines):
        return str(span.start_line)
    covered = lines[span.start_line - 1 : span.end_line or span.start_line]
    return "\n".join(line.strip() for line in covered)


@dataclass(frozen=True)
class Baseline:
    entries: Counter[Fingerprint] = field(default_factory=Counter)
    # The schema of the file read; its entries are compared by that schema's fingerprint.
    schema: int = BASELINE_SCHEMA

    @classmethod
    def of(cls, findings: Iterable[Finding], root: Path) -> Baseline:
        return cls(Counter(fingerprint(finding, root) for finding in findings))

    @classmethod
    def load(cls, path: Path) -> Baseline:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            schema = document.get("schema")
            if schema not in (*_LEGACY_SCHEMAS, BASELINE_SCHEMA):
                raise BaselineError(f"{path}: unsupported baseline schema {schema!r}")
            entries = Counter(
                {
                    (
                        str(e["path"]),
                        str(e["rule"]),
                        str(e["function"]),
                        str(e["digest"] if schema == BASELINE_SCHEMA else e.get("line", "")),
                        str(e.get("pointer", "")),
                    ): int(e["count"])
                    for e in document["findings"]
                }
            )
        except BaselineError:
            raise
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            raise BaselineError(f"{path}: {error}") from error
        return cls(entries, schema)

    def save(self, path: Path) -> None:
        document = {
            "schema": BASELINE_SCHEMA,
            "findings": [
                {"path": p, "rule": r, "function": f, "digest": digest, "pointer": pointer, "count": count}
                for (p, r, f, digest, pointer), count in sorted(self.entries.items())
            ],
        }
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    def partition(
        self, findings: Iterable[Finding], root: Path
    ) -> tuple[tuple[Finding, ...], tuple[Finding, ...]]:
        """The findings not in the baseline, and those it accounts for."""

        key_of: Callable[[Finding, Path], Fingerprint | None] = (
            fingerprint if self.schema == BASELINE_SCHEMA else legacy_fingerprint
        )
        remaining = Counter(self.entries)
        new: list[Finding] = []
        baselined: list[Finding] = []
        for finding in findings:
            key = key_of(finding, root)
            if key is not None and remaining[key] > 0:
                remaining[key] -= 1
                baselined.append(finding)
            else:
                new.append(finding)
        return tuple(new), tuple(baselined)

    def transition_notice(self) -> str | None:
        """What to tell when the baseline was read from schema 1 or 2, whose entries hold
        the text of lines and identify only findings on a single line: it is to be
        reviewed and recorded again; None for a schema 3 baseline."""

        if self.schema == BASELINE_SCHEMA:
            return None
        return (
            f"schema {self.schema} baseline: this baseline may contain secrets in plain text. Its "
            "entries identify only findings on a single line, so a finding over several lines, or "
            "in a JSON, TOML or lock file, may be reported new only because no old entry can "
            "identify it with certainty. Review the baseline and the new findings, then migrate it "
            f"explicitly to schema {BASELINE_SCHEMA}: delete it and run the check again, which "
            "records digests only"
        )
