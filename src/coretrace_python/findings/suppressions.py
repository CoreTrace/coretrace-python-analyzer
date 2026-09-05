"""Inline suppressions: ``# coretrace: ignore`` on the line of a finding.

A bare ``ignore`` silences every finding reported on that line; ``ignore[rule, rule]``
silences the listed rules only. Python sources are tokenized so a string that merely
contains the marker is not a suppression; other text files (requirements files,
configuration) are read line by line with the same comment syntax.
"""

from __future__ import annotations

import io
import re
import tokenize
from collections.abc import Callable, Iterable, Mapping

from coretrace_python.findings.model import Finding
from coretrace_python.source import SourceId

MARKER = re.compile(r"#\s*coretrace:\s*ignore(?:\[([^\]]*)\])?")

Suppressions = Mapping[int, frozenset[str] | None]
"""Line number to the suppressed rules, ``None`` meaning every rule."""


def suppressions_in(text: str) -> Suppressions:
    found: dict[int, frozenset[str] | None] = {}
    for line, comment in _comments(text):
        match = MARKER.search(comment)
        if match is None:
            continue
        rules = match.group(1)
        if rules is None:
            found[line] = None
        elif found.get(line, ()) is not None:
            listed = frozenset(r.strip() for r in rules.split(",") if r.strip())
            found[line] = frozenset(found.get(line) or ()) | listed
    return found


def _comments(text: str) -> Iterable[tuple[int, str]]:
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError):
        for number, line in enumerate(text.splitlines(), 1):
            if "#" in line:
                yield number, line[line.index("#") :]
        return
    for token in tokens:
        if token.type == tokenize.COMMENT:
            yield token.start[0], token.string


def partition(
    findings: Iterable[Finding], text_of: Callable[[SourceId], str | None]
) -> tuple[tuple[Finding, ...], tuple[Finding, ...]]:
    """Split findings into the kept and the suppressed, reading each file's text once."""

    cache: dict[SourceId, Suppressions] = {}
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    for finding in findings:
        source_id = finding.span.source_id
        if source_id not in cache:
            text = text_of(source_id)
            cache[source_id] = suppressions_in(text) if text is not None else {}
        rules = cache[source_id].get(finding.span.start_line, frozenset())
        if rules is None or finding.rule_id in rules:
            suppressed.append(finding)
        else:
            kept.append(finding)
    return tuple(kept), tuple(suppressed)
