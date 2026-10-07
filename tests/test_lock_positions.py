"""Acceptance tests for issue #207: a vulnerable package pinned in a lock file.

The finding is located at the package's own entry, the ``name = "..."`` line of its
``[[package]]`` table, which the position component checks; not at the first line that
mentions the name, which may be another package's dependency list. When the entry cannot
be placed, the finding has a file location, never a guessed line. The message states the
evidence: the pinned version, the lock file, and the packages that require it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.dependency import Advisory, dump_advisories
from coretrace_python.findings import Finding, Severity
from coretrace_python.source import SourceSpan
from coretrace_python.source.positions import file_location

PLUGINS = Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"
ADVISORY = Advisory(
    "CVE-2099-0207", "werkzeug", "<3.1.6", "safe_join accepts a device name", Severity.MEDIUM
)

UV_LOCK = """version = 1

[[package]]
name = "flask"
version = "3.1.2"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "werkzeug" },
]

[[package]]
name = "werkzeug"
version = "3.1.5"
source = { registry = "https://pypi.org/simple" }
"""
POETRY_LOCK = """[[package]]
name = "flask"
version = "3.1.2"

[package.dependencies]
werkzeug = ">=3.1"

[[package]]
name = "werkzeug"
version = "3.1.5"
"""
INLINE_LOCK = 'version = 1\npackage = [{ name = "werkzeug", version = "3.1.5" }]\n'


def vulnerable(tmp_path: Path, lock: str, text: str) -> Finding:
    (tmp_path / lock).write_text(text, encoding="utf-8")
    (tmp_path / "advisories.json").write_text(dump_advisories((ADVISORY,)), encoding="utf-8")
    (tmp_path / "app.py").write_text("import werkzeug\n", encoding="utf-8")
    (finding,) = [
        f
        for f in engine.analyze_project(tmp_path, [PLUGINS]).findings
        if f.rule_id == "vulnerable-dependency" and f.metadata["advisory"] == ADVISORY.id
    ]
    return finding


@pytest.mark.parametrize(
    ("lock", "text", "line"), [("uv.lock", UV_LOCK, 12), ("poetry.lock", POETRY_LOCK, 9)]
)
def test_a_locked_package_is_located_at_its_own_entry(
    tmp_path: Path, lock: str, text: str, line: int
) -> None:
    finding = vulnerable(tmp_path, lock, text)

    assert isinstance(finding.span, SourceSpan)
    assert (finding.span.start_line, finding.span.start_column) == (line, 8)


@pytest.mark.parametrize(("lock", "text"), [("uv.lock", UV_LOCK), ("poetry.lock", POETRY_LOCK)])
def test_the_message_states_the_pinned_version_the_lock_file_and_its_dependents(
    tmp_path: Path, lock: str, text: str
) -> None:
    finding = vulnerable(tmp_path, lock, text)

    assert finding.message == (
        f"CVE-2099-0207: werkzeug 3.1.5, pinned in {lock}, is in <3.1.6 (required by flask): "
        "safe_join accepts a device name"
    )


def test_a_locked_package_that_cannot_be_placed_has_a_file_location(tmp_path: Path) -> None:
    finding = vulnerable(tmp_path, "uv.lock", INLINE_LOCK)

    assert finding.span == file_location(finding.span.source_id, ("package", 0, "name"), "werkzeug")
    assert finding.message.startswith(
        "CVE-2099-0207: werkzeug 3.1.5, pinned in uv.lock, is in <3.1.6: "
    )


def test_a_declared_requirement_keeps_its_wording(tmp_path: Path) -> None:
    finding = vulnerable(tmp_path, "requirements.txt", "werkzeug>=3.0\n")

    assert (
        finding.message
        == "CVE-2099-0207: werkzeug <3.1.6 is allowed by werkzeug>=3.0: safe_join accepts a device name"
    )
    assert isinstance(finding.span, SourceSpan) and finding.span.start_line == 1
