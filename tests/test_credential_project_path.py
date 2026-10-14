"""Acceptance tests for issue #253: test code is judged on a file's path in the project,
not on where the project sits.

``hardcoded-credential`` and ``config-secrets`` lower the confidence of a credential in
test code or in a template file. They used to judge the absolute path, so a project
under a directory named ``tests`` had every credential at low confidence, as test code.
They now judge the path from the root of the analysis, as the context of #244 does, in
every way the engine runs them: one process, worker processes, a file checked alone.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cli import main
from coretrace_python.findings import Confidence, Finding
from coretrace_python.source import SourceManager

PASSWORD = 'PASSWORD = "Zx81kQpLw0RtY7vB"\n'
YAML = "database:\n  password: Zx81kQpLw0RtY7vB\n"


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    return root


def credentials(findings: tuple[Finding, ...]) -> dict[str, tuple[Confidence, str | None]]:
    return {
        Path(str(f.span.source_id)).name: (f.confidence, f.metadata.get("context"))
        for f in findings
        if f.rule_id == "hardcoded-credential"
    }


@pytest.mark.parametrize("jobs", [1, 2])
def test_a_project_under_a_tests_directory_keeps_its_credentials_confidence(tmp_path: Path, jobs: int) -> None:
    files = {
        "app/settings.py": PASSWORD,
        "app/other.py": "VALUE = 1\n",
        "config/settings.yaml": YAML,
        "tests/test_settings.py": PASSWORD,
        "docker/.env.example": "DB_PASSWORD=Zx81kQpLw0RtY7vB\n",
    }
    root = write(tmp_path / "tests" / "project", files)

    found = credentials(engine.analyze_project(root, [engine.BUNDLED_PLUGINS], jobs=jobs).findings)

    assert found == {
        "settings.py": (Confidence.MEDIUM, None),
        "settings.yaml": (Confidence.MEDIUM, None),
        # The project's own test code and template files keep the lower confidence.
        "test_settings.py": (Confidence.LOW, "test"),
        ".env.example": (Confidence.LOW, "example"),
    }


def report(target: Path) -> dict[str, tuple[str, str | None]]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        main(["--check", str(target), "--format", "json"])
    return {
        Path(f["location"]["path"]).name: (f["confidence"], f["metadata"].get("context"))
        for f in json.loads(out.getvalue())["findings"]
        if f["rule_id"] == "hardcoded-credential"
    }


def test_a_file_checked_alone_is_judged_from_its_directory(tmp_path: Path) -> None:
    root = write(tmp_path / "tests" / "project", {"app/settings.py": PASSWORD, "app/test_settings.py": PASSWORD})

    assert report(root / "app" / "settings.py") == {"settings.py": ("medium", None)}
    assert report(root / "app" / "test_settings.py") == {"test_settings.py": ("low", "test")}


@pytest.mark.parametrize(
    ("name", "expected"),
    [("tests/settings.py", (Confidence.LOW, "test")), ("app/settings.py", (Confidence.MEDIUM, None))],
)
def test_a_source_that_is_no_file_is_judged_on_its_name(name: str, expected: tuple[Confidence, str | None]) -> None:
    findings = engine.check(SourceManager().add_source(name, PASSWORD), [engine.BUNDLED_PLUGINS])

    assert credentials(findings) == {"settings.py": expected}
