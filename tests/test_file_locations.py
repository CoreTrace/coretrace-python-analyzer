"""Acceptance tests for issue #210: findings in structured files, located or not.

A value found in a JSON or TOML file is reported at its own line, from its structural
path. A value whose line cannot be established gets a file location: the file and the
JSON pointer of the value, never a guessed line. Reports show it without a line (JSON
``null``, SARIF without ``region``, text ``path: …``); an inline suppression, which
names a line, does not apply to it; the baseline recognises it by its pointer, in a
schema 2 file (schema 1 files: ``test_baseline_schema_1.py``).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cli import main
from coretrace_python.findings import Finding
from coretrace_python.source import FileLocation, SourceSpan

PLUGINS = Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"
TOKEN = "Zx81kQpLw0RtY7vBn3MsD9cF2hJ6gK4a"
OTHER = "Pq72mWnE5rTy8uIo1aSdF3gH6jK9lZxC"


def project(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).write_text(text, encoding="utf-8")
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    return root


def credentials(root: Path) -> list[Finding]:
    return [
        f
        for f in engine.analyze_project(root, [PLUGINS]).findings
        if f.rule_id == "hardcoded-credential"
    ]


def test_values_of_one_key_are_located_at_their_own_lines(tmp_path: Path) -> None:
    text = (
        f'{{\n  "first": {{"api_token": "{TOKEN}"}},\n  "second": {{"api_token": "{OTHER}"}}\n}}\n'
    )
    findings = credentials(project(tmp_path, {"settings.json": text}))

    assert sorted(
        (f.span.start_line, f.span.start_column) for f in findings if isinstance(f.span, SourceSpan)
    ) == [
        (2, 26),
        (3, 27),
    ]


def test_a_value_that_cannot_be_located_gets_a_file_location(tmp_path: Path) -> None:
    (finding,) = credentials(project(tmp_path, {"settings.toml": f'a.api_token = "{TOKEN}"\n'}))

    assert finding.span == FileLocation(finding.span.source_id, "/a/api_token")
    assert Path(str(finding.span.source_id)).name == "settings.toml"


@pytest.fixture
def unlocated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A project with one credential that cannot be located (a dotted TOML key, with an
    inline suppression on its line) and one that can, suppressed on its line."""

    root = tmp_path / "proj"
    root.mkdir()
    project(
        root,
        {
            "settings.toml": (
                f'a.api_token = "{TOKEN}"  # coretrace: ignore\n'
                f'[db]\npassword = "{OTHER}"  # coretrace: ignore\n'
            )
        },
    )
    monkeypatch.chdir(tmp_path)
    return root


def test_reports_show_a_file_location_without_a_line(
    unlocated: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["--check", "proj", "--format", "json"])
    (record,) = [
        f
        for f in json.loads(capsys.readouterr().out)["findings"]
        if f["rule_id"] == "hardcoded-credential"
    ]
    assert record["location"] == {
        "path": "settings.toml",
        "line": None,
        "column": None,
        "end_line": None,
        "end_column": None,
        "pointer": "/a/api_token",
    }

    main(["--check", "proj", "--format", "sarif"])
    results = json.loads(capsys.readouterr().out)["runs"][0]["results"]
    (result,) = [
        r for r in results if r["ruleId"] == "hardcoded-credential" and "suppressions" not in r
    ]
    (location,) = result["locations"]
    assert "region" not in location["physicalLocation"]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "settings.toml"
    assert location["properties"] == {"pointer": "/a/api_token"}

    main(["--check", "proj"])
    lines = capsys.readouterr().out.splitlines()
    assert (
        "settings.toml: high hardcoded-credential: Hardcoded credential in api_token: Zx81… (32 characters)"
        in lines
    )


def test_an_inline_suppression_applies_to_verified_lines_only(unlocated: Path) -> None:
    analysis = engine.analyze_project(unlocated, [PLUGINS])

    assert [type(f.span) for f in analysis.findings if f.rule_id == "hardcoded-credential"] == [
        FileLocation
    ]
    assert [f.metadata["name"] for f in analysis.suppressed] == ["password"]


def test_the_baseline_recognises_a_file_location_by_its_pointer(
    unlocated: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = tmp_path / "baseline.json"
    assert main(["--check", "proj", "--baseline", str(baseline)]) == 0
    document = json.loads(baseline.read_text(encoding="utf-8"))
    capsys.readouterr()

    assert document["schema"] == 2
    assert {
        "path": "settings.toml",
        "rule": "hardcoded-credential",
        "function": "",
        "pointer": "/a/api_token",
    }.items() <= next(
        e for e in document["findings"] if e["rule"] == "hardcoded-credential"
    ).items()
    assert main(["--check", "proj", "--baseline", str(baseline)]) == 0
    assert capsys.readouterr().out.startswith("no findings, 1 suppressed, 1 baselined\n")
