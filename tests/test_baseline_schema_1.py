"""Acceptance tests for the transition from schema 1 baselines (issues #207, #210).

Schema 1 files are still read, and their entries match exactly as they did: by file,
rule, function and the text of the line. Before #210, a finding in a JSON, TOML or lock
file was recorded with the text of its key's first line, which was its own line only
when the key was not repeated. Such an entry still identifies that finding with
certainty; any other finding, a new secret included, is new: an old entry never
accounts for a finding it cannot identify. When a schema 1 baseline leaves findings of
such files new, the check says so and asks for the baseline to be recorded again.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python.cli import main

TOKEN = "Zx81kQpLw0RtY7vBn3MsD9cF2hJ6gK4a"
OTHER = "Pq72mWnE5rTy8uIo1aSdF3gH6jK9lZxC"
NOTICE = "schema 1 baseline"


def legacy(path: Path, *entries: tuple[str, str, str, str, int]) -> Path:
    findings = [
        {"path": file, "rule": rule, "function": function, "line": line, "count": count}
        for file, rule, function, line, count in entries
    ]
    path.write_text(json.dumps({"schema": 1, "findings": findings}), encoding="utf-8")
    return path


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "app.py").write_text("def run(code):\n    eval(code)\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return root


def test_a_new_secret_is_never_accounted_for_by_an_old_entry(
    root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (root / "settings.json").write_text(
        f'{{\n  "db": {{"password": "{OTHER}"}}\n}}\n', encoding="utf-8"
    )
    baseline = legacy(
        tmp_path / "baseline.json",
        ("settings.json", "hardcoded-credential", "", f'"db": {{"api_token": "{TOKEN}"}}', 1),
        ("app.py", "dangerous-eval", "run", "eval(code)", 1),
    )

    assert main(["--check", "proj", "--baseline", str(baseline), "--format", "json"]) == 1
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert [f["metadata"]["name"] for f in report["findings"]] == ["password"]
    assert [f["rule_id"] for f in report["baselined"]] == ["dangerous-eval"]
    assert NOTICE in captured.err


def test_a_repeated_key_is_recognised_only_where_its_old_entry_was_certain(
    root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = (
        f'{{\n  "first": {{"api_token": "{TOKEN}"}},\n  "second": {{"api_token": "{OTHER}"}}\n}}\n'
    )
    (root / "settings.json").write_text(text, encoding="utf-8")
    baseline = legacy(
        tmp_path / "baseline.json",
        ("settings.json", "hardcoded-credential", "", f'"first": {{"api_token": "{TOKEN}"}},', 2),
        ("app.py", "dangerous-eval", "run", "eval(code)", 1),
    )

    assert main(["--check", "proj", "--baseline", str(baseline), "--format", "json"]) == 1
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert [f["location"]["line"] for f in report["findings"]] == [3]
    assert [
        f["location"]["line"] for f in report["baselined"] if f["rule_id"] != "dangerous-eval"
    ] == [2]
    assert NOTICE in captured.err


def test_a_schema_1_baseline_of_python_findings_matches_as_before(
    root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = legacy(
        tmp_path / "baseline.json", ("app.py", "dangerous-eval", "run", "eval(code)", 1)
    )

    assert main(["--check", "proj", "--baseline", str(baseline)]) == 0
    captured = capsys.readouterr()

    assert captured.out.startswith("no findings, 1 baselined\n")
    assert NOTICE in captured.err
