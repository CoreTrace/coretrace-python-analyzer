"""Acceptance tests: the kind of a command injection in the SARIF log (#220).

A SARIF result carries the ``injection`` of its finding in its ``properties`` when the
rule established it, ``option`` or ``command``, and no ``injection`` when it could not.
No other metadata of a finding is exported there: some, such as evidence, may quote
what the analysed code holds.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python.cli import main

CALLS = {
    "option.py": 'subprocess.run(["ls", sys.argv[1]])',
    "command.py": 'subprocess.run(["sh", "-c", sys.argv[1]])',
    "unknown.py": 'subprocess.run(["python", "-m", sys.argv[1]])',
    "shell.py": "os.system(sys.argv[1])",
}


@pytest.fixture
def results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> dict[str, dict[str, object]]:
    root = tmp_path / "proj"
    root.mkdir()
    for name, call in CALLS.items():
        (root / name).write_text(
            f"import os\nimport subprocess\nimport sys\n\n\ndef run():\n    {call}\n",
            encoding="utf-8",
        )
    monkeypatch.chdir(tmp_path)
    main(["--check", "proj", "--format", "sarif"])
    log = json.loads(capsys.readouterr().out)
    return {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: r
        for r in log["runs"][0]["results"]
        if r["ruleId"] == "command-injection"
    }


def test_a_result_carries_the_injection_its_rule_established(
    results: dict[str, dict[str, object]],
) -> None:
    assert results["option.py"]["properties"] == {"injection": "option"}
    assert results["command.py"]["properties"] == {"injection": "command"}


def test_a_result_whose_injection_is_not_established_has_none(
    results: dict[str, dict[str, object]],
) -> None:
    assert "properties" not in results["unknown.py"]
    assert "properties" not in results["shell.py"]
