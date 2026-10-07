"""Acceptance tests for issue #233: syntax nested deeper than the analyzer follows.

The frontend and the analyses after it recurse once per level of nesting. Python parses
left-nested chains of any length (``"a" + "b" + …``, ``a.b.b…``, ``x.strip().strip()…``),
so the frontend rejects, before building PyHIR, a file whose syntax is nested deeper than
``MAX_NESTING`` levels, as it rejects one it cannot represent: a ``syntax-error`` note
for that file, and the rest of the project analysed. Syntax within the bound is analysed
as before.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python.cli import main
from coretrace_python.frontend import HIRBuildError, build_hir
from coretrace_python.frontend.ast_adapter import MAX_NESTING
from coretrace_python.source import SourceManager


def chain(terms: int) -> str:
    return "X = " + " + ".join(['"ab"'] * terms) + "\n"


@pytest.mark.parametrize(
    "text",
    [
        chain(3000),
        "X = a" + ".b" * 3000 + "\n",
        "import sys\nX = sys.argv[1]" + ".strip()" * 600 + "\n",
    ],
)
def test_a_file_nested_too_deep_is_rejected_and_the_project_is_analysed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], text: str
) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    (root / "deep.py").write_text(text, encoding="utf-8")
    (root / "run.py").write_text("eval(input())\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert main(["--check", "proj", "--format", "json"]) == 1
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert "Traceback" not in captured.err
    assert {(f["location"]["path"], f["rule_id"]) for f in report["findings"]} >= {
        ("deep.py", "syntax-error"),
        ("run.py", "dangerous-eval"),
    }
    (note,) = [f for f in report["findings"] if f["rule_id"] == "syntax-error"]
    assert f"nested more than {MAX_NESTING} levels" in note["message"]


def test_the_rejection_names_where_the_nesting_goes_too_deep() -> None:
    with pytest.raises(HIRBuildError, match=rf"^a\.py:1:\d+: .*nested more than {MAX_NESTING}"):
        build_hir(SourceManager().add_source("a.py", chain(3000)))


def test_syntax_within_the_bound_is_analysed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    terms = MAX_NESTING - 10
    (root / "run.py").write_text(
        "import os\nimport sys\n\nX = sys.argv[1]" + ' + "ab"' * terms + "\nos.system(X)\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    assert main(["--check", "proj", "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)

    assert [f["rule_id"] for f in report["findings"]] == ["command-injection"]
