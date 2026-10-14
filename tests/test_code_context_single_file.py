"""Review of #244 (PR #251): a file checked alone carries the same context as in its
directory.

The context is judged on the file's path from the root of the report. For a directory,
that root is the directory; for a file checked alone, it is the file's own directory, as
the command line already reports it, so a test module named ``test_*.py`` is test code
either way. A source that is not a file is judged on its name as given.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cli import main
from coretrace_python.source import SourceManager

EVAL = "def total(code):\n    return eval(code)\n"


def contexts(target: Path) -> list[str | None]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        main(["--check", str(target), "--format", "json"])
    return [f["metadata"].get("context") for f in json.loads(out.getvalue())["findings"] if f["rule_id"] == "dangerous-eval"]


@pytest.mark.parametrize(("name", "context"), [("test_checks.py", "test"), ("checks.py", None)])
def test_a_file_checked_alone_carries_the_context_of_its_directory_run(
    tmp_path: Path, name: str, context: str | None
) -> None:
    (tmp_path / name).write_text(EVAL, encoding="utf-8")

    assert contexts(tmp_path / name) == contexts(tmp_path) == [context]


def test_the_api_judges_a_file_from_the_root_it_is_given(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "helpers.py").write_text(EVAL, encoding="utf-8")
    source = SourceManager().load_file(tmp_path / "tests" / "helpers.py")

    from_its_directory = engine.analyze_file(source, [engine.BUNDLED_PLUGINS]).findings
    from_the_project = engine.analyze_file(source, [engine.BUNDLED_PLUGINS], root=tmp_path).findings

    assert [f.metadata.get("context") for f in from_its_directory if f.rule_id == "dangerous-eval"] == [None]
    assert [f.metadata.get("context") for f in from_the_project if f.rule_id == "dangerous-eval"] == ["test"]


@pytest.mark.parametrize(("name", "context"), [("tests/helpers.py", "test"), ("app/helpers.py", None)])
def test_a_source_that_is_no_file_is_judged_on_its_name(name: str, context: str | None) -> None:
    findings = engine.check(SourceManager().add_source(name, EVAL), [engine.BUNDLED_PLUGINS])

    assert [f.metadata.get("context") for f in findings if f.rule_id == "dangerous-eval"] == [context]
