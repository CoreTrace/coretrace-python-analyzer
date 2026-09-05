"""Acceptance tests for inline suppressions (issue #68).

A finding whose line carries a ``# coretrace: ignore`` comment is suppressed; with a
bracketed list, ``# coretrace: ignore[dangerous-eval, weak-crypto]``, only those rules
are. The comment works in Python sources and in the text files the project checks read
(requirements files). Suppressed findings are kept apart: the text report counts them,
the JSON report lists them, the SARIF log marks them as suppressed in source, and they
do not affect the exit status.

Expected to remain red until ``coretrace_python.findings.suppressions`` exists.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cli import main
from coretrace_python.source import SourceManager

try:
    from coretrace_python.findings.suppressions import partition, suppressions_in
except ImportError as error:  # pragma: no cover - red until suppressions land
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_suppressions() -> None:
    if MISSING is not None:
        pytest.fail(f"inline suppressions are not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"

EVAL = "def run(code):\n    eval(code){comment}\n"


def check(text: str) -> engine.FileAnalysis:
    return engine.analyze_file(SourceManager().add_source("app.py", text), [PLUGINS])


def project(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        (root / relative).write_text(text, encoding="utf-8")
    return root


# --------------------------------------------------------------------------- parsing


def test_suppressions_are_read_from_comments_only() -> None:
    text = (
        "x = 1  # coretrace: ignore\n"
        "y = 2  # coretrace: ignore[dangerous-eval, weak-crypto]\n"
        "z = '# coretrace: ignore'\n"
        "w = 3  # coretrace:ignore[ssrf]\n"
        "v = 4  # unrelated\n"
    )

    found = suppressions_in(text)

    assert found == {1: None, 2: frozenset({"dangerous-eval", "weak-crypto"}), 4: frozenset({"ssrf"})}


def test_suppressions_in_text_that_is_not_python_use_the_comment_syntax() -> None:
    assert suppressions_in("pyyaml==5.3.1  # coretrace: ignore[vulnerable-dependency]\nflask\n") == {
        1: frozenset({"vulnerable-dependency"})
    }


def test_partition_separates_suppressed_findings() -> None:
    analysis = check(EVAL.format(comment=""))
    (finding,) = analysis.findings

    kept, suppressed = partition((finding,), lambda source_id: EVAL.format(comment="  # coretrace: ignore"))

    assert kept == () and suppressed == (finding,)
    assert partition((finding,), lambda source_id: None) == ((finding,), ())


# --------------------------------------------------------------------------- engine


def test_a_bare_ignore_suppresses_every_finding_on_its_line() -> None:
    analysis = check(EVAL.format(comment="  # coretrace: ignore"))

    assert analysis.findings == ()
    assert [f.rule_id for f in analysis.suppressed] == ["dangerous-eval"]
    assert analysis.coverage.functions_analysed == 1


def test_a_scoped_ignore_suppresses_only_the_listed_rules() -> None:
    assert check(EVAL.format(comment="  # coretrace: ignore[dangerous-eval]")).findings == ()
    other = check(EVAL.format(comment="  # coretrace: ignore[weak-crypto]"))
    assert [f.rule_id for f in other.findings] == ["dangerous-eval"]
    assert other.suppressed == ()


def test_project_checks_honour_suppressions_in_requirements_files(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "requirements.txt": "pyyaml==5.3.1  # coretrace: ignore[vulnerable-dependency]\n",
            "app.py": "import yaml\n\ndef load(text):\n    return yaml.load(text)\n",
        },
    )

    analysis = engine.analyze_project(root, [PLUGINS])

    assert [f.rule_id for f in analysis.findings] == ["reachable-vulnerability"]
    assert [f.rule_id for f in analysis.suppressed] == ["vulnerable-dependency"]


def test_cached_modules_stay_suppressed(tmp_path: Path) -> None:
    from coretrace_python.cache import ProjectCache

    root = project(tmp_path, {"app.py": EVAL.format(comment="  # coretrace: ignore")})
    cache = ProjectCache(tmp_path / "cache")
    engine.analyze_project(root, [PLUGINS], cache=cache)

    second = engine.analyze_project(root, [PLUGINS], cache=cache)

    assert second.reused == ("app",)
    assert second.findings == () and len(second.suppressed) == 1


# --------------------------------------------------------------------------- reports and CLI


def test_text_report_counts_suppressions_and_exit_status_ignores_them(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = tmp_path / "app.py"
    source.write_text(EVAL.format(comment="  # coretrace: ignore"), encoding="utf-8")

    assert main(["--check", str(source)]) == 0
    assert capsys.readouterr().out == "no findings, 1 suppressed\ncoverage: 1/1 files, 1/1 functions\n"


def test_json_report_lists_suppressed_findings(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = tmp_path / "app.py"
    source.write_text(
        "import hashlib\n\ndef run(code):\n    eval(code)  # coretrace: ignore\n    hashlib.md5(code)\n",
        encoding="utf-8",
    )

    assert main(["--check", str(source), "--format", "json"]) == 1
    document = json.loads(capsys.readouterr().out)

    assert [f["rule_id"] for f in document["findings"]] == ["weak-crypto"]
    assert [f["rule_id"] for f in document["suppressed"]] == ["dangerous-eval"]
    assert document["suppressed"][0]["location"]["path"] == "app.py"


def test_sarif_marks_suppressed_results_as_suppressed_in_source(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = tmp_path / "app.py"
    source.write_text(EVAL.format(comment="  # coretrace: ignore"), encoding="utf-8")

    assert main(["--check", str(source), "--format", "sarif"]) == 0
    (result,) = json.loads(capsys.readouterr().out)["runs"][0]["results"]

    assert result["ruleId"] == "dangerous-eval"
    assert result["suppressions"] == [{"kind": "inSource"}]
