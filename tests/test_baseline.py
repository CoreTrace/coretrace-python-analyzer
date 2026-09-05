"""Acceptance tests for the baseline file (issue #68).

``--baseline PATH`` records the findings of a check the first time and, on later checks,
sets apart the findings already recorded so that only new ones fail the check. A finding
is recognised by its file relative to the root, its rule, its function and the text of
its line, not by its line number, so inserting code above it does not make it new. The
text report counts baselined findings, the JSON report lists them, the SARIF log marks
every result's ``baselineState``.

Expected to remain red until ``coretrace_python.findings.baseline`` and ``--baseline`` exist.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python.cli import main
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.source import SourceId, SourceSpan

try:
    from coretrace_python.findings.baseline import Baseline, BaselineError, fingerprint
except ImportError as error:  # pragma: no cover - red until the baseline lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_baseline() -> None:
    if MISSING is not None:
        pytest.fail(f"the baseline is not implemented yet: {MISSING}")


EVAL = "import hashlib\n\ndef run(code):\n    eval(code)\n"
EVAL_AND_MD5 = "import hashlib\n\ndef run(code):\n    eval(code)\n    hashlib.md5(code)\n"
EVAL_SHIFTED = "import hashlib\n\n\ndef run(code):\n\n    eval(code)\n"


def finding(path: str, line: int, rule: str = "dangerous-eval") -> Finding:
    return Finding(rule, "m", Severity.HIGH, Confidence.HIGH, SourceSpan(SourceId(path), line, 5, line, 9), "run")


# --------------------------------------------------------------------------- fingerprints


def test_fingerprint_ignores_the_line_number_but_not_the_line_text(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(EVAL, encoding="utf-8")
    before = fingerprint(finding(str(source), 4), tmp_path)
    source.write_text(EVAL_SHIFTED, encoding="utf-8")
    after = fingerprint(finding(str(source), 6), tmp_path)
    source.write_text(EVAL.replace("eval(code)", "eval(code.strip())"), encoding="utf-8")
    changed = fingerprint(finding(str(source), 4), tmp_path)

    assert before == after == ("app.py", "dangerous-eval", "run", "eval(code)")
    assert changed != before
    assert fingerprint(finding(str(source), 4, "weak-crypto"), tmp_path) != before


def test_fingerprint_falls_back_to_the_line_number_without_the_file(tmp_path: Path) -> None:
    assert fingerprint(finding(str(tmp_path / "gone.py"), 7), tmp_path) == ("gone.py", "dangerous-eval", "run", "7")


def test_baseline_round_trips_and_partitions_with_counts(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(EVAL, encoding="utf-8")
    first, second = finding(str(source), 4), finding(str(source), 4)
    path = tmp_path / "baseline.json"

    Baseline.of((first,), tmp_path).save(path)
    loaded = Baseline.load(path)
    new, baselined = loaded.partition((first, second), tmp_path)

    assert json.loads(path.read_text(encoding="utf-8"))["schema"] == 1
    assert baselined == (first,) and new == (second,)


def test_corrupt_baseline_files_are_reported(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(BaselineError):
        Baseline.load(path)


# --------------------------------------------------------------------------- CLI


def project(root: Path, text: str) -> Path:
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / "app.py").write_text(text, encoding="utf-8")
    return root / "src"


def test_the_first_run_records_the_baseline_and_passes(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    root = project(tmp_path, EVAL)
    baseline = tmp_path / "baseline.json"

    assert main(["--check", str(root), "--baseline", str(baseline)]) == 0
    out = capsys.readouterr().out

    assert baseline.is_file()
    assert out == "no findings, 1 baselined\ncoverage: 1/1 files, 1/1 functions\n"


def test_only_new_findings_fail_later_runs(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    root = project(tmp_path, EVAL)
    baseline = tmp_path / "baseline.json"
    main(["--check", str(root), "--baseline", str(baseline)])
    capsys.readouterr()

    assert main(["--check", str(root), "--baseline", str(baseline)]) == 0
    assert capsys.readouterr().out.startswith("no findings, 1 baselined\n")

    project(tmp_path, EVAL_SHIFTED)
    assert main(["--check", str(root), "--baseline", str(baseline)]) == 0
    assert capsys.readouterr().out.startswith("no findings, 1 baselined\n")

    project(tmp_path, EVAL_AND_MD5)
    assert main(["--check", str(root), "--baseline", str(baseline)]) == 1
    out = capsys.readouterr().out
    assert out.startswith("app.py:5:5: medium weak-crypto:")
    assert "1 finding, 1 baselined\n" in out
    assert "dangerous-eval" not in out


def test_json_and_sarif_reports_carry_the_baseline_state(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    root = project(tmp_path, EVAL)
    baseline = tmp_path / "baseline.json"
    main(["--check", str(root), "--baseline", str(baseline)])
    capsys.readouterr()
    project(tmp_path, EVAL_AND_MD5)

    assert main(["--check", str(root), "--baseline", str(baseline), "--format", "json"]) == 1
    document = json.loads(capsys.readouterr().out)
    assert [f["rule_id"] for f in document["findings"]] == ["weak-crypto"]
    assert [f["rule_id"] for f in document["baselined"]] == ["dangerous-eval"]

    assert main(["--check", str(root), "--baseline", str(baseline), "--format", "sarif"]) == 1
    results = json.loads(capsys.readouterr().out)["runs"][0]["results"]
    assert {(r["ruleId"], r["baselineState"]) for r in results} == {
        ("weak-crypto", "new"),
        ("dangerous-eval", "unchanged"),
    }


def test_baseline_requires_a_check_and_a_readable_file(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    root = project(tmp_path, EVAL)
    assert main(["--emit-ir", "--baseline", str(tmp_path / "b.json"), str(root / "app.py")]) == 2
    assert "--baseline" in capsys.readouterr().err

    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not json", encoding="utf-8")
    assert main(["--check", str(root), "--baseline", str(corrupt)]) == 2
    assert "corrupt.json" in capsys.readouterr().err
