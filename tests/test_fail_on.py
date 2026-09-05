"""Acceptance tests for the severity threshold (issue #68).

``--fail-on SEVERITY`` makes the exit status 1 only when a finding of that severity or
above was reported; every finding is still printed. Without it, any finding fails the
check as before. Suppressed and baselined findings never count.

Expected to remain red until ``Severity`` is ordered and ``--fail-on`` exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python.cli import main
from coretrace_python.findings import Severity

MISSING = None if hasattr(Severity, "rank") else "Severity has no rank"


@pytest.fixture(autouse=True)
def require_threshold() -> None:
    if MISSING is not None:
        pytest.fail(f"the severity threshold is not implemented yet: {MISSING}")


HIGH_AND_MEDIUM = "import hashlib\n\ndef run(code):\n    eval(code)\n    hashlib.md5(code)\n"


def write(tmp_path: Path, text: str) -> Path:
    source = tmp_path / "app.py"
    source.write_text(text, encoding="utf-8")
    return source


def test_severities_are_ordered() -> None:
    ranks = [s.rank for s in (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]

    assert ranks == sorted(ranks) and len(set(ranks)) == 5


def test_findings_below_the_threshold_are_reported_but_do_not_fail(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = write(tmp_path, HIGH_AND_MEDIUM)

    assert main(["--check", str(source), "--fail-on", "critical"]) == 0
    out = capsys.readouterr().out
    assert "dangerous-eval" in out and "weak-crypto" in out and "2 findings\n" in out

    assert main(["--check", str(source), "--fail-on", "high"]) == 1
    assert main(["--check", str(source), "--fail-on", "medium"]) == 1
    assert main(["--check", str(source)]) == 1


def test_a_clean_file_passes_whatever_the_threshold(tmp_path: Path) -> None:
    source = write(tmp_path, "def ok():\n    return 1\n")

    assert main(["--check", str(source), "--fail-on", "info"]) == 0


def test_suppressed_and_baselined_findings_never_count(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = write(tmp_path, "def run(code):\n    eval(code)  # coretrace: ignore\n")
    assert main(["--check", str(source), "--fail-on", "low"]) == 0

    source = write(tmp_path, HIGH_AND_MEDIUM)
    baseline = tmp_path / "baseline.json"
    main(["--check", str(source), "--baseline", str(baseline)])
    assert main(["--check", str(source), "--baseline", str(baseline), "--fail-on", "low"]) == 0


def test_fail_on_requires_a_check_and_a_known_severity(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = write(tmp_path, "def ok():\n    return 1\n")

    assert main(["--emit-ir", "--fail-on", "high", str(source)]) == 2
    assert "--fail-on" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        main(["--check", str(source), "--fail-on", "severe"])
