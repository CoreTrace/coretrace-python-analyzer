"""Acceptance tests for report paths relative to the checked root (issue #68).

A report knows the root it was produced for: the directory checked, or the directory of
the file checked. Every reporter renders paths under that root relative to it, POSIX
style, and leaves other paths as they are. The SARIF log names the root once as the
``SRCROOT`` original URI base, so code scanning services attach results to files. The JSON
document carries the root so consumers can rebuild absolute paths.

Expected to remain red until ``Report`` has a ``root`` and the CLI passes it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python.cli import main
from coretrace_python.findings import Confidence, Coverage, FileCoverage, Finding, Severity
from coretrace_python.reporters import Report, render_json, render_sarif, render_text
from coretrace_python.source import SourceId, SourceSpan

MISSING = None if "root" in Report.__dataclass_fields__ else "Report has no root"


@pytest.fixture(autouse=True)
def require_root() -> None:
    if MISSING is not None:
        pytest.fail(f"relative report paths are not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"
ROOT = Path("/work/project")


def finding(path: str, line: int = 3) -> Finding:
    return Finding(
        "dangerous-eval", "m", Severity.HIGH, Confidence.HIGH, SourceSpan(SourceId(path), line, 5, line, 9), "run"
    )


def report(*findings: Finding, root: Path | None = ROOT) -> Report:
    coverage = Coverage(tuple(FileCoverage(str(f.span.source_id), "analysed", 1, 1) for f in findings))
    return Report(findings, "coretrace-python-analyzer", "0.1.0", coverage, root)


# --------------------------------------------------------------------------- reporters


def test_text_paths_are_relative_to_the_root() -> None:
    text = render_text(report(finding("/work/project/app/views.py"), finding("/elsewhere/x.py")))

    assert text.startswith("/elsewhere/x.py:3:5: high dangerous-eval: m [run]\napp/views.py:3:5:")


def test_json_paths_are_relative_and_the_root_is_recorded() -> None:
    document = json.loads(render_json(report(finding("/work/project/app/views.py"))))

    assert document["root"] == "/work/project"
    assert document["findings"][0]["location"]["path"] == "app/views.py"
    assert document["coverage"]["details"][0]["path"] == "app/views.py"


def test_json_without_a_root_keeps_paths_and_omits_the_root() -> None:
    document = json.loads(render_json(report(finding("/work/project/app/views.py"), root=None)))

    assert "root" not in document
    assert document["findings"][0]["location"]["path"] == "/work/project/app/views.py"


def test_sarif_locations_use_the_srcroot_uri_base() -> None:
    document = json.loads(render_sarif(report(finding("/work/project/app/views.py"))))
    run = document["runs"][0]

    assert run["originalUriBaseIds"] == {"SRCROOT": {"uri": "file:///work/project/"}}
    location = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert location == {"uri": "app/views.py", "uriBaseId": "SRCROOT"}


def test_sarif_paths_outside_the_root_stay_absolute_without_a_base() -> None:
    document = json.loads(render_sarif(report(finding("/elsewhere/x.py"))))
    location = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]

    assert location == {"uri": "/elsewhere/x.py"}


def test_sarif_without_a_root_has_no_uri_bases() -> None:
    document = json.loads(render_sarif(report(finding("app/views.py"), root=None)))

    assert "originalUriBaseIds" not in document["runs"][0]


# --------------------------------------------------------------------------- CLI


def test_directory_checks_report_paths_relative_to_the_directory(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "app.py").write_text("def run(code):\n    eval(code)\n", encoding="utf-8")

    assert main(["--check", str(tmp_path), "--format", "json"]) == 1
    document = json.loads(capsys.readouterr().out)

    assert document["root"] == str(tmp_path.resolve())
    assert document["findings"][0]["location"]["path"] == "pkg/app.py"
    assert document["coverage"]["details"][0]["path"] == "pkg/app.py"

    assert main(["--check", str(tmp_path)]) == 1
    assert capsys.readouterr().out.startswith("pkg/app.py:2:5: high dangerous-eval")


def test_file_checks_report_paths_relative_to_the_file_directory(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = tmp_path / "app.py"
    source.write_text("def run(code):\n    eval(code)\n", encoding="utf-8")

    assert main(["--check", str(source), "--format", "sarif"]) == 1
    document = json.loads(capsys.readouterr().out)
    run = document["runs"][0]

    assert run["originalUriBaseIds"]["SRCROOT"]["uri"] == tmp_path.resolve().as_uri() + "/"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] == {
        "uri": "app.py",
        "uriBaseId": "SRCROOT",
    }
