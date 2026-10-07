"""Acceptance tests for one rule of line numbering across the engine (#207, #210).

Python reads a line break as ``\\n``, ``\\r\\n`` or a lone ``\\r``, never as U+2028, U+0085,
a form feed or the other separators ``str.splitlines`` also breaks on. Every producer of
a line number (the parser, the position component, the readers of ``.env``, YAML, INI and
requirements files) and every consumer (inline suppressions, the baseline) counts lines
by that rule, ``coretrace_python.source.lines_of``; otherwise a suppression or a baseline
entry refers to another line, and a new secret can be absorbed. A requirement declared
in ``pyproject.toml`` is located at its own element, never at the first line mentioning
it nor at a default line.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cli import main
from coretrace_python.dependency import Advisory, dump_advisories
from coretrace_python.findings import Finding, Severity
from coretrace_python.source import SourceSpan, lines_of
from coretrace_python.source.positions import file_location

PLUGINS = Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"
TOKEN = "ghp_" + "a1B2" * 9
ROTATED = "ghp_" + "Z9y8" * 9


def test_lines_are_counted_as_python_counts_them() -> None:
    assert lines_of("a b\nc\r\nd\re\x0cf\x85g\n") == ["a b", "c", "d", "e\x0cf\x85g"]
    assert lines_of("") == []
    assert lines_of("last") == ["last"]


@pytest.fixture
def checked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    monkeypatch.chdir(tmp_path)
    return root


@pytest.mark.parametrize(
    ("name", "text"),
    [
        (".env", f"A=1 B=2\nGITHUB_TOKEN={TOKEN}\nC=3\n"),
        ("config.yaml", f"a: 'x y'\ntoken: {TOKEN}\nc: 3\n"),
        ("app.ini", f"[main]\x0c\ntoken = {TOKEN}\nc = 3\n"),
        ("app.py", f"# a\rb\nTOKEN = '{TOKEN}'\nC = 3\n"),
    ],
)
def test_a_rotated_secret_below_a_separator_is_a_new_finding(
    checked: Path, tmp_path: Path, name: str, text: str, capsys: pytest.CaptureFixture[str]
) -> None:
    (checked / name).write_text(text, encoding="utf-8", newline="")
    baseline = tmp_path / "baseline.json"
    main(["--check", "proj", "--baseline", str(baseline)])
    (checked / name).write_text(text.replace(TOKEN, ROTATED), encoding="utf-8", newline="")
    capsys.readouterr()

    assert main(["--check", "proj", "--baseline", str(baseline)]) == 1
    assert "hardcoded-secret" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("name", "text", "line"),
    [
        (".env", f"# note x\nGITHUB_TOKEN={TOKEN}\nC=3 # coretrace: ignore\n", 2),
        ("app.py", f"# a\rb\nTOKEN = '{TOKEN}'\nC = 3  # coretrace: ignore\n", 3),
    ],
)
def test_a_suppression_on_the_next_line_does_not_apply(
    checked: Path, name: str, text: str, line: int
) -> None:
    (checked / name).write_text(text, encoding="utf-8", newline="")
    if name != "app.py":
        (checked / "app.py").write_text("x = 1\n", encoding="utf-8")

    (finding,) = [
        f
        for f in engine.analyze_project(checked, [PLUGINS]).findings
        if f.rule_id == "hardcoded-secret"
    ]

    assert isinstance(finding.span, SourceSpan) and finding.span.start_line == line


ADVISORY = Advisory("CVE-2099-0208", "requests", "<2.1", "requests is vulnerable", Severity.MEDIUM)


def declared(root: Path, name: str, text: str) -> Finding:
    (root / name).write_text(text, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories((ADVISORY,)), encoding="utf-8")
    (root / "app.py").write_text("import requests\n", encoding="utf-8")
    (finding,) = [
        f
        for f in engine.analyze_project(root, [PLUGINS]).findings
        if f.rule_id == "vulnerable-dependency" and f.metadata["advisory"] == ADVISORY.id
    ]
    return finding


def test_a_requirements_file_counts_lines_as_python(tmp_path: Path) -> None:
    finding = declared(tmp_path, "requirements.txt", "# deps\x0c\nflask==1.0\nrequests==2.0.0\n")

    assert isinstance(finding.span, SourceSpan) and finding.span.start_line == 3


def test_a_pyproject_requirement_is_located_at_its_own_element(tmp_path: Path) -> None:
    text = (
        '# pin requests==2.0.0 later\n[project]\nname = "app"\n'
        'dependencies = [\n    "requests-toolbelt",\n    "requests==2.0.0",  # pinned\n    "django>=1.0",\n]\n'
    )
    finding = declared(tmp_path, "pyproject.toml", text)

    assert isinstance(finding.span, SourceSpan)
    assert (finding.span.start_line, finding.span.start_column) == (6, 5)


def test_a_poetry_requirement_is_located_at_its_key(tmp_path: Path) -> None:
    text = '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = { version = "<2.1" }\n'
    finding = declared(tmp_path, "pyproject.toml", text)

    assert isinstance(finding.span, SourceSpan)
    assert (finding.span.start_line, finding.span.start_column) == (3, 12)


def test_a_pyproject_requirement_that_cannot_be_placed_has_a_file_location(tmp_path: Path) -> None:
    text = 'project.name = "app"\nproject.dependencies = ["requests==2.0.0"]\n'
    finding = declared(tmp_path, "pyproject.toml", text)

    assert finding.span == file_location(
        finding.span.source_id, ("project", "dependencies", 0), "requests==2.0.0"
    )
