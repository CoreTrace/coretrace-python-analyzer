"""Acceptance tests for issue #206: a root given as a relative path.

Findings located in a dependency file or a configuration file are reported relative to
the analysed root, like the findings of Python modules, whatever the working directory
and whether the root was given as a relative or an absolute path. A baseline recorded
with one form of the root therefore matches the findings of a check with the other.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python.cli import main
from coretrace_python.dependency import Advisory, dump_advisories
from coretrace_python.findings import Severity

LOCK = """\
version = 1

[[package]]
name = "vulnlib"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
"""
ADVISORY = Advisory("CVE-2099-0206", "vulnlib", "<1.1", "vulnlib is vulnerable", Severity.MEDIUM)
SETTINGS = '{"api_token": "Zx81kQpLw0RtY7vBn3MsD9cF2hJ6gK4a"}\n'


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A project ``proj`` under the working directory, with a vulnerable locked
    requirement and a credential in a configuration file."""

    root = tmp_path / "proj"
    root.mkdir()
    (root / "uv.lock").write_text(LOCK, encoding="utf-8")
    (root / "advisories.json").write_text(dump_advisories((ADVISORY,)), encoding="utf-8")
    (root / "settings.json").write_text(SETTINGS, encoding="utf-8")
    (root / "app.py").write_text("import vulnlib\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return root


def located(capsys: pytest.CaptureFixture[str], rule: str) -> list[str]:
    report = json.loads(capsys.readouterr().out)
    return sorted(f["location"]["path"] for f in report["findings"] if f["rule_id"] == rule)


@pytest.mark.parametrize("form", ["relative", "absolute"])
def test_dependency_findings_are_located_relative_to_the_root(
    project: Path, form: str, capsys: pytest.CaptureFixture[str]
) -> None:
    root = "proj" if form == "relative" else str(project)

    main(["--check", root, "--format", "json"])

    assert located(capsys, "vulnerable-dependency") == ["uv.lock"]


@pytest.mark.parametrize("form", ["relative", "absolute"])
def test_configuration_findings_are_located_relative_to_the_root(
    project: Path, form: str, capsys: pytest.CaptureFixture[str]
) -> None:
    root = "proj" if form == "relative" else str(project)

    main(["--check", root, "--format", "json"])

    assert located(capsys, "hardcoded-credential") == ["settings.json"]


@pytest.mark.parametrize(
    ("option", "name", "text"),
    [
        ("--policy", "bad-policy.toml", "[dependencies\n"),
        ("--advisories", "bad-advisories.json", "{\n"),
    ],
)
def test_explicit_files_are_located_relative_to_the_root(
    project: Path, option: str, name: str, text: str, capsys: pytest.CaptureFixture[str]
) -> None:
    (project / name).write_text(text, encoding="utf-8")

    main(["--check", "proj", option, f"proj/{name}", "--format", "json"])

    assert located(capsys, "syntax-error") == [name]


@pytest.mark.parametrize("form", ["relative", "absolute"])
def test_a_root_reached_through_a_symbolic_link_keeps_root_relative_paths(
    project: Path, tmp_path: Path, form: str, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "link").symlink_to(project, target_is_directory=True)
    root = "link" if form == "relative" else str(tmp_path / "link")

    main(["--check", root, "--format", "json"])

    assert located(capsys, "vulnerable-dependency") == ["uv.lock"]


def test_a_baseline_recorded_with_a_relative_root_matches_an_absolute_one(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = tmp_path / "baseline.json"
    assert main(["--check", "proj", "--baseline", str(baseline)]) == 0
    capsys.readouterr()

    assert main(["--check", str(project), "--baseline", str(baseline)]) == 0
    assert capsys.readouterr().out.startswith("no findings, 2 baselined\n")
