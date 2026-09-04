"""Non-regression suite on real repositories.

Every repository listed in ``tests/regression/repositories.toml`` is checked out at its
pinned commit, analysed with the bundled plugins and compared with the snapshot recorded
in ``tests/regression/expected/<name>.json``: the findings (file, line, rule, function)
and the coverage. A change in either is a regression, or an intended change to record
with ``CORETRACE_REGRESSION_UPDATE=1``. Checkouts are kept under
``CORETRACE_REGRESSION_ROOT`` (default ``.regression/`` at the repository root).

The repository tests carry the ``regression`` marker, deselected by default and run by
the dedicated CI job with ``pytest -m regression``.

Expected to remain red until the manifest, the snapshots and the ``regression`` marker exist.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path

import pytest

from coretrace_python import engine

REPO = Path(__file__).resolve().parent.parent
REGRESSION = REPO / "tests" / "regression"
MANIFEST = REGRESSION / "repositories.toml"
EXPECTED = REGRESSION / "expected"


@dataclass(frozen=True)
class Repository:
    name: str
    url: str | None = None
    commit: str | None = None
    path: str | None = None


def repositories() -> tuple[Repository, ...]:
    if not MANIFEST.is_file():
        return ()
    manifest = tomllib.loads(MANIFEST.read_text(encoding="utf-8"))
    return tuple(Repository(**entry) for entry in manifest["repository"])


REPOSITORIES = repositories()


def checkout(repository: Repository) -> Path:
    """The repository at its pinned commit, cloned on first use."""

    if repository.path is not None:
        return REGRESSION / repository.path
    assert repository.url is not None and repository.commit is not None
    root = Path(os.environ.get("CORETRACE_REGRESSION_ROOT", REPO / ".regression"))
    target = root / repository.name
    marker = target / ".coretrace-commit"
    if marker.is_file() and marker.read_text(encoding="utf-8").strip() == repository.commit:
        return target
    shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)
    for command in (
        ["git", "init", "-q"],
        ["git", "fetch", "-q", "--depth", "1", repository.url, repository.commit],
        ["git", "checkout", "-q", "FETCH_HEAD"],
    ):
        subprocess.run(command, cwd=target, check=True)
    marker.write_text(repository.commit + "\n", encoding="utf-8")
    return target


def snapshot(path: Path) -> dict[str, object]:
    analysis = engine.analyze_project(path, [engine.BUNDLED_PLUGINS])
    findings = sorted(
        (
            {
                "file": Path(str(f.span.source_id)).resolve().relative_to(path.resolve()).as_posix(),
                "line": f.span.start_line,
                "rule": f.rule_id,
                "function": f.function,
            }
            for f in analysis.findings
        ),
        key=lambda f: (f["file"], f["line"], f["rule"], f["function"] or ""),
    )
    return {
        "coverage": {
            "files": analysis.coverage.files,
            "files_analysed": analysis.coverage.files_analysed,
            "functions": analysis.coverage.functions,
            "functions_analysed": analysis.coverage.functions_analysed,
        },
        "findings": findings,
    }


def test_every_repository_has_a_snapshot_and_vice_versa() -> None:
    assert MANIFEST.is_file(), f"{MANIFEST} is missing"
    names = {repository.name for repository in REPOSITORIES}
    assert names == {path.stem for path in EXPECTED.glob("*.json")}
    assert len(names) >= 16
    assert all(
        (r.path is None) != (r.url is None and r.commit is None) for r in REPOSITORIES
    )
    assert all(len(r.commit) == 40 for r in REPOSITORIES if r.commit is not None)


@pytest.mark.regression
@pytest.mark.parametrize("repository", REPOSITORIES, ids=lambda r: r.name)
def test_repository_analysis_matches_its_snapshot(repository: Repository) -> None:
    observed = snapshot(checkout(repository))
    expected_path = EXPECTED / f"{repository.name}.json"
    if os.environ.get("CORETRACE_REGRESSION_UPDATE"):
        expected_path.write_text(json.dumps(observed, indent=2) + "\n", encoding="utf-8")
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    assert observed["coverage"] == expected["coverage"]
    assert observed["findings"] == expected["findings"]
