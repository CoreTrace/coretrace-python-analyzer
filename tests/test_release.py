"""Acceptance tests for a release (issue #72).

A release has one version, declared in ``pyproject.toml`` and mirrored by
``coretrace_python.__version__``, and a ``CHANGELOG.md`` whose first entry is that
version. The release workflow refuses a tag that does not match the version.

Expected to remain red until ``CHANGELOG.md`` exists and the version is 0.2.0.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

import coretrace_python

REPO = Path(__file__).resolve().parent.parent
CHANGELOG = REPO / "CHANGELOG.md"


@pytest.fixture(autouse=True)
def require_changelog() -> None:
    if not CHANGELOG.is_file():
        pytest.fail("CHANGELOG.md is not written yet")


def test_the_version_is_declared_once_and_mirrored() -> None:
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert project["version"] == coretrace_python.__version__ == "0.4.0"


def test_the_changelog_starts_with_the_current_version() -> None:
    headings = re.findall(r"^## \[?(\d+\.\d+\.\d+)\]?", CHANGELOG.read_text(encoding="utf-8"), re.MULTILINE)

    assert headings and headings[0] == coretrace_python.__version__
    assert "0.1.0" in headings
