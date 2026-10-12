"""Acceptance tests for issue #241: a warning Python raises while parsing an analysed
source is about that source, not about the analyzer, and never reaches its stderr.

An invalid escape sequence is a ``SyntaxWarning`` from Python 3.12 on and a
``DeprecationWarning`` on 3.11. With ``-j N`` the parent and a worker both parse every
module, so an unfiltered warning was printed twice.
"""

from __future__ import annotations

import subprocess
import sys
import warnings
from pathlib import Path

import pytest

from coretrace_python.frontend.parser import parse_source

INVALID_ESCAPE = 'import re\n\nPATTERN = re.compile("\\d+")\n'


def test_parsing_raises_no_warning_about_the_analysed_source() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        tree = parse_source(INVALID_ESCAPE, "escapes.py")

    assert caught == []
    assert len(tree.body) == 2


def test_parsing_leaves_the_warning_filters_of_the_process_alone() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        parse_source(INVALID_ESCAPE, "escapes.py")
        warnings.warn("raised by the analyzer itself", SyntaxWarning, stacklevel=1)

    assert [str(warning.message) for warning in caught] == ["raised by the analyzer itself"]


@pytest.mark.parametrize("jobs", ["1", "2"])
def test_check_prints_nothing_on_stderr_about_the_analysed_sources(
    tmp_path: Path, jobs: str
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "escapes.py").write_text(INVALID_ESCAPE, encoding="utf-8")
    (root / "other.py").write_text("def run():\n    return 1\n", encoding="utf-8")

    checked = subprocess.run(
        [sys.executable, "-m", "coretrace_python", "--check", str(root), "-j", jobs],
        capture_output=True,
        text=True,
        check=False,
    )

    assert checked.stderr == ""
    assert checked.stdout == "no findings\ncoverage: 2/2 files, 2/2 functions\n"
    assert checked.returncode == 0
