"""Acceptance tests for the review of #264: a name a module has only from its own
directory is seen only from there, up to the summaries.

``pkg/sub/os.py`` is ``os`` to a script run from ``pkg/sub`` (``sys.path[0]``), and
``pkg.sub.os`` to the rest of the project. From the project root, ``import os`` is the
library: the short name answers no import from another directory, even when no other
file has it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cache import ProjectCache

PLUGINS = [engine.BUNDLED_PLUGINS]


def project(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "project"
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def injections(tmp_path: Path, root: Path, run: str) -> list[tuple[str, int]]:
    options: dict[str, object] = {
        "plain": {},
        "cold-cache": {"cache": ProjectCache(tmp_path / "cache")},
        "warm-cache": {"cache": ProjectCache(tmp_path / "cache")},
        "processes": {"jobs": 2},
    }[run]
    if run == "warm-cache":
        engine.analyze_project(root, PLUGINS, **options)  # type: ignore[arg-type]
    analysis = engine.analyze_project(root, PLUGINS, **options)  # type: ignore[arg-type]
    return sorted(
        (Path(str(f.span.source_id)).relative_to(root.resolve()).as_posix(), f.span.start_line)
        for f in analysis.findings
        if f.rule_id == "command-injection"
    )


RUNS = ["plain", "cold-cache", "warm-cache", "processes"]
SHADOWED_OS = "def system(command):\n    return None\n"


@pytest.mark.parametrize("run", RUNS)
@pytest.mark.parametrize("relative", [True, False], ids=["with-a-relative-import", "without"])
def test_a_short_name_from_another_directory_leaves_the_library(tmp_path: Path, run: str, relative: bool) -> None:
    root = project(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/config.py": "VALUE = 1\n",
            "pkg/sub/os.py": ("from ..config import VALUE\n\n\n" if relative else "") + SHADOWED_OS,
            "main.py": "import os\n\n\ndef run():\n    os.system(input())\n",
        },
    )

    assert injections(tmp_path, root, run) == [("main.py", 5)]
