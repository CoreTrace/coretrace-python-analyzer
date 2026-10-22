"""Acceptance tests for the review of #264: a name a module has only from its own
directory is seen only from there, up to the summaries.

``pkg/sub/os.py`` is ``os`` to a script run from ``pkg/sub`` (``sys.path[0]``), and
``pkg.sub.os`` to the rest of the project. From the project root, ``import os`` is the
library: the short name answers no import from another directory, even when no other
file has it. Up to the summaries: a module is registered for an importer only under
the names that importer resolved, or, reached through another module, under its module
name. A name the module graph leaves unresolved is registered for no file, and what a
module in between resolved from its own directory changes nothing for its importer.
Within an import cycle too, each member reads the others under the names it resolved
itself, and itself under its own names.
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


@pytest.mark.parametrize("run", RUNS)
def test_a_short_name_the_graph_leaves_unresolved_is_registered_for_no_file(tmp_path: Path, run: str) -> None:
    # pkg.a.helper is reached by its full name only: its execute, which returns a
    # constant, is not the helper.execute main.py calls.
    root = project(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/a/helper.py": 'def execute(command):\n    return "constant"\n\n\ndef noop():\n    return None\n',
            "pkg/b/helper.py": "def execute(command):\n    return command\n",
            "main.py": (
                "import os\nimport helper\nfrom pkg.a.helper import noop\n\n\n"
                "def run():\n    noop()\n    os.system(helper.execute(input()))\n"
            ),
        },
    )

    assert injections(tmp_path, root, run) == [("main.py", 8)]


@pytest.mark.parametrize("run", RUNS)
def test_a_name_a_member_leaves_unresolved_is_not_taken_from_a_module_it_imports(tmp_path: Path, run: str) -> None:
    # a/user.py resolves helper to a/helper.py, from a; main.py, at the root, cannot
    # tell a/helper.py from z/helper.py, and its helper.execute is neither.
    root = project(
        tmp_path,
        {
            "a/helper.py": 'def execute(command):\n    return "constant"\n',
            "a/user.py": 'import helper\n\n\ndef use():\n    return helper.execute("x")\n',
            "z/helper.py": "def execute(command):\n    return command\n",
            "main.py": "import os\nimport helper\nimport user\n\n\ndef run():\n    user.use()\n    os.system(helper.execute(input()))\n",
        },
    )

    assert injections(tmp_path, root, run) == [("main.py", 8)]


@pytest.mark.parametrize("run", RUNS)
def test_a_member_keeps_the_module_it_resolved_over_one_an_import_resolved(tmp_path: Path, run: str) -> None:
    # pkg/b/tool.py's helper is pkg/b/helper.py; pkg/a/run.py's is its own.
    root = project(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/a/run.py": "import helper\nfrom pkg.b import tool\n\n\ndef main():\n    tool.use()\n    helper.execute(input())\n",
            "pkg/a/helper.py": "import os\n\n\ndef execute(command):\n    os.system(command)\n",
            "pkg/b/tool.py": 'import helper\n\n\ndef use():\n    return helper.execute("x")\n',
            "pkg/b/helper.py": "def execute(command):\n    return command\n",
        },
    )

    assert injections(tmp_path, root, run) == [("pkg/a/run.py", 7)]


@pytest.mark.parametrize("run", RUNS)
def test_what_a_module_in_between_resolved_does_not_change_the_importer(tmp_path: Path, run: str) -> None:
    # loader.py, in pkg/sub, resolves os to pkg/sub/os.py; main.py's os is the library.
    root = project(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/config.py": "VALUE = 1\n",
            "pkg/sub/os.py": "from ..config import VALUE\n\n\n" + SHADOWED_OS,
            "pkg/sub/loader.py": "import os\n\n\ndef noop():\n    return None\n",
            "main.py": "import os\nfrom pkg.sub.loader import noop\n\n\ndef run():\n    noop()\n    os.system(input())\n",
        },
    )

    assert injections(tmp_path, root, run) == [("main.py", 7)]


@pytest.mark.parametrize("run", RUNS)
def test_a_module_reached_through_its_package_is_followed_by_its_module_name(tmp_path: Path, run: str) -> None:
    # pkg.helpers is reached through ``import pkg``, whose __init__.py imports it.
    root = project(
        tmp_path,
        {
            "pkg/__init__.py": "from . import helpers\n",
            "pkg/helpers.py": "import os\n\n\ndef run(command):\n    os.system(command)\n",
            "main.py": "import pkg\n\n\ndef go():\n    pkg.helpers.run(input())\n",
        },
    )

    assert injections(tmp_path, root, run) == [("main.py", 5)]


@pytest.mark.parametrize("run", RUNS)
def test_a_name_one_member_of_a_cycle_resolved_does_not_change_another(tmp_path: Path, run: str) -> None:
    # main.py and x/a.py import each other; x/a.py's helper is x/helper.py, while main.py,
    # at the root, cannot tell x/helper.py from y/helper.py.
    root = project(
        tmp_path,
        {
            "x/helper.py": 'def execute(command):\n    return "constant"\n',
            "x/a.py": 'import helper\nimport main\n\n\ndef use():\n    return helper.execute("x")\n',
            "y/helper.py": "def execute(command):\n    return command\n",
            "main.py": "import os\nimport helper\nimport a\n\n\ndef run():\n    a.use()\n    os.system(helper.execute(input()))\n",
        },
    )

    assert injections(tmp_path, root, run) == [("main.py", 8)]


@pytest.mark.parametrize("run", RUNS)
def test_a_member_of_a_cycle_is_not_read_under_a_short_name_another_did_not_resolve(tmp_path: Path, run: str) -> None:
    # main.py and pkg/sub/os.py import each other; main.py's os is the library.
    root = project(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/config.py": "VALUE = 1\n",
            "pkg/sub/os.py": "from ..config import VALUE\nimport main\n\n\ndef noop():\n    return None\n\n\n" + SHADOWED_OS,
            "main.py": "import os\nfrom pkg.sub.os import noop\n\n\ndef run():\n    noop()\n    os.system(input())\n",
        },
    )

    assert injections(tmp_path, root, run) == [("main.py", 7)]


@pytest.mark.parametrize("run", RUNS)
def test_what_a_member_of_a_cycle_resolved_does_not_change_another(tmp_path: Path, run: str) -> None:
    # main.py and pkg/sub/loader.py import each other; loader.py's os is pkg/sub/os.py,
    # main.py's the library.
    root = project(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/config.py": "VALUE = 1\n",
            "pkg/sub/os.py": "from ..config import VALUE\n\n\n" + SHADOWED_OS,
            "pkg/sub/loader.py": "import os\nimport main\n\n\ndef noop():\n    return None\n",
            "main.py": "import os\nfrom pkg.sub.loader import noop\n\n\ndef run():\n    noop()\n    os.system(input())\n",
        },
    )

    assert injections(tmp_path, root, run) == [("main.py", 7)]


@pytest.mark.parametrize("run", RUNS)
def test_a_module_that_imports_itself_by_its_short_name_reads_its_own_functions(tmp_path: Path, run: str) -> None:
    # Run from pkg/tools, helper.py's ``import helper`` is helper.py itself.
    root = project(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/tools/helper.py": (
                "import os\nimport helper\n\n\ndef execute(command):\n    os.system(command)\n\n\n"
                "def run():\n    helper.execute(input())\n"
            ),
        },
    )

    assert injections(tmp_path, root, run) == [("pkg/tools/helper.py", 10)]


@pytest.mark.parametrize("run", RUNS)
def test_each_member_of_a_cycle_reads_the_module_it_resolved(tmp_path: Path, run: str) -> None:
    # pkg/a/run.py and pkg/b/tool.py import each other, and each its own helper.
    root = project(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/a/run.py": "import helper\nfrom pkg.b import tool\n\n\ndef main():\n    tool.use()\n    helper.execute(input())\n",
            "pkg/a/helper.py": "import os\n\n\ndef execute(command):\n    os.system(command)\n",
            "pkg/b/tool.py": 'import helper\nfrom pkg.a import run\n\n\ndef use():\n    return helper.execute("x")\n',
            "pkg/b/helper.py": "def execute(command):\n    return command\n",
        },
    )

    assert injections(tmp_path, root, run) == [("pkg/a/run.py", 7)]


@pytest.mark.parametrize("run", RUNS)
def test_a_member_of_a_cycle_reached_through_its_package_is_followed_by_its_module_name(tmp_path: Path, run: str) -> None:
    # main.py, pkg/__init__.py and pkg/helpers.py import one another in turn.
    root = project(
        tmp_path,
        {
            "pkg/__init__.py": "from . import helpers\n",
            "pkg/helpers.py": "import os\nimport main\n\n\ndef run(command):\n    os.system(command)\n",
            "main.py": "import pkg\n\n\ndef go():\n    pkg.helpers.run(input())\n",
        },
    )

    assert injections(tmp_path, root, run) == [("main.py", 5)]
