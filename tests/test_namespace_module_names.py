"""Acceptance tests for issue #264: the name of a module follows the packages it is in.

Python imports a directory without ``__init__.py`` inside a regular package as a portion
of that package (PEP 420): ``pkg/sub/app.py`` is ``pkg.sub.app`` once the directory above
``pkg`` is on the import path, and so is ``pkg/a/b/deep.py`` through two such directories.
A project's module is named that way: from the parent of the outermost directory holding
an ``__init__.py``, searched up through directories without one as far as the project
root. A module in no package is named from its own directory, as before, and a package
climbs above the root only while each directory holds an ``__init__.py``.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from coretrace_python import engine

TIMEOUT = 60


def project(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "project"
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def module_names(root: Path) -> dict[str, str]:
    """Each analysed file of the project, by its path from the root, with its module name."""

    graph = engine.analyze_project(root, [engine.BUNDLED_PLUGINS]).graph
    return {
        Path(str(graph.source(name).source_id)).relative_to(root.resolve()).as_posix(): name
        for name in graph.modules
    }


def test_a_module_in_packages_is_named_after_them(tmp_path: Path) -> None:
    root = project(tmp_path, {"pkg/__init__.py": "", "pkg/sub/__init__.py": "", "pkg/sub/mod.py": ""})

    assert module_names(root) == {"pkg/__init__.py": "pkg", "pkg/sub/__init__.py": "pkg.sub", "pkg/sub/mod.py": "pkg.sub.mod"}


def test_a_module_in_no_package_is_named_from_its_own_directory(tmp_path: Path) -> None:
    root = project(tmp_path, {"scripts/tool.py": "", "setup.py": ""})

    assert module_names(root) == {"scripts/tool.py": "tool", "setup.py": "setup"}


def test_no_directory_above_the_project_root_names_a_module(tmp_path: Path) -> None:
    # Outside the project, an __init__.py names nothing in it: ``app`` stays ``app``.
    (tmp_path / "__init__.py").write_text("", encoding="utf-8")
    root = project(tmp_path, {"tools/app.py": ""})

    assert module_names(root) == {"tools/app.py": "app"}


def test_a_directory_without_init_inside_a_package_is_a_portion_of_it(tmp_path: Path) -> None:
    root = project(tmp_path, {"pkg/__init__.py": "", "pkg/sub/app.py": "", "pkg/a/b/deep.py": ""})

    assert module_names(root) == {"pkg/__init__.py": "pkg", "pkg/sub/app.py": "pkg.sub.app", "pkg/a/b/deep.py": "pkg.a.b.deep"}


def test_python_imports_every_module_by_its_name(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "src/flask/__init__.py": "",
            "src/flask/helpers.py": "VALUE = 1\n",
            "src/flask/sansio/app.py": "from ..helpers import VALUE\n",
            "src/flask/sansio/deep/more.py": "from ...helpers import VALUE\n",
        },
    )
    names = module_names(root)
    check = "import importlib, sys\nsys.path.insert(0, sys.argv[1])\nfor name in sys.argv[2:]:\n    importlib.import_module(name)\n"

    completed = subprocess.run(
        [sys.executable, "-I", "-c", check, str(root / "src"), *names.values()],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert names["src/flask/sansio/deep/more.py"] == "flask.sansio.deep.more"
