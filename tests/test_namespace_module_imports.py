"""Acceptance tests for issue #264: imports of and from modules in directories without
``__init__.py`` inside a package.

Such a module has one identity, its name after its package, and may be imported by two
names: that one, and, as a script run from its directory imports it (``sys.path[0]``),
the name it has from there. Its relative imports resolve against its package; an
absolute import from it prefers what its own directory holds, as a script finds it,
then what the package's import root holds. Of two files with one such name, each
importer reaches the one in its own directory. Whatever the names a module is reached
by, its summaries are computed once, and the result does not depend on the cache or on
the number of processes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cache import ProjectCache

PLUGINS = [engine.BUNDLED_PLUGINS]


def project(tmp_path: Path, files: dict[str, str], name: str = "project") -> Path:
    root = tmp_path / name
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def located(analysis: engine.ProjectAnalysis, root: Path, *rules: str) -> list[tuple[str, str, int]]:
    return sorted(
        (f.rule_id, Path(str(f.span.source_id)).relative_to(root.resolve()).as_posix(), f.span.start_line)
        for f in analysis.findings
        if not rules or f.rule_id in rules
    )


NAMESPACE = {
    "pkg/__init__.py": "",
    "pkg/config.py": "import os\n\n\ndef run(command):\n    os.system(command)\n",
    "pkg/sub/app.py": "from ..config import run\nfrom .helper import read\n\n\ndef view():\n    run(read())\n",
    "pkg/sub/helper.py": "def read():\n    return input()\n",
    "pkg/a/b/deep.py": "from ...config import run\n\n\ndef view():\n    run(input())\n",
}


def test_relative_imports_from_a_directory_without_init_resolve_against_its_package(tmp_path: Path) -> None:
    root = project(tmp_path, NAMESPACE)

    analysis = engine.analyze_project(root, PLUGINS)

    assert located(analysis, root) == [("command-injection", "pkg/a/b/deep.py", 5), ("command-injection", "pkg/sub/app.py", 6)]


def test_a_core_module_in_such_a_directory_is_followed_from_its_package(tmp_path: Path) -> None:
    # flask 3.1.0: src/flask/sansio has no __init__.py, and flask/app.py imports from it.
    root = project(
        tmp_path,
        {
            "src/flask/__init__.py": "",
            "src/flask/helpers.py": "import os\n\n\ndef spawn(command):\n    os.system(command)\n",
            "src/flask/sansio/scaffold.py": "from ..helpers import spawn\n\n\ndef launch(command):\n    spawn(command)\n",
            "src/flask/app.py": "from .sansio.scaffold import launch\n\n\ndef serve():\n    launch(input())\n",
        },
    )

    analysis = engine.analyze_project(root, PLUGINS)

    assert located(analysis, root) == [("command-injection", "src/flask/app.py", 5)]


def test_a_sibling_imported_relatively_is_found_beside_a_module_of_the_same_short_name(tmp_path: Path) -> None:
    # pygoat: introduction/playground/A9/api.py imports .main, and another main.py lies
    # elsewhere, outside any package.
    root = project(
        tmp_path,
        {
            "introduction/__init__.py": "",
            "introduction/playground/__init__.py": "",
            "introduction/playground/A9/main.py": "import os\n\n\nclass Log:\n    def write(self, line):\n        os.system(line)\n",
            "introduction/playground/A9/api.py": "from .main import Log\n\n\ndef view():\n    Log().write(input())\n",
            "labs/insec/main.py": "def unrelated():\n    return 1\n",
        },
    )

    analysis = engine.analyze_project(root, PLUGINS)

    assert located(analysis, root, "command-injection", "syntax-error") == [
        ("command-injection", "introduction/playground/A9/api.py", 5)
    ]


SCRIPTS = {
    "pkg/__init__.py": "",
    "pkg/tools/run.py": 'import helper\n\n\ndef main():\n    helper.execute(input())\n\n\nif __name__ == "__main__":\n    main()\n',
    "pkg/tools/helper.py": "import os\n\n\ndef execute(command):\n    os.system(command)\n",
}


def test_a_script_reaches_the_module_beside_it_by_its_short_name(tmp_path: Path) -> None:
    root = project(tmp_path, SCRIPTS)

    analysis = engine.analyze_project(root, PLUGINS)

    assert located(analysis, root) == [("command-injection", "pkg/tools/run.py", 5)]


def test_a_module_beside_a_script_named_like_a_library_leaves_the_library_modelled(tmp_path: Path) -> None:
    # The script's os is the library: the os.py beside it defines no system.
    root = project(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/tools/run.py": "import os\n\n\ndef main():\n    os.system(input())\n",
            "pkg/tools/os.py": "def unrelated():\n    return 1\n",
        },
    )

    analysis = engine.analyze_project(root, PLUGINS)

    assert located(analysis, root) == [("command-injection", "pkg/tools/run.py", 5)]


@pytest.mark.parametrize("dangerous", ["a", "b"])
def test_each_importer_reaches_the_helper_of_its_own_directory(tmp_path: Path, dangerous: str) -> None:
    run = "import helper\n\n\ndef main():\n    helper.execute(input())\n"
    sink = "import os\n\n\ndef execute(command):\n    os.system(command)\n"
    harmless = "def execute(command):\n    return command\n"
    root = project(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/a/run.py": run,
            "pkg/a/helper.py": sink if dangerous == "a" else harmless,
            "pkg/b/run.py": run,
            "pkg/b/helper.py": sink if dangerous == "b" else harmless,
        },
    )

    analysis = engine.analyze_project(root, PLUGINS)

    assert located(analysis, root, "command-injection") == [("command-injection", f"pkg/{dangerous}/run.py", 5)]


def test_a_script_reaches_the_helper_beside_it_before_one_at_the_project_root(tmp_path: Path) -> None:
    # Run from its directory, the script finds the helper beside it first (sys.path[0]).
    root = project(
        tmp_path,
        {
            **SCRIPTS,
            "helper.py": "def execute(command):\n    return command\n",
        },
    )

    analysis = engine.analyze_project(root, PLUGINS)

    assert located(analysis, root, "command-injection") == [("command-injection", "pkg/tools/run.py", 5)]


def test_a_script_keeps_the_helper_it_resolved_beside_another_of_that_short_name(tmp_path: Path) -> None:
    # pkg/b/helper.py is also ``helper`` from pkg/b: the script's ``helper`` is its own.
    root = project(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/a/run.py": "import helper\nfrom pkg.b import helper as other\n\n\ndef main():\n    other.execute(input())\n    helper.execute(input())\n",
            "pkg/a/helper.py": "import os\n\n\ndef execute(command):\n    os.system(command)\n",
            "pkg/b/helper.py": "def execute(command):\n    return command\n",
        },
    )

    analysis = engine.analyze_project(root, PLUGINS)

    assert located(analysis, root, "command-injection") == [("command-injection", "pkg/a/run.py", 7)]


def test_a_module_reached_by_both_its_names_keeps_one_identity(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            **SCRIPTS,
            "pkg/other.py": "from .tools import helper\n\n\ndef handle():\n    helper.execute(input())\n",
        },
    )

    analysis = engine.analyze_project(root, PLUGINS)

    helpers = [n for n in analysis.graph.modules if str(analysis.graph.source(n).source_id).endswith("tools/helper.py")]
    assert helpers == ["pkg.tools.helper"]
    assert [d.path for d in analysis.coverage.details].count(str((root / "pkg/tools/helper.py").resolve())) == 1
    assert located(analysis, root) == [("command-injection", "pkg/other.py", 5), ("command-injection", "pkg/tools/run.py", 5)]


EVERYTHING = {
    **NAMESPACE,
    "pkg/tools/run.py": SCRIPTS["pkg/tools/run.py"],
    "pkg/tools/helper.py": SCRIPTS["pkg/tools/helper.py"],
    "pkg/other.py": "from .tools import helper\n\n\ndef handle():\n    helper.execute(input())\n",
    "pkg/b/run.py": "import helper\n\n\ndef main():\n    helper.execute(input())\n",
    "pkg/b/helper.py": "def execute(command):\n    return command\n",
}


def test_the_result_does_not_depend_on_the_cache_or_the_processes(tmp_path: Path) -> None:
    root = project(tmp_path, EVERYTHING)

    def outcome(**options: object) -> tuple[list[tuple[str, str, int]], list[tuple[str, str]]]:
        analysis = engine.analyze_project(root, PLUGINS, **options)  # type: ignore[arg-type]
        return located(analysis, root), sorted((d.path, d.status) for d in analysis.coverage.details)

    expected = outcome()
    cache = ProjectCache(tmp_path / "cache")

    assert expected[0] == [
        ("command-injection", "pkg/a/b/deep.py", 5),
        ("command-injection", "pkg/other.py", 5),
        ("command-injection", "pkg/sub/app.py", 6),
        ("command-injection", "pkg/tools/run.py", 5),
    ]
    assert outcome(cache=cache) == expected
    assert outcome(cache=cache) == expected
    assert outcome(jobs=2) == expected
    assert outcome(jobs=2, cache=ProjectCache(tmp_path / "parallel-cache")) == expected


def test_a_short_name_no_directory_of_the_importer_answers_is_no_module_of_the_project(tmp_path: Path) -> None:
    # Run from the root, tool.py finds no helper: pkg/a/helper.py and pkg/b/helper.py
    # are ``helper`` only to a script beside them, and Python raises ModuleNotFoundError.
    root = project(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/a/helper.py": "import os\n\n\ndef execute(command):\n    os.system(command)\n",
            "pkg/b/helper.py": "def execute(command):\n    return command\n",
            "tool.py": "import helper\n\n\ndef main():\n    helper.execute(input())\n",
        },
    )

    analysis = engine.analyze_project(root, PLUGINS)

    (tool,) = [n for n in analysis.graph.modules if Path(str(analysis.graph.source(n).source_id)).name == "tool.py"]
    assert analysis.graph.imports(tool) == frozenset()
    assert analysis.graph.unresolved(tool) == frozenset()
    assert [f for f in analysis.findings if Path(str(f.span.source_id)).name == "tool.py"] == []
