"""Acceptance tests for multi-file analysis (``docs/architecture.md`` §21).

``engine.analyze_project`` discovers the Python files under a directory, builds a
``ModuleGraph`` of the imports between project modules, analyses every module with its
own manager, and shares a project-wide ``SummaryIndex`` so taint follows calls into
functions defined in other files. Summaries are iterated to a fixpoint across modules
without retaining more than one module's PyIR at a time in a given manager.

Expected to remain red until ``coretrace_python.interprocedural.modulegraph`` and
``engine.analyze_project`` exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cli import main
from coretrace_python.findings import Finding
from coretrace_python.semantic.symbols import SymbolId

try:
    from coretrace_python.interprocedural.modulegraph import (
        ModuleGraph,
        ProjectSummaries,
        SummaryIndex,
    )
except ImportError as error:  # pragma: no cover - red until the module graph lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_module_graph() -> None:
    if MISSING is not None:
        pytest.fail(f"multi-file analysis is not implemented yet: {MISSING}")
    if not hasattr(engine, "analyze_project"):
        pytest.fail("engine.analyze_project is not implemented yet")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"


def project(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, str, int]]:
    return [(Path(str(f.span.source_id)).name, f.rule_id, f.span.start_line) for f in findings]


# --------------------------------------------------------------------------- discovery


def test_discovers_modules_and_their_dotted_names(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/main.py": "import os\n",
            "app/helpers.py": "",
            "scripts/tool.py": "",
            ".venv/lib/site.py": "",
            "node_modules/x.py": "",
            "app/__pycache__/main.cpython-313.py": "",
        },
    )

    graph = engine.analyze_project(root).graph

    assert isinstance(graph, ModuleGraph)
    assert graph.modules == ("app", "app.helpers", "app.main", "tool")
    assert graph.source("app.main").path == (root / "app" / "main.py").resolve()


def test_module_graph_records_imports_between_project_modules(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/main.py": "import os\nfrom app.helpers import run\nfrom . import config\n",
            "app/helpers.py": "import app.config\n",
            "app/config.py": "",
        },
    )

    graph = engine.analyze_project(root).graph

    assert graph.imports("app.main") == frozenset({"app.helpers", "app.config"})
    assert graph.imports("app.helpers") == frozenset({"app.config"})
    assert graph.imports("app.config") == frozenset()
    assert graph.importers("app.config") == frozenset({"app.main", "app.helpers"})


def test_project_functions_have_project_symbols(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {"app/__init__.py": "", "app/helpers.py": "def run(x):\n    return x\n\nclass K:\n    def m(self):\n        pass\n"},
    )

    index = engine.analyze_project(root).index

    assert isinstance(index, SummaryIndex)
    summary = index.summary(SymbolId("python.app.helpers.run"))
    assert summary is not None and summary.return_dependencies == frozenset({0})
    assert index.summary(SymbolId("python.app.helpers.K.m")) is not None
    assert index.summary(SymbolId("python.os.system")) is None
    assert SymbolId("python.app.helpers.run") in index.symbols


# --------------------------------------------------------------------------- cross-module taint


def test_taint_flows_into_a_function_defined_in_another_file(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/helpers.py": "import os\n\ndef execute(command):\n    os.system(command)\n",
            "app/main.py": "from app.helpers import execute\n\ndef run():\n    execute(input())\n",
        },
    )

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert rules(findings) == [("main.py", "command-injection", 4)]
    assert findings[0].metadata["through"] == "app.helpers.execute"
    assert findings[0].metadata["sink_line"] == "4"


def test_module_attribute_calls_resolve_too(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/helpers.py": "import os\n\ndef execute(command):\n    os.system(command)\n",
            "app/main.py": "import app.helpers\n\ndef run():\n    app.helpers.execute(input())\n",
        },
    )

    assert rules(engine.analyze_project(root, [PLUGINS]).findings) == [("main.py", "command-injection", 4)]


def test_tainted_results_cross_files(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/io.py": "def read():\n    return input()\n",
            "app/main.py": "import os\nfrom app.io import read\n\ndef run():\n    os.system(read())\n",
        },
    )

    assert rules(engine.analyze_project(root, [PLUGINS]).findings) == [("main.py", "command-injection", 5)]


def test_relative_imports_inside_packages(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/helpers.py": "import os\n\ndef execute(command):\n    os.system(command)\n",
            "app/main.py": "from .helpers import execute\n\ndef run():\n    execute(input())\n",
        },
    )

    assert rules(engine.analyze_project(root, [PLUGINS]).findings) == [("main.py", "command-injection", 4)]


def test_relative_imports_inside_a_package_init(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "app/__init__.py": "from .helpers import execute\n\ndef run():\n    execute(input())\n",
            "app/helpers.py": "import os\n\ndef execute(command):\n    os.system(command)\n",
        },
    )

    result = engine.analyze_project(root, [PLUGINS])

    assert result.graph.imports("app") == frozenset({"app.helpers"})
    assert rules(result.findings) == [("__init__.py", "command-injection", 4)]


def test_mutual_recursion_across_files_converges(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "a.py": "import os\nfrom b import g\n\ndef f(x):\n    return g(x)\n\ndef run():\n    os.system(f(input()))\n",
            "b.py": "from a import f\n\ndef g(x):\n    if x:\n        return f(x)\n    return x\n",
        },
    )

    result = engine.analyze_project(root, [PLUGINS])

    assert result.index.summary(SymbolId("python.a.f")).return_dependencies == frozenset({0})  # type: ignore[union-attr]
    assert rules(result.findings) == [("a.py", "command-injection", 8)]


def test_single_file_projects_behave_like_check(tmp_path: Path) -> None:
    root = project(tmp_path, {"one.py": "import os\n\ndef run():\n    os.system(input())\n"})
    assert rules(engine.analyze_project(root, [PLUGINS]).findings) == [("one.py", "command-injection", 4)]


def test_unsupported_functions_and_syntax_errors_are_reported_per_file(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "good.py": "def f():\n    pass\n",
            "nested.py": "def outer():\n    break\n",
            "broken.py": "def broken(:\n",
        },
    )

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert rules(findings) == [("broken.py", "syntax-error", 1), ("nested.py", "unsupported-syntax", 1)]
    assert "broken.py:1:12" in findings[0].message


def test_project_summaries_default_to_an_empty_index_and_can_be_provided() -> None:
    assert ProjectSummaries.name == "interprocedural.project"
    manager = engine.build_manager(engine.build_hir(engine.SourceManager().add_source("x.py", "")))
    assert manager.get(ProjectSummaries).symbols == ()

    provided = SummaryIndex()
    bare = engine.AnalysisManager(engine.build_hir(engine.SourceManager().add_source("y.py", "")))
    bare.register(ProjectSummaries)
    bare.provide(ProjectSummaries, provided)
    assert bare.get(ProjectSummaries) is provided


# --------------------------------------------------------------------------- CLI


def test_check_accepts_a_directory(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    root = project(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/helpers.py": "import os\n\ndef execute(command):\n    os.system(command)\n",
            "app/main.py": "from app.helpers import execute\n\ndef run():\n    execute(input())\n",
            "app/clean.py": "def ok():\n    return 1\n",
        },
    )

    exit_code = main(["--check", str(root), "--plugins", str(PLUGINS)])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert output == (
        f"{(root / 'app' / 'main.py').resolve()}:4:5: high command-injection: Command injection:"
        " stdin input reaches python.os.system through app.helpers.execute [run]\n"
        "1 finding\n"
        "coverage: 4/4 files, 3/3 functions\n"
    )


def test_emit_ir_rejects_directories(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    assert main(["--emit-ir", str(tmp_path)]) == 2
    assert "directory" in capsys.readouterr().err
