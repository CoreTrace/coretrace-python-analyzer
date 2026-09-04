"""Acceptance tests for parallel analysis and memory eviction (``docs/architecture.md``
§29, §30, §38 Phase 10).

The module graph is scheduled by strongly connected components in topological order:
components of one wave depend only on earlier waves, so they can be analysed at the same
time, in separate processes when ``jobs`` is above one. Each component reads the
summaries of the modules it imports, which are final by then, and hands back its
summaries, call sites and findings; the engine then drops its intermediate results,
keeping the semantic tables only. The result is the same whatever the number of jobs.

Expected to remain red until ``ModuleGraph.schedule``, ``analyze_project(jobs=)``,
``engine.ResultsEvicted`` and the ``--jobs`` option exist.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from types import MappingProxyType

import pytest

from coretrace_python import engine
from coretrace_python.cache import ProjectCache
from coretrace_python.cfg import CFGAnalysis
from coretrace_python.cli import main
from coretrace_python.findings import Finding
from coretrace_python.frontend import build_hir
from coretrace_python.interprocedural import ModuleGraph, ProjectSummaries
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.semantic.imports import ImportAnalysis
from coretrace_python.semantic.scopes import ScopeAnalysis
from coretrace_python.source import SourceManager
from coretrace_python.taint import SecurityModelAnalysis

try:
    from coretrace_python.engine import ResultsEvicted
except ImportError as error:  # pragma: no cover - red until parallel analysis lands
    MISSING: Exception | None = error
else:
    MISSING = None
    if "jobs" not in inspect.signature(engine.analyze_project).parameters:
        MISSING = AttributeError("analyze_project has no jobs parameter")
    elif not hasattr(ModuleGraph, "schedule"):
        MISSING = AttributeError("ModuleGraph has no schedule")


@pytest.fixture(autouse=True)
def require_parallel() -> None:
    if MISSING is not None:
        pytest.fail(f"parallel analysis is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "plugins"

HELPERS = "import os\n\ndef execute(command):\n    os.system(command)\n"
MAIN = "from app.helpers import execute\n\ndef run():\n    execute(input())\n"
CLEAN = "def ok():\n    return 1\n"


def project(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def standard(root: Path) -> Path:
    return project(
        root / "src",
        {"app/__init__.py": "", "app/helpers.py": HELPERS, "app/main.py": MAIN, "app/clean.py": CLEAN},
    )


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, str, int]]:
    return sorted((Path(str(f.span.source_id)).name, f.rule_id, f.span.start_line) for f in findings)


def graph_of(imports: dict[str, set[str]]) -> ModuleGraph:
    sources = SourceManager()
    return ModuleGraph(
        MappingProxyType({name: sources.add_source(f"{name}.py", "", name) for name in imports}),
        MappingProxyType({name: frozenset(found) for name, found in imports.items()}),
    )


# --------------------------------------------------------------------------- schedule


def test_schedule_groups_cycles_and_orders_waves_topologically() -> None:
    graph = graph_of({"a": {"b", "c"}, "b": {"d"}, "c": {"d"}, "d": set(), "e": {"f"}, "f": {"e"}, "g": set()})

    waves = graph.schedule()

    assert waves == (
        (frozenset({"d"}), frozenset({"e", "f"}), frozenset({"g"})),
        (frozenset({"b"}), frozenset({"c"})),
        (frozenset({"a"}),),
    )


def test_schedule_of_a_project_puts_importers_after_their_imports(tmp_path: Path) -> None:
    graph = engine.analyze_project(standard(tmp_path), [PLUGINS]).graph

    assert graph.schedule() == (
        (frozenset({"app"}), frozenset({"app.clean"}), frozenset({"app.helpers"})),
        (frozenset({"app.main"}),),
    )


def test_schedule_ignores_imports_outside_the_graph() -> None:
    assert graph_of({"a": {"missing"}}).schedule() == ((frozenset({"a"}),),)


# --------------------------------------------------------------------------- parallel


def test_parallel_analysis_matches_the_sequential_result(tmp_path: Path) -> None:
    root = standard(tmp_path)

    sequential = engine.analyze_project(root, [PLUGINS])
    parallel = engine.analyze_project(root, [PLUGINS], jobs=3)

    assert parallel.findings == sequential.findings
    assert rules(parallel.findings) == [("main.py", "command-injection", 4)]
    assert parallel.index == sequential.index
    assert parallel.keys == sequential.keys
    assert parallel.reused == ()


def test_mutually_importing_modules_are_analysed_together(tmp_path: Path) -> None:
    root = project(
        tmp_path / "src",
        {
            "a.py": "from b import g\n\ndef f():\n    g(input())\n",
            "b.py": "import os\nfrom a import f\n\ndef g(x):\n    os.system(x)\n\ndef h():\n    return f()\n",
        },
    )

    result = engine.analyze_project(root, [PLUGINS], jobs=2)

    assert result.graph.schedule() == ((frozenset({"a", "b"}),),)
    assert rules(result.findings) == [("a.py", "command-injection", 4)]


def test_parallel_analysis_serves_project_plugins_and_correlation(tmp_path: Path) -> None:
    root = project(
        tmp_path / "src",
        {
            "requirements.txt": "pyyaml==5.3.1\n",
            "app/__init__.py": "",
            "app/config.py": "import yaml\n\ndef parse(text):\n    return yaml.load(text)\n",
            "app/main.py": "from app.config import parse\n\ndef run():\n    parse(input())\n",
        },
    )

    findings = engine.analyze_project(root, [PLUGINS], jobs=2).findings

    assert rules(findings) == [
        ("config.py", "reachable-vulnerability", 4),
        ("main.py", "exploitable-vulnerability", 4),
        ("requirements.txt", "vulnerable-dependency", 1),
    ]


def test_parallel_analysis_keeps_syntax_and_unsupported_notes(tmp_path: Path) -> None:
    root = project(
        tmp_path / "src",
        {
            "broken.py": "def (:\n",
            "nested.py": "def outer():\n    class Inner:\n        pass\n    return Inner\n",
            "fine.py": CLEAN,
        },
    )

    sequential = engine.analyze_project(root, [PLUGINS])
    parallel = engine.analyze_project(root, [PLUGINS], jobs=2)

    assert parallel.findings == sequential.findings
    assert [f.rule_id for f in parallel.findings] == ["syntax-error", "unsupported-syntax"]


def test_parallel_analysis_fills_and_reuses_the_cache(tmp_path: Path) -> None:
    root = standard(tmp_path)
    cache = ProjectCache(tmp_path / "cache")

    first = engine.analyze_project(root, [PLUGINS], cache=cache, jobs=2)
    second = engine.analyze_project(root, [PLUGINS], cache=cache, jobs=2)
    third = engine.analyze_project(root, [PLUGINS], cache=cache)

    assert first.reused == ()
    assert set(second.reused) == set(third.reused) == {"app", "app.helpers", "app.main", "app.clean"}
    assert second.findings == first.findings == third.findings


def test_one_job_never_spawns_workers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import concurrent.futures

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("a process pool was created for jobs=1")

    monkeypatch.setattr(concurrent.futures, "ProcessPoolExecutor", forbidden)

    assert rules(engine.analyze_project(standard(tmp_path), [PLUGINS], jobs=1).findings) == [
        ("main.py", "command-injection", 4)
    ]


# --------------------------------------------------------------------------- eviction


def test_eviction_keeps_semantic_tables_and_engine_inputs_only() -> None:
    source = SourceManager().add_source("m.py", "import os\n\ndef f(x):\n    os.system(x)\n")
    manager = engine.build_manager(build_hir(source))
    function = manager.module.body[-1]
    manager.get(SSAAnalysis, function)  # type: ignore[arg-type]
    manager.get(ImportAnalysis)

    manager.run(ResultsEvicted)

    assert not manager.is_cached(SSAAnalysis, function)  # type: ignore[arg-type]
    assert not manager.is_cached(CFGAnalysis, function)  # type: ignore[arg-type]
    assert manager.is_cached(ImportAnalysis)
    assert manager.is_cached(ScopeAnalysis)
    assert manager.is_cached(ProjectSummaries)
    assert manager.is_cached(SecurityModelAnalysis)


# --------------------------------------------------------------------------- CLI


def test_check_accepts_a_job_count(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    root = standard(tmp_path)

    sequential = main(["--check", str(root), "--plugins", str(PLUGINS)])
    sequential_output = capsys.readouterr().out
    parallel = main(["--check", str(root), "--plugins", str(PLUGINS), "--jobs", "2"])
    parallel_output = capsys.readouterr().out

    assert sequential == parallel == 1
    assert parallel_output == sequential_output


def test_jobs_option_requires_a_directory_check(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = tmp_path / "x.py"
    source.write_text("", encoding="utf-8")

    assert main(["--emit-ir", "--jobs", "2", str(source)]) == 2
    assert "--jobs" in capsys.readouterr().err
    assert main(["--check", "--jobs", "0", str(source)]) == 2
    assert "--jobs" in capsys.readouterr().err
