"""Files sharing a Python module name stay distinct modules (#182).

``a/app.py`` and ``z/app.py``, outside any package, are both the module ``app`` to
Python, each importable from its own directory. The engine keeps one entry per file: its
import name when no other file has it, otherwise its path from the root as a dotted name
(``a.app``, ``z.app``), so both files are discovered, analysed and covered whatever the
order they are found in. An import of a shared name resolves within the importer's own
root only; one no root resolves is reported and not followed. The colliding files carry
an ``ambiguous-module`` note and are covered as ``ambiguous``, since a model or a route
naming ``python.app.main`` applies to every definition of that symbol.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cache import ProjectCache
from coretrace_python.findings import Finding
from coretrace_python.plugins import ProjectContext, ProjectPlugin
from coretrace_python.reporters import render_json
from coretrace_python.semantic.symbols import SymbolId

MANIFEST = (
    'name = "declared-handlers"\nversion = "1.0.0"\nplugin_api = ">=1,<2"\nrequires = []\n'
    'provides = ["model.declared-handlers"]\n\n[entrypoint]\nmodule = "declared"\nclass = "Declared"\n'
)
PLUGIN = '''
from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import EntryPoint, Model


class Declared(ModelPlugin):
    name: ClassVar[str] = "declared-handlers"
    models: ClassVar[tuple[Model, ...]] = (EntryPoint(SymbolId("python.app.main"), "event", inputs=(0,)),)
'''
# The issue's reproduction: ``import os`` makes ``<module>`` a second function of the
# vulnerable handler's file.
VULNERABLE = "import os\n\ndef main(event, context):\n    os.system(event['cmd'])\n"
CLEAN = "def main(event, context):\n    return 'ok'\n"
EXECUTE = "import os\n\ndef execute(command):\n    os.system(command)\n"
RETURNS = "def execute(command):\n    return command\n"
RUN = "from app import execute\n\ndef run():\n    execute(input())\n"
NOTE = "ambiguous-module"


def plugins(tmp_path: Path) -> Path:
    plugin = tmp_path / "plugins" / "declared"
    plugin.mkdir(parents=True, exist_ok=True)
    (plugin / "plugin.toml").write_text(MANIFEST, encoding="utf-8")
    (plugin / "declared.py").write_text(PLUGIN, encoding="utf-8")
    return tmp_path / "plugins"


def project(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "project"
    for relative, text in files.items():
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_text(text, encoding="utf-8")
    return root


def check(tmp_path: Path, root: Path, **options: object) -> engine.ProjectAnalysis:
    roots = [engine.BUNDLED_PLUGINS, plugins(tmp_path)]
    return engine.analyze_project(root, roots, **options)  # type: ignore[arg-type]


def analyze(tmp_path: Path, files: dict[str, str], **options: object) -> engine.ProjectAnalysis:
    return check(tmp_path, project(tmp_path, files), **options)


def located(path: str, root: Path) -> str:
    return Path(path).resolve().relative_to(root.resolve()).as_posix()


def rules(findings: tuple[Finding, ...], root: Path, rule_id: str) -> list[tuple[str, int]]:
    return sorted((located(str(f.span.source_id), root), f.span.start_line) for f in findings if f.rule_id == rule_id)


def notes(findings: tuple[Finding, ...], root: Path) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for finding in findings:
        if finding.rule_id == NOTE:
            found.setdefault(located(str(finding.span.source_id), root), []).append(finding.message)
    return found


# --------------------------------------------------------------------------- discovery


def test_two_files_sharing_a_module_name_are_both_discovered_and_covered(tmp_path: Path) -> None:
    root = project(tmp_path, {"a/app.py": VULNERABLE, "z/app.py": CLEAN})

    analysis = check(tmp_path, root)

    assert analysis.graph.modules == ("a.app", "z.app")
    assert analysis.graph.source("a.app").path == (root / "a" / "app.py").resolve()
    assert analysis.graph.source("a.app").module_name == "app"
    assert [(located(d.path, root), d.status, d.functions, d.analysed) for d in analysis.coverage.details] == [
        ("a/app.py", "ambiguous", 2, 2),
        ("z/app.py", "ambiguous", 1, 1),
    ]
    assert analysis.coverage.summary() == "coverage: 0/2 files, 3/3 functions"
    assert rules(analysis.findings, root, NOTE) == [("a/app.py", 1), ("z/app.py", 1)]
    assert notes(analysis.findings, root) == {
        "a/app.py": [
            (
                "a/app.py is the module 'app' like z/app.py: a symbol python.app.* may name a function of "
                "either, and an import of 'app' resolves only from its own root"
            )
        ],
        "z/app.py": [
            (
                "z/app.py is the module 'app' like a/app.py: a symbol python.app.* may name a function of "
                "either, and an import of 'app' resolves only from its own root"
            )
        ],
    }


@pytest.mark.parametrize("jobs", [1, 2])
@pytest.mark.parametrize("vulnerable", ["a", "z"])
def test_the_vulnerable_handler_keeps_its_finding_whatever_the_discovery_order(
    tmp_path: Path, vulnerable: str, jobs: int
) -> None:
    clean = "z" if vulnerable == "a" else "a"
    root = project(tmp_path, {f"{vulnerable}/app.py": VULNERABLE, f"{clean}/app.py": CLEAN})

    findings = check(tmp_path, root, jobs=jobs).findings

    commands = [f for f in findings if f.rule_id == "command-injection"]
    assert [(located(str(f.span.source_id), root), f.span.start_line) for f in commands] == [
        (f"{vulnerable}/app.py", 4)
    ]
    assert commands[0].metadata["source_label"] == "event"
    assert set(notes(findings, root)) == {"a/app.py", "z/app.py"}


def test_dotted_paths_that_coincide_fall_back_to_the_relative_path(tmp_path: Path) -> None:
    root = project(tmp_path, {"x.y/app.py": VULNERABLE, "x/y/app.py": CLEAN})

    analysis = check(tmp_path, root)

    assert analysis.graph.modules == ("x.y/app.py", "x/y/app.py")
    assert analysis.graph.source("x.y/app.py").path == (root / "x.y" / "app.py").resolve()
    assert [located(d.path, root) for d in analysis.coverage.details] == ["x.y/app.py", "x/y/app.py"]
    assert rules(analysis.findings, root, "command-injection") == [("x.y/app.py", 4)]


# --------------------------------------------------------------------------- import resolution


def test_an_import_of_a_shared_name_resolves_within_the_importers_root(tmp_path: Path) -> None:
    root = project(tmp_path, {"a/app.py": EXECUTE, "a/run.py": RUN, "z/app.py": RETURNS, "z/run.py": RUN})

    analysis = check(tmp_path, root)

    assert analysis.graph.modules == ("a.app", "a.run", "z.app", "z.run")
    assert analysis.graph.imports("a.run") == frozenset({"a.app"})
    assert analysis.graph.imports("z.run") == frozenset({"z.app"})
    assert analysis.graph.unresolved("a.run") == frozenset()
    commands = [f for f in analysis.findings if f.rule_id == "command-injection"]
    assert [(located(str(f.span.source_id), root), f.span.start_line) for f in commands] == [("a/run.py", 4)]
    assert commands[0].metadata["through"] == "app.execute"
    # The importers share the name ``run`` too; nothing they import stayed unresolved.
    assert all("imported here" not in message for messages in notes(analysis.findings, root).values() for message in messages)


def test_an_import_no_root_resolves_is_reported_and_not_followed(tmp_path: Path) -> None:
    root = project(tmp_path, {"a/app.py": EXECUTE, "z/app.py": RETURNS, "c/run.py": RUN})

    analysis = check(tmp_path, root)

    assert analysis.graph.modules == ("a.app", "run", "z.app")
    assert analysis.graph.imports("run") == frozenset()
    assert analysis.graph.unresolved("run") == frozenset({"app"})
    assert rules(analysis.findings, root, "command-injection") == []
    assert notes(analysis.findings, root)["c/run.py"] == [
        "'app' imported here is a/app.py or z/app.py: calls into it are not followed"
    ]
    assert [(located(d.path, root), d.status) for d in analysis.coverage.details] == [
        ("a/app.py", "ambiguous"),
        ("c/run.py", "analysed"),
        ("z/app.py", "ambiguous"),
    ]


THROUGH = "from app import execute\n\ndef through(command):\n    execute(command)\n"
CALLER = (
    "from x import through as x_through\n"
    "from y import through as y_through\n"
    "from app import execute\n\n"
    "def run():\n"
    "    execute(input())\n"
    "    x_through(input())\n"
    "    y_through(input())\n"
)


def test_a_component_reaching_both_files_follows_neither_through_an_unresolved_import(tmp_path: Path) -> None:
    files = {"a/app.py": RETURNS, "a/x.py": THROUGH, "z/app.py": EXECUTE, "z/y.py": THROUGH, "c.py": CALLER}
    root = project(tmp_path, files)

    analysis = check(tmp_path, root)

    assert analysis.graph.imports("c") == frozenset({"x", "y"})
    assert analysis.graph.unresolved("c") == frozenset({"app"})
    # ``y`` carries ``z/app.py``'s sink; the unresolved ``execute`` is followed into neither file.
    assert rules(analysis.findings, root, "command-injection") == [("c.py", 8)]
    assert notes(analysis.findings, root)["c.py"] == [
        "'app' imported here is a/app.py or z/app.py: calls into it are not followed"
    ]


def test_a_component_reaching_both_files_follows_the_one_its_own_root_resolves(tmp_path: Path) -> None:
    files = {"a/app.py": EXECUTE, "a/x.py": THROUGH, "a/c.py": CALLER, "z/app.py": RETURNS, "z/y.py": THROUGH}
    root = project(tmp_path, files)

    analysis = check(tmp_path, root)

    assert analysis.graph.imports("c") == frozenset({"a.app", "x", "y"})
    assert analysis.graph.unresolved("c") == frozenset()
    # ``execute`` is ``a/app.py``'s, whatever ``z/app.py`` reached through ``y`` defines.
    assert rules(analysis.findings, root, "command-injection") == [("a/c.py", 6), ("a/c.py", 7)]
    assert "a/c.py" not in notes(analysis.findings, root)


def test_a_unique_module_resolves_from_any_directory(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {"app/__init__.py": "", "app/helpers.py": EXECUTE, "scripts/tool.py": "from app.helpers import execute\n"},
    )

    analysis = check(tmp_path, root)

    assert analysis.graph.modules == ("app", "app.helpers", "tool")
    assert analysis.graph.imports("tool") == frozenset({"app.helpers"})
    assert analysis.graph.unresolved("tool") == frozenset()
    assert rules(analysis.findings, root, NOTE) == []


def test_a_package_and_a_script_sharing_a_name_keep_their_own_importers(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "authentication/__init__.py": "",
            "authentication/views.py": "import authentication\n",
            "features/steps/authentication.py": "",
            "features/steps/notes.py": "import authentication\n",
        },
    )

    graph = check(tmp_path, root).graph

    assert graph.modules == ("authentication", "authentication.views", "features.steps.authentication", "notes")
    assert graph.imports("authentication.views") == frozenset({"authentication"})
    assert graph.imports("notes") == frozenset({"features.steps.authentication"})
    assert graph.importers("authentication") == frozenset({"authentication.views"})
    assert graph.importers("features.steps.authentication") == frozenset({"notes"})


# --------------------------------------------------------------------------- index, cache and plugins


def test_the_index_and_the_cache_keep_the_files_apart(tmp_path: Path) -> None:
    root = project(tmp_path, {"a/app.py": VULNERABLE, "z/app.py": CLEAN})
    cache = ProjectCache(tmp_path / "cache")

    first = check(tmp_path, root, cache=cache)

    vulnerable = first.index.summary(SymbolId("python.a.app.main"))
    clean = first.index.summary(SymbolId("python.z.app.main"))
    assert vulnerable is not None and clean is not None and vulnerable != clean
    assert first.index.summary(SymbolId("python.app.main")) is None
    assert set(first.keys) == {"a.app", "z.app"}
    assert first.keys["a.app"] != first.keys["z.app"]
    assert first.reused == ()

    second = check(tmp_path, root, cache=cache)

    assert set(second.reused) == {"a.app", "z.app"}
    assert second.findings == first.findings
    assert rules(second.findings, root, "command-injection") == [("a/app.py", 4)]

    (root / "z" / "app.py").unlink()
    third = check(tmp_path, root, cache=cache)

    assert set(third.keys) == {"app"}
    assert third.reused == ()
    assert rules(third.findings, root, "command-injection") == [("a/app.py", 4)]
    assert rules(third.findings, root, NOTE) == []
    assert third.coverage.summary() == "coverage: 1/1 files, 2/2 functions"


def test_a_project_plugin_sees_both_files_with_their_entry_points(tmp_path: Path) -> None:
    seen: dict[str, dict[str, str | None]] = {}

    class Peek(ProjectPlugin):
        name = "peek"

        def analyze_project(self, ctx: ProjectContext) -> tuple[Finding, ...]:
            for module in ctx.modules:
                seen[module] = {f.name: f.entry_point for f in ctx.functions(module)}
            return ()

    root = project(tmp_path, {"a/app.py": VULNERABLE, "z/app.py": CLEAN})

    check(tmp_path, root, plugins=[Peek()])

    assert tuple(seen) == ("a.app", "z.app")
    assert seen["a.app"]["main"] == "event"
    assert seen["z.app"]["main"] == "event"


def test_the_json_report_carries_the_ambiguous_status(tmp_path: Path) -> None:
    root = project(tmp_path, {"a/app.py": VULNERABLE, "z/app.py": CLEAN})
    analysis = check(tmp_path, root)

    document = json.loads(render_json(engine.report(analysis.findings, analysis.coverage, root)))

    assert document["coverage"]["files_analysed"] == 0
    assert [(d["path"], d["status"]) for d in document["coverage"]["details"]] == [
        ("a/app.py", "ambiguous"),
        ("z/app.py", "ambiguous"),
    ]
    assert [f["rule_id"] for f in document["findings"]].count(NOTE) == 2
