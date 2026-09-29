"""A symbol naming an alias of a project function names that function.

A deployment declaration names its handler as ``app.main``, and the module may define
``main`` as an alias, ``main = actual``, of the function that does the work. An
``EntryPoint`` naming ``python.app.main`` then makes ``actual`` the entry point, with the
inputs the model gives, as it would a function named ``main``. An alias is a module-level
assignment of one name to another, followed transitively; a class alias names the
class's methods the same way. A name bound to anything else, a call or an imported name,
is no alias: the model names nothing through it, and an integration reporting declared
handlers sees no entry point.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.plugins import ProjectContext, ProjectPlugin

MANIFEST = (
    'name = "declared-aliases"\nversion = "1.0.0"\nplugin_api = ">=1,<2"\nrequires = []\n'
    'provides = ["model.declared-aliases"]\n\n[entrypoint]\nmodule = "declared"\nclass = "Declared"\n'
)
PLUGIN = '''
from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import EntryPoint, Model


class Declared(ModelPlugin):
    name: ClassVar[str] = "declared-aliases"
    models: ClassVar[tuple[Model, ...]] = (
        EntryPoint(SymbolId("python.app.handlers.main"), "event", inputs=(0,)),
        EntryPoint(SymbolId("python.app.handlers.Worker"), "event"),
        EntryPoint(SymbolId("python.app.handlers.Jobs.run"), "event", inputs=(0,)),
    )
'''
ACTUAL = "import os\n\ndef actual(event, context):\n    os.system(event['cmd'])\n    os.system(context.function_name)\n\n"


def plugins(tmp_path: Path) -> Path:
    plugin = tmp_path / "plugins" / "declared"
    plugin.mkdir(parents=True, exist_ok=True)
    (plugin / "plugin.toml").write_text(MANIFEST, encoding="utf-8")
    (plugin / "declared.py").write_text(PLUGIN, encoding="utf-8")
    return tmp_path / "plugins"


def project(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "project"
    for relative, text in {"app/__init__.py": "", **files}.items():
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_text(text, encoding="utf-8")
    return root


def commands(findings: tuple[Finding, ...]) -> list[tuple[int, str]]:
    return sorted((f.span.start_line, f.metadata["source_label"]) for f in findings if f.rule_id == "command-injection")


def analyze(tmp_path: Path, handlers: str, **options: object) -> list[tuple[int, str]]:
    root = project(tmp_path, {"app/handlers.py": handlers})
    return commands(engine.analyze_project(root, [engine.BUNDLED_PLUGINS, plugins(tmp_path)], **options).findings)  # type: ignore[arg-type]


@pytest.mark.parametrize("jobs", [1, 2])
def test_an_alias_of_a_function_names_that_function(tmp_path: Path, jobs: int) -> None:
    assert analyze(tmp_path, ACTUAL + "main = actual\n", jobs=jobs) == [(4, "event")]


@pytest.mark.parametrize(
    "aliases",
    [
        "handler = actual\nmain = handler\n",
        "main = handler = actual\n",
        "if os.environ.get('DEBUG'):\n    main = actual\nelse:\n    main = actual\n",
        "try:\n    main = actual\nexcept NameError:\n    pass\n",
    ],
    ids=["chained", "chained-in-one", "conditional", "guarded"],
)
def test_module_level_aliases_are_followed_transitively(tmp_path: Path, aliases: str) -> None:
    assert analyze(tmp_path, ACTUAL + aliases) == [(4, "event")]


@pytest.mark.parametrize(
    "aliases",
    [
        "main = decorate(actual)\n",
        "main = actual()\n",
        "from app.other import main\n",
        "def outer():\n    main = actual\n",
        "class Config:\n    main = actual\n",
        "main = 'actual'\n",
    ],
    ids=["a-call", "a-result", "an-import", "in-a-function", "in-a-class", "a-string"],
)
def test_a_name_bound_to_anything_else_is_no_alias(tmp_path: Path, aliases: str) -> None:
    files = {"app/handlers.py": "def decorate(f):\n    return f\n\n" + ACTUAL + aliases, "app/other.py": "main = 1\n"}
    root = project(tmp_path, files)

    findings = engine.analyze_project(root, [engine.BUNDLED_PLUGINS, plugins(tmp_path)]).findings

    assert commands(findings) == []


def test_an_alias_of_a_class_names_its_methods(tmp_path: Path) -> None:
    handlers = (
        "import os\n\n"
        "class Impl:\n"
        "    def start(self, event, context):\n"
        "        os.system(event['cmd'])\n"
        "        os.system(context.function_name)\n\n"
        "    def run(self, event, context):\n"
        "        os.system(event['cmd'])\n"
        "        os.system(context.function_name)\n\n"
        "Worker = Impl\n"
        "Jobs = Impl\n"
    )

    # ``Worker`` makes every parameter of every method input; ``Jobs.run``, naming the
    # method, wins over it for ``run`` and makes only the event input.
    assert analyze(tmp_path, handlers) == [(5, "event"), (6, "event"), (9, "event")]


def test_a_class_alias_alone_limits_the_inputs_it_declares(tmp_path: Path) -> None:
    handlers = (
        "import os\n\n"
        "class Impl:\n"
        "    def run(self, event, context):\n"
        "        os.system(event['cmd'])\n"
        "        os.system(context.function_name)\n\n"
        "Jobs = Impl\n"
    )

    assert analyze(tmp_path, handlers) == [(5, "event")]


def test_a_project_plugin_sees_the_aliased_function_as_the_entry_point(tmp_path: Path) -> None:
    seen: dict[str, str | None] = {}

    class Peek(ProjectPlugin):
        name = "peek"

        def analyze_project(self, ctx: ProjectContext) -> tuple[Finding, ...]:
            for module in ctx.modules:
                for function in ctx.functions(module):
                    seen[f"{module}:{function.name}"] = function.entry_point
            return ()

    root = project(tmp_path, {"app/handlers.py": ACTUAL + "main = actual\n\ndef other(event, context):\n    pass\n"})

    engine.analyze_project(root, [engine.BUNDLED_PLUGINS, plugins(tmp_path)], plugins=[Peek()])

    assert seen["app.handlers:actual"] == "event"
    assert seen["app.handlers:other"] is None
