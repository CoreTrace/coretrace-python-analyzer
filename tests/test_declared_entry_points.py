"""Entry points declared by their own symbol, with the parameters that are input.

Nothing in a bare AWS Lambda handler, ``def main(event, context)``, marks it: no
decorator, no base class, no registration call. What marks it is a deployment
declaration, a SAM template or a ``serverless.yml``, which an integration reads and
turns into an ``EntryPoint`` naming the project function by its symbol,
``python.app.handlers.main``. The engine then treats the function as it treats a
decorated one, whatever its parameters are called. An ``EntryPoint`` may also say which
parameters are input, by position after ``self``: a handler's event is, its context is
not. A class named this way makes every method an entry point, as a registered class
does. A function named ``handler`` is nothing without a declaration.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.plugins import ProjectContext, ProjectPlugin
from coretrace_python.source import SourceManager

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
    models: ClassVar[tuple[Model, ...]] = (
        EntryPoint(SymbolId("python.app.handlers.main"), "event", inputs=(0,)),
        EntryPoint(SymbolId("python.app.handlers.Jobs.run"), "event", inputs=(0,)),
        EntryPoint(SymbolId("python.app.handlers.Worker"), "event"),
        EntryPoint(SymbolId("python.handlers.main"), "event", inputs=(0,)),
        EntryPoint(SymbolId("python.jobs.task"), "queue", inputs=(1,)),
    )
'''
HANDLERS = (
    "import os\n\n"
    "def main(evt, ctx):\n"
    "    os.system(evt['cmd'])\n"
    "    os.system(ctx.function_name)\n\n"
    "def handler(event, context):\n"
    "    os.system(event['cmd'])\n\n"
    "class Jobs:\n"
    "    def run(self, event, context):\n"
    "        os.system(event['cmd'])\n"
    "        os.system(context.function_name)\n\n"
    "    def other(self, event, context):\n"
    "        os.system(event['cmd'])\n\n"
    "class Worker:\n"
    "    def start(self, event, context):\n"
    "        os.system(event['cmd'])\n"
    "        os.system(context.function_name)\n"
)
EVENT_LINES = [4, 12, 20, 21]


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


def analyze(tmp_path: Path, files: dict[str, str], **options: object) -> list[tuple[int, str]]:
    root = project(tmp_path, files)
    roots = [engine.BUNDLED_PLUGINS, plugins(tmp_path)]
    return commands(engine.analyze_project(root, roots, **options).findings)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- declared


@pytest.mark.parametrize("jobs", [1, 2])
def test_a_function_declared_by_its_symbol_receives_its_inputs_whatever_their_names(tmp_path: Path, jobs: int) -> None:
    files = {"app/handlers.py": HANDLERS, "app/other.py": "X = 1\n"}

    # ``main``'s event, ``Jobs.run``'s event, and everything ``Worker.start`` takes;
    # not the contexts of ``main`` and ``Jobs.run``, not ``handler``, not ``Jobs.other``.
    assert analyze(tmp_path, files, jobs=jobs) == [(line, "event") for line in EVENT_LINES]


def test_a_function_named_handler_is_nothing_without_a_declaration(tmp_path: Path) -> None:
    module = "import os\n\ndef handler(event, context):\n    os.system(event['cmd'])\n\ndef lambda_handler(event, context):\n    os.system(event['cmd'])\n"

    assert analyze(tmp_path, {"app/lambda_function.py": module}) == []


def test_a_single_file_check_honours_a_declared_symbol(tmp_path: Path) -> None:
    source = SourceManager().add_source("handlers.py", HANDLERS)

    findings = engine.analyze_file(source, [engine.BUNDLED_PLUGINS, plugins(tmp_path)]).findings

    assert commands(findings) == [(4, "event")]


def test_the_inputs_of_a_decorated_entry_point_can_be_limited_too(tmp_path: Path) -> None:
    module = (
        "import os\n"
        "from jobs import task\n\n"
        "@task\n"
        "def send(channel, payload):\n"
        "    os.system(channel)\n"
        "    os.system(payload)\n"
    )

    assert analyze(tmp_path, {"app/tasks.py": module}) == [(7, "queue")]


def test_a_project_plugin_sees_the_declared_functions_as_entry_points(tmp_path: Path) -> None:
    seen: dict[str, str | None] = {}

    class Peek(ProjectPlugin):
        name = "peek"

        def analyze_project(self, ctx: ProjectContext) -> tuple[Finding, ...]:
            for module in ctx.modules:
                for function in ctx.functions(module):
                    seen[function.name] = function.entry_point
            return ()

    root = project(tmp_path, {"app/handlers.py": HANDLERS})

    engine.analyze_project(root, [engine.BUNDLED_PLUGINS, plugins(tmp_path)], plugins=[Peek()])

    assert {name: seen[name] for name in ("main", "handler", "Jobs.run", "Jobs.other", "Worker.start")} == {
        "main": "event",
        "handler": None,
        "Jobs.run": "event",
        "Jobs.other": None,
        "Worker.start": "event",
    }
