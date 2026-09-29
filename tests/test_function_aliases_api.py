"""Project plugins see the module-level aliases of a function.

An integration reading a deployment declaration names its handler as the module binds
it, ``handlers.main``, and the engine applies an entry point named that way to the
function a module-level alias, ``main = actual``, denotes. ``ModuleFunction.aliases``
gives a project plugin the names the module binds to each function that way, in source
order and transitively, so it can report a declared name that names no function instead
of trusting the assignment. A name bound to anything but a name is no alias, a method
or a nested function has none, and the aliases survive the cache.
"""

from __future__ import annotations

from pathlib import Path

from coretrace_python import engine
from coretrace_python.cache import ProjectCache
from coretrace_python.findings import Finding
from coretrace_python.plugins import ProjectContext, ProjectPlugin

HANDLERS = (
    "def actual(event, context):\n"
    "    pass\n\n"
    "handler = actual\n"
    "main = handler\n\n"
    "class Impl:\n"
    "    def run(self, event, context):\n"
    "        pass\n\n"
    "Worker = Impl\n\n"
    "def outer():\n"
    "    def inner():\n"
    "        pass\n"
    "    return inner\n\n"
    "made = outer()\n"
)


class Peek(ProjectPlugin):
    name = "peek"

    def __init__(self) -> None:
        self.seen: dict[str, tuple[str, ...]] = {}

    def analyze_project(self, ctx: ProjectContext) -> tuple[Finding, ...]:
        for module in ctx.modules:
            for function in ctx.functions(module):
                self.seen[f"{module}:{function.name}"] = function.aliases
        return ()


def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    for relative, text in {"app/__init__.py": "", "app/handlers.py": HANDLERS}.items():
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_text(text, encoding="utf-8")
    return root


def peek(root: Path, cache: ProjectCache | None = None) -> tuple[dict[str, tuple[str, ...]], engine.ProjectAnalysis]:
    plugin = Peek()
    analysis = engine.analyze_project(root, [engine.BUNDLED_PLUGINS], plugins=[plugin], cache=cache)
    return plugin.seen, analysis


def test_a_function_lists_the_module_level_names_bound_to_it(tmp_path: Path) -> None:
    seen, _ = peek(project(tmp_path))

    assert seen["app.handlers:actual"] == ("handler", "main")
    assert seen["app.handlers:Impl.run"] == ()
    assert seen["app.handlers:outer"] == ()
    assert seen["app.handlers:outer.inner"] == ()
    assert seen["app.handlers:<module>"] == ()


def test_the_aliases_survive_the_cache(tmp_path: Path) -> None:
    root = project(tmp_path)
    cache = ProjectCache(tmp_path / "cache")

    first, _ = peek(root, cache)
    second, analysis = peek(root, cache)

    assert analysis.reused == ("app", "app.handlers")
    assert second == first
    assert second["app.handlers:actual"] == ("handler", "main")
