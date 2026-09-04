"""Acceptance tests for attribute state on ``self`` across methods (option 2, second
point of the consolidation).

``self.cmd = argv`` in ``__init__`` then ``os.system(self.cmd)`` in ``run()`` was
invisible: each method saw its own ``self``. Three mechanisms close the gap.

- The call graph knows the classes of a module: ``App(x)`` is a call to ``App.__init__``
  whose receiver is the new object, ``app.run()`` on an instance and ``self.helper()``
  inside a method are calls to the class's methods with the receiver as ``self``.
- A method's summary expresses what it reads from ``self`` as a dependency on its first
  parameter, and callers map that parameter onto the receiver, contents included, so a
  value stored by one method and read by another flows through the object, in one file
  or across files through the project index.
- When the framework calls the methods, as for a Django view, a method starts with the
  attributes of ``self`` seeded by what its sibling methods store there from their own
  inputs, so ``self.cmd = request.POST[...]`` in ``post`` reaches ``os.system`` in ``get``.

Expected to remain red until the call graph resolves instantiations and method calls and
the taint engine seeds ``self``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.interprocedural import CallGraphAnalysis, KnownFunction, SummaryAnalysis
from coretrace_python.source import SourceManager

REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "plugins"

APP = (
    "import os\nimport sys\n\n"
    "class App:\n"
    "    def __init__(self, cmd):\n        self.cmd = cmd\n\n"
    "    def setup(self):\n        self.cmd = input()\n\n"
    "    def run(self):\n        os.system(self.cmd)\n\n"
    "    def helper(self):\n        self.run()\n\n"
)


def hir(text: str) -> nodes.Module:
    return build_hir(SourceManager().add_source("s.py", text))


def check(text: str, name: str = "s.py") -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source(name, text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, int, str | None, str]]:
    return sorted((f.rule_id, f.span.start_line, f.function, f.metadata.get("through", "")) for f in findings)


@pytest.fixture(autouse=True)
def require_self_state() -> None:
    graph = engine.build_manager(hir(APP + "def main():\n    App(sys.argv[1]).run()\n")).get(CallGraphAnalysis)
    if not any(isinstance(s.target, KnownFunction) and s.target.name == "App.__init__" for s in graph.sites("main")):
        pytest.fail("self state across methods is not implemented yet")


# --------------------------------------------------------------------------- call graph


def test_instantiations_and_method_calls_resolve_to_the_class_methods() -> None:
    graph = engine.build_manager(hir(APP + "def main(a: App):\n    app = App(sys.argv[1])\n    app.run()\n    a.setup()\n")).get(CallGraphAnalysis)

    assert [s.target for s in graph.sites("main") if isinstance(s.target, KnownFunction)] == [
        KnownFunction("App.__init__"),
        KnownFunction("App.run"),
        KnownFunction("App.setup"),
    ]
    assert [s.target for s in graph.sites("App.helper")] == [KnownFunction("App.run")]
    assert graph.callers("App.run") == frozenset({"main", "App.helper"})


def test_unknown_classes_stay_unknown() -> None:
    from coretrace_python.interprocedural import UnknownTarget

    graph = engine.build_manager(hir("def main(thing):\n    thing.run()\n    Other().go()\n")).get(CallGraphAnalysis)
    assert all(isinstance(s.target, UnknownTarget) for s in graph.sites("main"))


# --------------------------------------------------------------------------- driven flows


def test_a_value_stored_by_init_reaches_a_sink_in_another_method() -> None:
    findings = check(APP + "def main():\n    app = App(sys.argv[1])\n    app.run()\n")
    assert rules(findings) == [("command-injection", 19, "main", "App.run")]
    assert findings[0].metadata["sink_line"] == "12"


def test_a_value_stored_by_a_setter_method_reaches_a_later_method() -> None:
    findings = check(APP + "def main():\n    app = App('ls')\n    app.setup()\n    app.run()\n")
    assert rules(findings) == [("command-injection", 20, "main", "App.run")]


def test_clean_instances_and_other_classes_are_not_confused() -> None:
    assert check(APP + "def main():\n    app = App('ls')\n    app.run()\n") == ()
    assert (
        check(
            APP + "class Other:\n    def __init__(self):\n        self.cmd = input()\n\n"
            "def main():\n    Other()\n    App('ls').run()\n"
        )
        == ()
    )


def test_method_chains_go_through_self_calls() -> None:
    findings = check(APP + "def main():\n    App(input()).helper()\n")
    assert rules(findings) == [("command-injection", 18, "main", "App.helper")]


def test_summaries_read_self_as_the_first_parameter() -> None:
    table = engine.build_manager(hir(APP)).get(SummaryAnalysis)

    run = table.summary("App.run")
    assert [(str(c.symbol), c.argument_dependencies) for c in run.external_calls] == [("python.os.system", (frozenset({0}),))]
    init = table.summary("App.__init__")
    assert [(m.parameter, m.field, m.dependencies) for m in init.mutations] == [(0, "attributes", frozenset({1}))]


def test_instances_cross_files_through_the_project_index(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    (tmp_path / "main.py").write_text("import sys\nfrom app import App\n\ndef main():\n    App(sys.argv[1]).run()\n", encoding="utf-8")

    findings = engine.analyze_project(tmp_path, [PLUGINS]).findings

    assert [(f.rule_id, Path(str(f.span.source_id)).name, f.span.start_line, f.metadata.get("through")) for f in findings] == [
        ("command-injection", "main.py", 5, "app.App.run")
    ]


# --------------------------------------------------------------------------- framework-driven methods


def test_sibling_methods_seed_self_for_entry_point_classes() -> None:
    findings = check(
        "import os\nfrom django.views import View\n\n"
        "class Runner(View):\n"
        "    def post(self, request):\n        self.cmd = request.POST['cmd']\n        return 'stored'\n\n"
        "    def get(self, request):\n        os.system(self.cmd)\n        return 'ran'\n"
    )
    assert rules(findings) == [("command-injection", 10, "get", "")]
    assert findings[0].metadata["source_label"] == "http"


def test_seeding_needs_a_sibling_that_stores_input() -> None:
    assert (
        check(
            "import os\nfrom django.views import View\n\n"
            "class Runner(View):\n"
            "    def post(self, request):\n        self.cmd = 'ls'\n        return 'stored'\n\n"
            "    def get(self, request):\n        os.system(self.cmd)\n        return 'ran'\n"
        )
        == ()
    )
