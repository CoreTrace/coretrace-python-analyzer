"""Acceptance tests for issue #240, part 2: ``getattr(obj, name)(...)`` with a name the
input chooses.

The name only matters when the attribute it selects is called: the flow is anchored at
each invocation of ``getattr``'s result, one finding per invocation, in the function and
through project helpers, whose summaries keep the ``getattr`` call and each invocation.
What runs depends on what the object exposes: a hotspot, ``Untrusted attribute call``,
on a module too. A check proves the name only when it limits it to constants, and only
on the value ``getattr`` received: checking the name after it was rebound proves
nothing. Not followed, as documented: a ``getattr`` whose result is only read, returned,
or stored before it is called.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cache import ProjectCache
from coretrace_python.cli import main
from coretrace_python.findings import Finding
from coretrace_python.source import SourceManager

HEADER = "import os\n\n\nclass Handler:\n    def run(self):\n        name = input()\n"


def injections(body: str) -> list[Finding]:
    text = HEADER + "".join(f"        {line}\n" for line in body.splitlines())
    findings = engine.check(SourceManager().add_source("app.py", text), [engine.BUNDLED_PLUGINS])
    return sorted((f for f in findings if f.rule_id == "code-injection"), key=lambda f: f.span.start_line)


def shape(finding: Finding) -> tuple[str, str, str, int, str | None, str | None]:
    return (
        finding.metadata["verdict"],
        finding.confidence.value,
        finding.message.split(":", 1)[0],
        finding.span.start_line,
        finding.metadata.get("selected_line"),
        finding.metadata.get("invoked_line"),
    )


ATTRIBUTE_CALL = ("hotspot", "medium", "Untrusted attribute call")


def test_the_called_attribute_is_reported_at_its_invocation() -> None:
    (finding,) = injections("handler = getattr(self, name)\nhandler()")

    assert shape(finding) == (*ATTRIBUTE_CALL, 8, "7", "8")


def test_each_invocation_is_reported_once() -> None:
    findings = injections("handler = getattr(self, name)\nhandler()\nhandler(1)")

    assert [shape(f) for f in findings] == [(*ATTRIBUTE_CALL, 8, "7", "8"), (*ATTRIBUTE_CALL, 9, "7", "9")]


def test_two_selections_reaching_one_invocation_are_reported_each() -> None:
    body = "if name:\n    handler = getattr(self, name)\nelse:\n    handler = getattr(os, name)\nhandler()"

    findings = injections(body)

    assert sorted(f.metadata["selected_line"] for f in findings) == ["10", "8"]
    assert {f.span.start_line for f in findings} == {11}


@pytest.mark.parametrize(
    "body",
    [
        # Only read, not called.
        "value = getattr(self, name)",
        "print(getattr(self, name, None))",
        # Not followed (documented): returned, or stored before it is called.
        "return getattr(self, name)",
        "self.handler = getattr(self, name)\nself.handler()",
        # The input is the object, not the name.
        "getattr(name, 'strip')()",
        "getattr(self, 'run')()",
    ],
)
def test_a_name_that_selects_nothing_called_is_not_reported(body: str) -> None:
    assert injections(body) == []


@pytest.mark.parametrize(
    "body",
    [
        "getattr(os, name)('id')",
        "getattr(self, 'do_' + name)()",
        "handler = getattr(self, name)\nif callable(handler):\n    handler()",
        "if name.isidentifier():\n    getattr(self, name)()",
    ],
)
def test_a_module_a_prefix_or_a_check_of_the_shape_leaves_a_hotspot(body: str) -> None:
    (finding,) = injections(body)

    assert shape(finding)[:3] == ATTRIBUTE_CALL


@pytest.mark.parametrize(
    "body",
    [
        "if name in ('start', 'stop'):\n    getattr(self, name)()",
        "handler = getattr(self, name)\nif name in ('start', 'stop'):\n    handler()",
        "handler = getattr(self, name)\nif name == 'start':\n    handler()",
    ],
)
def test_a_check_against_constants_between_selection_and_invocation_proves_the_name(body: str) -> None:
    assert injections(body) == []


@pytest.mark.parametrize(
    "body",
    [
        # The name checked is another value than the one ``getattr`` received.
        "handler = getattr(self, name)\nname = 'start'\nif name in ('start', 'stop'):\n    handler()",
        "handler = getattr(self, name)\nname = input()\nif name in ('start', 'stop'):\n    handler()",
        "handler = getattr(self, name)\nchecked = name.strip()\nif checked in ('start', 'stop'):\n    handler()",
    ],
)
def test_a_check_on_another_value_than_the_selected_name_proves_nothing(body: str) -> None:
    (finding,) = injections(body)

    assert shape(finding)[:3] == ATTRIBUTE_CALL


@pytest.mark.parametrize(
    "body",
    [
        "eval(name)()",
        "result = eval(name)\nresult()\nresult(1)",
    ],
)
def test_an_unconditional_sink_whose_result_is_called_is_reported_once(body: str) -> None:
    (finding,) = injections(body)

    assert (finding.message.split(":", 1)[0], finding.span.start_line) == ("Code injection", 7)


HELPERS = {
    "app/__init__.py": "",
    "app/dispatch.py": (
        "def invoke(obj, name):\n"
        "    handler = getattr(obj, name)\n"
        "    handler()\n"
        "    handler(1)\n"
        "\n\n"
        "def forward(obj, name):\n"
        "    invoke(obj, name)\n"
        "\n\n"
        "def evaluate(code):\n"
        "    return eval(code)()\n"
    ),
    "app/views.py": (
        "from flask import request\n\nfrom app.dispatch import evaluate, forward, invoke\n\n\n"
        "class View:\n"
        "    def direct(self):\n"
        "        invoke(self, request.args['a'])\n\n"
        "    def nested(self):\n"
        "        forward(self, request.args['a'])\n\n"
        "    def code(self):\n"
        "        evaluate(request.args['c'])\n"
    ),
}


def project_findings(root: Path, **options: object) -> list[tuple[str, str, int, str | None, str | None]]:
    analysis = engine.analyze_project(root, [engine.BUNDLED_PLUGINS], **options)  # type: ignore[arg-type]
    return sorted(
        (
            f.function or "",
            f.message.split(":", 1)[0],
            f.span.start_line,
            f.metadata.get("sink_line"),
            f.metadata.get("invoked_line"),
        )
        for f in analysis.findings
        if f.rule_id == "code-injection"
    )


EXPECTED_THROUGH_HELPERS = [
    ("code", "Code injection", 14, "12", None),
    ("direct", "Untrusted attribute call", 8, "2", "3"),
    ("direct", "Untrusted attribute call", 8, "2", "4"),
    ("nested", "Untrusted attribute call", 11, "2", "3"),
    ("nested", "Untrusted attribute call", 11, "2", "4"),
]


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    return root


def test_helper_summaries_keep_the_selection_and_each_invocation(tmp_path: Path) -> None:
    root = write(tmp_path / "project", HELPERS)

    assert project_findings(root) == EXPECTED_THROUGH_HELPERS


@pytest.mark.parametrize("cached", [False, True], ids=["workers", "workers-and-warm-cache"])
def test_workers_and_the_cache_keep_every_invocation(tmp_path: Path, cached: bool) -> None:
    root = write(tmp_path / "project", HELPERS)
    cache = ProjectCache(tmp_path / "cache") if cached else None
    if cache is not None:
        engine.analyze_project(root, [engine.BUNDLED_PLUGINS], cache=cache)

    assert project_findings(root, jobs=2, cache=cache) == EXPECTED_THROUGH_HELPERS


MANIFEST = (
    'name = "getattr-sink"\nversion = "1.0.0"\nplugin_api = ">=1,<2"\nrequires = []\n'
    'provides = []\n\n[entrypoint]\nmodule = "getattr_sink"\nclass = "GetattrSink"\n'
)
# Another plugin declaring every ``getattr`` name a CODE sink, called or not.
PLUGIN = '''
from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import Sink, TaintKind


class GetattrSink(ModelPlugin):
    name: ClassVar[str] = "getattr-sink"
    models: ClassVar = (
        Sink(SymbolId("python.builtins.getattr"), TaintKind.CODE, ((TaintKind.CODE, (1,)),)),
    )
'''


@pytest.mark.parametrize("extra_first", [True, False], ids=["extra-plugin-first", "bundled-first"])
def test_an_unconditional_declaration_reports_at_the_selection_without_duplicate(tmp_path: Path, extra_first: bool) -> None:
    plugin = tmp_path / "plugins" / "getattr_sink"
    plugin.mkdir(parents=True)
    (plugin / "plugin.toml").write_text(MANIFEST, encoding="utf-8")
    (plugin / "getattr_sink.py").write_text(PLUGIN, encoding="utf-8")
    root = write(
        tmp_path / "project",
        {"app.py": "from flask import request\n\n\nclass View:\n    def run(self):\n        handler = getattr(self, request.args['a'])\n        handler()\n        handler(1)\n"},
    )
    roots = [tmp_path / "plugins", engine.BUNDLED_PLUGINS]

    findings = engine.analyze_project(root, roots if extra_first else roots[::-1]).findings

    assert [(f.span.start_line, f.metadata.get("invoked_line")) for f in findings if f.rule_id == "code-injection"] == [
        (6, None)
    ]


def test_the_command_line_reports_the_invocation(tmp_path: Path) -> None:
    root = write(tmp_path / "project", {"app.py": HEADER + "        getattr(self, name)()\n"})
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        main(["--check", str(root), "--format", "json"])

    (finding,) = [f for f in json.loads(out.getvalue())["findings"] if f["rule_id"] == "code-injection"]
    assert (finding["location"]["line"], finding["metadata"]["selected_line"], finding["metadata"]["invoked_line"]) == (
        7,
        "7",
        "7",
    )
