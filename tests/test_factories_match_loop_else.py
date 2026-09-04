"""Acceptance tests for the last gaps found on the ``tests-project/`` repositories.

- Factory instances: ``app = create_app()`` at module level, where ``create_app`` is a
  project function whose summary returns a ``Flask`` instance, makes ``app.route`` an
  entry point like ``app = Flask(__name__)`` does. One repository's routes were invisible.
- Loop ``else`` clauses run when the loop is exhausted without ``break``.
- ``match`` statements over literal patterns, wildcards, captures, or-patterns and
  guards lower to an ``if`` chain over a hidden subject; other patterns are reported.

Expected to remain red until ``While.orelse`` / ``For.orelse``, ``Match`` desugaring and
factory instances exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.ir.lowering import lower_module
from coretrace_python.ir.printer import format_module
from coretrace_python.source import SourceManager

try:
    from coretrace_python.taint.engine import factory_instances
except ImportError as error:  # pragma: no cover - red until factories land
    MISSING: Exception | None = error
else:
    MISSING = None
    if "orelse" not in nodes.For.__dataclass_fields__:
        MISSING = AttributeError("loops have no orelse")


@pytest.fixture(autouse=True)
def require_pass() -> None:
    if MISSING is not None:
        pytest.fail(f"factories, match and loop else are not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "plugins"


def check(text: str, name: str = "app.py") -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source(name, text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, int]]:
    return sorted((f.rule_id, f.span.start_line) for f in findings)


def project(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def hir(text: str) -> nodes.Module:
    return build_hir(SourceManager().add_source("s.py", text))


def printed(text: str) -> str:
    return format_module(lower_module(hir(text)))


# --------------------------------------------------------------------------- factory instances


FACTORY = (
    "import os\nfrom flask import Flask, request, send_file\n\n"
    "def create_app():\n    _app = Flask(__name__)\n    _app.config['X'] = 1\n    return _app\n\n"
    "app = create_app()\n\n"
    "@app.route('/img/<name>')\n"
    "def image(name):\n"
    "    return send_file(os.path.join('/srv/img', name + '.jpg'))\n"
)


def test_routes_of_a_factory_made_app_are_entry_points() -> None:
    assert rules(check(FACTORY)) == [("path-traversal", 13)]


def test_factory_instances_are_derived_from_return_externals() -> None:
    from coretrace_python.interprocedural import ProjectSummaries, SummaryAnalysis
    from coretrace_python.semantic.scopes import ScopeAnalysis
    from coretrace_python.semantic.symbols import SymbolAnalysis, SymbolId

    manager = engine.build_manager(hir(FACTORY))
    instances = factory_instances(
        manager.module,
        manager.get(ScopeAnalysis),
        manager.get(SymbolAnalysis),
        manager.get(SummaryAnalysis),
        manager.get(ProjectSummaries),
    )

    assert instances == {"app": (SymbolId("python.flask.Flask"),)}


def test_factories_defined_in_another_file_work_through_the_project_index(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "factory.py": "from flask import Flask\n\ndef create_app():\n    return Flask(__name__)\n",
            "app.py": (
                "import os\nfrom flask import send_file\nfrom factory import create_app\n\n"
                "app = create_app()\n\n"
                "@app.route('/img/<name>')\n"
                "def image(name):\n"
                "    return send_file(os.path.join('/srv/img', name))\n"
            ),
        },
    )
    findings = engine.analyze_project(root, [PLUGINS]).findings
    assert [(f.rule_id, Path(str(f.span.source_id)).name, f.span.start_line) for f in findings] == [
        ("path-traversal", "app.py", 9)
    ]


def test_factories_returning_nothing_known_create_no_entry_point() -> None:
    text = (
        "import os\n\ndef make():\n    return object()\n\napp = make()\n\n"
        "@app.route('/x/<name>')\ndef image(name):\n    os.system(name)\n"
    )
    assert check(text) == ()


# --------------------------------------------------------------------------- loop else


def test_loop_else_runs_only_when_the_loop_is_exhausted() -> None:
    module = hir("def f(items):\n    for item in items:\n        if item:\n            break\n    else:\n        return 'none'\n    return item\n")
    loop = module.body[0].body[0]  # type: ignore[union-attr]
    assert isinstance(loop, nodes.For) and len(loop.orelse) == 1

    text = printed("def f(items):\n    for item in items:\n        if item:\n            break\n    else:\n        return 'none'\n    return item\n")
    assert "for_next" in text and text.count("return") >= 2

    module = hir("def f(n):\n    while n:\n        n = n - 1\n    else:\n        n = 0\n    return n\n")
    loop = module.body[0].body[0]  # type: ignore[union-attr]
    assert isinstance(loop, nodes.While) and len(loop.orelse) == 1


def test_taint_reaches_the_else_clause_and_break_skips_it() -> None:
    findings = check(
        "import os\n\ndef f(items):\n    for item in items:\n        if item == 'stop':\n            break\n"
        "    else:\n        os.system(input())\n    return 1\n"
    )
    assert rules(findings) == [("command-injection", 8)]


# --------------------------------------------------------------------------- match


def test_match_over_literals_lowers_to_branches() -> None:
    text = printed(
        "def f(op, x):\n"
        "    match op:\n"
        "        case 'gray' | 'grey':\n            return 1\n"
        "        case 'png' if x:\n            return 2\n"
        "        case None:\n            return 3\n"
        "        case other:\n            return other\n"
    )
    assert text.count("branch") >= 4
    assert "compare.eq" in text


def test_match_binds_captures_and_flows_taint() -> None:
    findings = check(
        "import os\n\ndef f():\n    match input():\n        case 'ls':\n            os.system('ls')\n"
        "        case cmd:\n            os.system(cmd)\n"
    )
    assert rules(findings) == [("command-injection", 8)]


def test_match_wildcard_and_subject_taint() -> None:
    findings = check(
        "import os\n\ndef f(op):\n    cmd = input()\n    match op:\n        case 'run':\n            os.system(cmd)\n"
        "        case _:\n            pass\n"
    )
    assert rules(findings) == [("command-injection", 7)]


def test_unsupported_patterns_are_reported_per_function() -> None:
    findings = check("def f(p):\n    match p:\n        case [x, y]:\n            return x\n        case _:\n            return 0\n")
    assert [f.rule_id for f in findings] == ["unsupported-syntax"]
    assert "pattern" in findings[0].message


def test_the_image_editing_site_is_analysed(tmp_path: Path) -> None:
    text = (
        "import os\nfrom flask import Flask, request\nfrom werkzeug.utils import secure_filename\n\n"
        "app = Flask(__name__)\n\n"
        "def process(filename, operation):\n"
        "    match operation:\n"
        "        case 'cgray':\n            return filename + '.gray'\n"
        "        case 'cpng':\n            return filename + '.png'\n"
        "    return filename\n\n"
        "@app.route('/edit', methods=['POST'])\n"
        "def edit():\n"
        "    f = request.files['file']\n"
        "    name = secure_filename(f.filename)\n"
        "    f.save(os.path.join('/srv', name))\n"
        "    return process(name, request.form.get('operation'))\n"
    )
    assert check(text) == ()
