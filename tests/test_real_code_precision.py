"""Acceptance tests for precision gaps found by hand on the ``tests-project/`` repositories.

Reading the two true path traversals of ``uploadbox-cloud-storage-solution`` showed four
things around them: a third traversal missed because ``request.files['file'].save(...)``
resolves no symbol, a ``'logged_in' in session`` check the refutation engine did not
count as authorization, a secret assigned through ``app.config['SECRET_KEY']`` the secret
detector did not name, and a ``del`` statement that blocked a whole file elsewhere.

Expected to remain red until item symbols, membership authorization, subscript and
attribute credential names and ``del`` exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Confidence, Finding
from coretrace_python.frontend import build_hir
from coretrace_python.interprocedural import CallGraphAnalysis
from coretrace_python.ir.lowering import lower_module
from coretrace_python.ir.printer import format_module
from coretrace_python.plugins.secrets import literals
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager

try:
    from coretrace_python.hir.nodes import Delete
    from coretrace_python.ir.model import DelAttr, DelItem
except ImportError as error:  # pragma: no cover - red until del lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_precision() -> None:
    if MISSING is not None:
        pytest.fail(f"real-code precision pass is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("app.py", text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, int]]:
    return sorted((f.rule_id, f.span.start_line) for f in findings)


FLASK = "import os\nfrom flask import Flask, request, session, send_file\n\napp = Flask(__name__)\n\n"


# --------------------------------------------------------------------------- item symbols


def test_items_of_symbol_containers_carry_the_container_symbol() -> None:
    module = build_hir(
        SourceManager().add_source(
            "m.py", "from flask import request\n\ndef f():\n    stored = request.files['file']\n    stored.save('x')\n"
        )
    )
    graph = engine.build_manager(module).get(CallGraphAnalysis)
    (site,) = graph.sites("f")

    from coretrace_python.interprocedural import ExternalSymbol

    assert isinstance(site.target, ExternalSymbol)
    assert site.target.symbol == SymbolId("python.flask.request.files.save")


def test_uploaded_files_saved_under_their_own_name_are_path_traversals() -> None:
    findings = check(
        FLASK + "@app.route('/upload', methods=['POST'])\n"
        "def upload():\n"
        "    f = request.files['file']\n"
        "    f.save(os.path.join('/srv/files', session['email'], f.filename))\n"
        "    return 'ok'\n"
    )
    assert rules(findings) == [("path-traversal", 9)]


def test_secure_filename_sanitises_the_upload_name() -> None:
    findings = check(
        FLASK + "from werkzeug.utils import secure_filename\n\n"
        "@app.route('/upload', methods=['POST'])\n"
        "def upload():\n"
        "    f = request.files['file']\n"
        "    f.save(os.path.join('/srv/files', secure_filename(f.filename)))\n"
        "    return 'ok'\n"
    )
    assert findings == ()


# --------------------------------------------------------------------------- session authorization


def test_membership_in_the_session_is_an_authorization_guard() -> None:
    findings = check(
        FLASK + "@app.route('/delete', methods=['POST'])\n"
        "def delete():\n"
        "    name = request.get_json()['filename']\n"
        "    if 'logged_in' in session:\n"
        "        os.remove(os.path.join('/srv/files', name))\n"
        "    return 'ok'\n"
    )
    (finding,) = findings
    assert finding.rule_id == "path-traversal"
    assert finding.confidence is Confidence.MEDIUM
    assert finding.metadata["verdict"] == "hotspot"
    assert finding.metadata["evidence"] == "behind authorization (session) at line 9"


def test_early_return_on_missing_session_counts_too() -> None:
    findings = check(
        FLASK + "@app.route('/delete', methods=['POST'])\n"
        "def delete():\n"
        "    if 'logged_in' not in session:\n"
        "        return 'no'\n"
        "    os.remove(request.get_json()['filename'])\n"
    )
    (finding,) = findings
    assert finding.metadata["verdict"] == "hotspot"


def test_unrelated_membership_checks_are_ordinary_guards() -> None:
    findings = check(
        FLASK + "@app.route('/delete', methods=['POST'])\n"
        "def delete():\n"
        "    name = request.get_json()['filename']\n"
        "    if 'x' in name:\n"
        "        os.remove(name)\n"
    )
    (finding,) = findings
    assert finding.metadata["verdict"] == "hotspot"
    assert "authorization" not in finding.metadata["evidence"]


# --------------------------------------------------------------------------- credential names


def test_credentials_bound_through_subscripts_and_attributes_are_named() -> None:
    module = build_hir(
        SourceManager().add_source(
            "settings.py",
            "app.config['SECRET_KEY'] = 'find@me1290'\n"
            "class Client:\n    def __init__(self):\n        self.password = 'hunter2'\n"
            "options[0] = 'positional'\n",
        )
    )

    found = [(value, name) for value, name, _, _ in literals(module)]

    assert found == [("find@me1290", "SECRET_KEY"), ("hunter2", "password"), ("positional", None)]
    findings = check("app = object()\napp.config['SECRET_KEY'] = 'find@me1290'\n")
    assert [(f.rule_id, f.metadata["name"]) for f in findings] == [("hardcoded-credential", "SECRET_KEY")]


# --------------------------------------------------------------------------- del


def test_del_statements_lower_to_delete_effects() -> None:
    module = build_hir(
        SourceManager().add_source("d.py", "def f(d, obj, x):\n    del d['k'], obj.attr\n    del x\n    return d\n")
    )
    statement = module.body[0].body[0]  # type: ignore[union-attr]
    assert isinstance(statement, Delete) and len(statement.targets) == 2

    function = lower_module(module).functions[0]
    effects = [i for b in function.blocks for i in b.instructions if isinstance(i, DelItem | DelAttr)]
    assert [type(i).__name__ for i in effects] == ["DelItem", "DelAttr"]
    text = format_module(lower_module(module))
    assert "del_item" in text and 'del_attr %1, "attr"' in text


def test_del_does_not_block_a_file() -> None:
    findings = check("import os\n\ndef f(cache):\n    del cache['x']\n    os.system(input())\n")
    assert rules(findings) == [("command-injection", 5)]
