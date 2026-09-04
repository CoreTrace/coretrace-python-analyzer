"""Acceptance tests for what the FastAPI and command-line repositories under
``tests-project/`` showed: ``Vulnerable_fastapi``, ``InsecureGram`` and ``yt-fts``.

- A method on what a project function returns resolves through that function's summary
  even when the call graph already derived a project symbol for it
  (``get_conn().execute`` in another file was ``app.database.get_conn.execute``).
- SQL sinks read the statement only: a tainted value in the parameter tuple of a
  parameterised query is not an injection. ``Sink.positions`` restricts kinds to
  argument positions; unrestricted kinds keep every argument.
- An annotated parameter denotes its class, so ``db: Session = Depends(get_db)`` gives
  ``db.execute`` and ``sqlalchemy.text`` their sinks.
- Two new kinds with their sinks and detectors: ``DESERIALIZATION`` (``pickle``,
  ``marshal``, ``yaml``) and ``REDIRECT`` (Flask, Django, FastAPI redirects).
- Command-line entry points: ``click.command``, ``click.group`` and the commands of a
  group or a Typer application, whose parameters are ``argv`` input; a function decorated
  by a symbol is an instance of that symbol, so ``@cli.command()`` resolves.

Expected to remain red until ``Sink.positions``, the two kinds, the ``models/cli`` plugin
and the two detectors exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.interprocedural import CallGraphAnalysis
from coretrace_python.plugins import discover_plugins
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import SecurityModelRegistry, Sink, TaintKind

MISSING: Exception | None = None
if "positions" not in Sink.__dataclass_fields__:
    MISSING = AttributeError("Sink has no positions")
elif not hasattr(TaintKind, "DESERIALIZATION") or not hasattr(TaintKind, "REDIRECT"):
    MISSING = AttributeError("TaintKind lacks DESERIALIZATION or REDIRECT")


@pytest.fixture(autouse=True)
def require_pass() -> None:
    if MISSING is not None:
        pytest.fail(f"FastAPI and CLI precision pass is not implemented yet: {MISSING}")


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


FLASK = "import os\nimport sqlite3\nfrom flask import Flask, request, redirect\n\napp = Flask(__name__)\n\n"
FASTAPI = "from fastapi import APIRouter, Depends, Query\n\nrouter = APIRouter()\n\n"


# --------------------------------------------------------------------------- returned symbols


def test_methods_on_project_function_results_resolve_across_files(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "database.py": "import sqlite3\n\ndef get_conn():\n    conn = sqlite3.connect('x.db')\n    conn.row_factory = sqlite3.Row\n    return conn\n",
            "auth.py": (
                "from fastapi import APIRouter, Form\nfrom database import get_conn\n\nrouter = APIRouter()\n\n"
                "@router.post('/login')\n"
                "def login(username: str = Form(...)):\n"
                "    conn = get_conn()\n"
                "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
                "    return conn.execute(query).fetchone()\n"
            ),
        },
    )
    findings = engine.analyze_project(root, [PLUGINS]).findings
    assert [(f.rule_id, Path(str(f.span.source_id)).name, f.span.start_line) for f in findings] == [
        ("sql-injection", "auth.py", 10)
    ]


# --------------------------------------------------------------------------- sink positions


def test_sinks_restrict_kinds_to_argument_positions() -> None:
    sink = Sink(SymbolId("python.db.execute"), TaintKind.SQL | TaintKind.CREDENTIAL, positions=((TaintKind.SQL, (0,)),))

    assert sink.kinds_at(0) == TaintKind.SQL | TaintKind.CREDENTIAL
    assert sink.kinds_at(1) == TaintKind.CREDENTIAL
    assert sink.kinds_at(None) == TaintKind.CREDENTIAL
    assert Sink(SymbolId("python.os.system"), TaintKind.COMMAND).kinds_at(3) == TaintKind.COMMAND
    registry = SecurityModelRegistry()
    registry.register(sink)
    extended = registry.freeze().extended(Sink(SymbolId("python.db.execute"), TaintKind.ADVISORY))
    merged = extended.sink(SymbolId("python.db.execute"))
    assert merged is not None and merged.kinds_at(1) == TaintKind.CREDENTIAL | TaintKind.ADVISORY


def test_parameterised_queries_are_not_injections() -> None:
    findings = check(
        FLASK + "@app.route('/u')\n"
        "def user():\n"
        "    conn = sqlite3.connect('app.db')\n"
        "    conn.execute('SELECT * FROM users WHERE name = ?', (request.args['name'],))\n"
        "    conn.execute('SELECT * FROM users WHERE name = ' + request.args['name'])\n"
        "    conn.execute('SELECT 1', parameters=(request.args['name'],))\n"
    )
    assert rules(findings) == [("sql-injection", 11)]


def test_credentials_in_the_parameter_tuple_are_still_seen() -> None:
    findings = check(
        "import sqlite3\n\ndef register(email, password):\n    conn = sqlite3.connect('app.db')\n"
        "    conn.execute('INSERT INTO users VALUES (?, ?)', (email, password))\n"
    )
    assert rules(findings) == [("plaintext-credential-storage", 5)]


# --------------------------------------------------------------------------- annotated parameters


def test_annotated_parameters_denote_their_class() -> None:
    module = build_hir(
        SourceManager().add_source(
            "m.py", "from sqlalchemy.orm import Session\n\ndef f(db: Session, other):\n    return db.execute('x')\n"
        )
    )
    manager = engine.build_manager(module)
    graph = manager.get(CallGraphAnalysis)
    function = module.body[1]
    assert isinstance(function, nodes.Function)
    from coretrace_python.ir.ssa import SSAAnalysis

    ssa = manager.get(SSAAnalysis, function)
    symbols = graph.symbols("f")

    assert symbols[ssa.parameters[0]] == SymbolId("python.sqlalchemy.orm.Session")
    assert ssa.parameters[1] not in symbols
    (site,) = graph.sites("f")
    from coretrace_python.interprocedural import ExternalSymbol

    assert isinstance(site.target, ExternalSymbol) and site.target.symbol == SymbolId("python.sqlalchemy.orm.Session.execute")


def test_fastapi_dependency_sessions_and_text_are_sql_sinks() -> None:
    findings = check(
        FASTAPI + "from sqlalchemy.orm import Session\nfrom sqlalchemy import text\nfrom database import get_db\n\n"
        "@router.get('/search')\n"
        "def search(field: str = 'username', keyword: str = '', db: Session = Depends(get_db)):\n"
        "    db.query(text(f'LOWER({field}) LIKE :kw')).params(kw=f'%{keyword}%')\n"
        "    raw_sql = f\"SELECT username FROM users WHERE {field} = '{keyword}'\"\n"
        "    return db.execute(text(raw_sql)).fetchall()\n"
    )
    assert rules(findings) == [("sql-injection", 11), ("sql-injection", 13)]


# --------------------------------------------------------------------------- deserialization and redirects


def test_new_kinds_are_part_of_all() -> None:
    assert TaintKind.DESERIALIZATION & TaintKind.ALL
    assert TaintKind.REDIRECT & TaintKind.ALL


def test_untrusted_pickle_and_yaml_are_insecure_deserialization() -> None:
    findings = check(
        FASTAPI + "import pickle\nimport json\nimport yaml\nfrom pydantic import BaseModel\n\n"
        "class Payload(BaseModel):\n    payload: str\n\n"
        "@router.post('/deserialize')\n"
        "async def deserialize(data: Payload, raw: str = Query('')):\n"
        "    obj = pickle.loads(bytes.fromhex(data.payload))\n"
        "    doc = yaml.load(raw)\n"
        "    safe = json.loads(raw)\n"
        "    return obj, doc, safe\n"
    )
    assert rules(findings) == [("insecure-deserialization", 15), ("insecure-deserialization", 16)]
    assert all(f.metadata["source_label"] == "http" for f in findings)


def test_user_controlled_redirects_are_open_redirects() -> None:
    findings = check(
        FLASK + "@app.route('/go')\n"
        "def go():\n"
        "    return redirect(request.args['next'])\n\n"
        "@app.route('/home')\n"
        "def home():\n"
        "    return redirect('/dashboard')\n"
    )
    assert rules(findings) == [("open-redirect", 9)]
    findings = check(
        FASTAPI + "from fastapi.responses import RedirectResponse\n\n"
        "@router.get('')\n"
        "def redirect_to(target: str = Query(...)):\n"
        "    return RedirectResponse(url=target)\n"
    )
    assert rules(findings) == [("open-redirect", 9)]


# --------------------------------------------------------------------------- command-line entry points


def test_click_commands_receive_argv_input() -> None:
    findings = check(
        "import os\nimport click\n\n"
        "@click.command()\n@click.argument('url')\n"
        "def download(url):\n    os.system('yt-dlp ' + url)\n\n"
        "def helper(url):\n    os.system(url)\n"
    )
    (finding,) = findings
    assert (finding.rule_id, finding.span.start_line, finding.metadata["source_label"]) == ("command-injection", 7, "argv")


def test_command_line_tools_may_open_the_paths_they_are_given() -> None:
    assert check("import sys\nimport click\n\n@click.command()\n@click.argument('path')\ndef export(path):\n    open(path).read()\n    open(sys.argv[1]).read()\n") == ()


def test_group_commands_and_typer_apps_are_entry_points() -> None:
    assert rules(
        check(
            "import os\nimport click\n\n"
            "@click.group()\ndef cli():\n    pass\n\n"
            "@cli.command()\n@click.argument('name')\n"
            "def run(name):\n    os.system(name)\n"
        )
    ) == [("command-injection", 11)]
    assert rules(
        check("import os\nimport typer\n\napp = typer.Typer()\n\n@app.command()\ndef run(name: str):\n    os.system(name)\n")
    ) == [("command-injection", 8)]


def test_shipped_cli_models_and_detectors_load() -> None:
    module = build_hir(SourceManager().add_source("empty.py", ""))
    loaded = {p.manifest.name: p.manifest for p in discover_plugins(PLUGINS, engine.build_manager(module))}

    assert loaded["cli-models"].provides == ("model.cli-sources",)
    assert loaded["insecure-deserialization"].provides == ("vulnerability.insecure-deserialization",)
    assert loaded["open-redirect"].provides == ("vulnerability.open-redirect",)
