"""Acceptance tests for plaintext credential storage, the last actionable point of the
``tests-project/SECURITY_AUDIT.md`` review (``uploadbox/db.py:24``).

A ``CREDENTIAL`` taint kind, outside ``TaintKind.ALL`` so ordinary sources never carry it,
is sourced by a ``NamedParameter`` model (parameters named ``password`` and the like),
sinks into database writes and is cleared by password hashing functions. The detector
reports at medium confidence by construction: a name is a hint, not a proof. The audit's
own case stores through ``get_db().execute(...)``, a connection returned by a project
function, so calls on what a known function returns resolve through its summary.

Expected to remain red until ``TaintKind.CREDENTIAL``, ``NamedParameter`` and the
``models/credentials`` and ``security/plaintext_credentials`` plugins exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.frontend import build_hir
from coretrace_python.plugins import discover_plugins
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import SecurityModelRegistry, Sink, TaintKind

try:
    from coretrace_python.taint import NamedParameter
except ImportError as error:  # pragma: no cover - red until the model lands
    MISSING: Exception | None = error
else:
    MISSING = None
    if not hasattr(TaintKind, "CREDENTIAL"):
        MISSING = AttributeError("TaintKind has no CREDENTIAL")


@pytest.fixture(autouse=True)
def require_credentials() -> None:
    if MISSING is not None:
        pytest.fail(f"plaintext credential detection is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "plugins"


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("db.py", "import sqlite3\n\n" + text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, int]]:
    return sorted((f.rule_id, f.span.start_line) for f in findings)


REGISTER = (
    "def register_user(email, password):\n"
    "    conn = sqlite3.connect('app.db')\n"
    "    conn.execute('insert into users(email, password) values(?, ?)', (email, password))\n"
)


# --------------------------------------------------------------------------- model


def test_credential_kind_is_outside_the_default_set() -> None:
    assert TaintKind.CREDENTIAL & TaintKind.ALL == TaintKind.NONE
    assert TaintKind.CREDENTIAL & TaintKind.SQL == TaintKind.NONE


def test_named_parameters_are_indexed_and_extended() -> None:
    named = NamedParameter(r"(?i)^(password|passwd)$", "credential", TaintKind.CREDENTIAL)
    registry = SecurityModelRegistry()
    registry.register(named, Sink(SymbolId("python.db.write"), TaintKind.CREDENTIAL))
    table = registry.freeze()

    assert table.named_parameters == (named,)
    assert named.matches("password") and named.matches("PASSWD") and not named.matches("password_hash")
    assert table.extended(Sink(SymbolId("python.x"), TaintKind.ADVISORY)).named_parameters == (named,)


def test_named_parameters_are_credential_sources() -> None:
    from coretrace_python.semantic.scopes import ScopeAnalysis
    from coretrace_python.semantic.symbols import SymbolAnalysis
    from coretrace_python.taint import SecurityModelAnalysis
    from coretrace_python.taint.engine import parameter_sources

    module = build_hir(SourceManager().add_source("m.py", "def f(name, password):\n    return password\n"))
    registry = SecurityModelRegistry()
    registry.register(NamedParameter(r"(?i)^password$", "credential", TaintKind.CREDENTIAL))
    manager = engine.build_manager(module, registry)
    function = module.body[0]
    assert isinstance(function, type(module.body[0]))

    sources = parameter_sources(function, module, manager.get(SecurityModelAnalysis), manager.get(ScopeAnalysis), manager.get(SymbolAnalysis))  # type: ignore[arg-type]

    assert list(sources) == [1]
    assert sources[1].label == "credential" and sources[1].kinds == TaintKind.CREDENTIAL


# --------------------------------------------------------------------------- detector


def test_storing_a_password_parameter_unhashed_is_reported_at_medium_confidence() -> None:
    (finding,) = check(REGISTER)

    assert finding.rule_id == "plaintext-credential-storage"
    assert finding.span.start_line == 5
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.MEDIUM
    assert finding.metadata["source_label"] == "credential"


@pytest.mark.parametrize(
    "hashing",
    [
        "from werkzeug.security import generate_password_hash\n",
        "import hashlib\n",
        "import bcrypt\n",
        "from argon2 import PasswordHasher\n",
    ],
)
def test_hashed_passwords_are_not_reported(hashing: str) -> None:
    hashed = {
        "from werkzeug.security import generate_password_hash\n": "generate_password_hash(password)",
        "import hashlib\n": "hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt', 100000)",
        "import bcrypt\n": "bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
        "from argon2 import PasswordHasher\n": "PasswordHasher().hash(password)",
    }[hashing]
    findings = check(
        hashing + "\ndef register_user(email, password):\n"
        f"    digest = {hashed}\n"
        "    conn = sqlite3.connect('app.db')\n"
        "    conn.execute('insert into users(email, password) values(?, ?)', (email, digest))\n"
    )
    assert [f.rule_id for f in findings] == []


def test_http_input_reaching_a_database_is_not_a_credential_finding() -> None:
    findings = check(
        "from flask import Flask, request\n\napp = Flask(__name__)\n\n"
        "@app.route('/u')\n"
        "def create():\n"
        "    conn = sqlite3.connect('app.db')\n"
        "    conn.execute(\"insert into users(name) values('\" + request.args['name'] + \"')\")\n"
    )
    assert rules(findings) == [("sql-injection", 10)]


def test_calls_on_what_a_known_function_returns_resolve_through_its_summary() -> None:
    findings = check(
        "DATABASE = 'app.db'\n\n"
        "def get_db():\n    return sqlite3.connect(DATABASE)\n\n"
        "def register_user(email, password):\n"
        "    cur = get_db().execute('insert into users(email, password) values(?, ?)', (email, password))\n"
        "    return cur\n"
    )
    assert rules(findings) == [("plaintext-credential-storage", 9)]


def test_other_parameters_and_reads_stay_clean() -> None:
    assert check("def find_user(email):\n    conn = sqlite3.connect('app.db')\n    conn.execute('select * from users where email=?', (email,))\n") == ()
    assert check("def login(email, password):\n    conn = sqlite3.connect('app.db')\n    return conn.execute('select 1 from users where email=?', (email,))\n") == ()


def test_shipped_credential_plugins_load() -> None:
    module = build_hir(SourceManager().add_source("empty.py", ""))
    loaded = {p.manifest.name: p.manifest for p in discover_plugins(PLUGINS, engine.build_manager(module))}

    assert loaded["credential-models"].provides == ("model.credential-sources", "model.credential-sinks")
    assert loaded["plaintext-credentials"].provides == ("vulnerability.plaintext-credential-storage",)


def test_getters_returning_several_symbols_pick_the_one_a_model_knows() -> None:
    # uploadbox's ``get_db``: ``getattr(g, '_database', None)`` or a fresh connection.
    findings = check(
        "from flask import g\n\nDATABASE = 'app.db'\n\n"
        "def get_db():\n"
        "    db = getattr(g, '_database', None)\n"
        "    if db is None:\n"
        "        db = g._database = sqlite3.connect(DATABASE)\n"
        "    return db\n\n"
        "def register_user(email, password):\n"
        "    cur = get_db().execute('insert into users(email, password) values(?, ?)', (email, password))\n"
        "    return cur\n"
    )
    assert rules(findings) == [("plaintext-credential-storage", 14)]
