"""Acceptance tests for operator-controlled sources (issue #71).

Environment variables and the output of local processes are set by whoever runs the
program, not by a remote attacker: like ``argv`` they are sources, since they may carry a
URL to fetch or a statement to run, but a command or a path built from them is the
operator's own doing (luigi's cluster wrappers, httpie's daemon). The environment does
not carry ``COMMAND`` or ``PATH``; process output does not carry ``PATH`` but keeps
``COMMAND``, since piping a downloaded script into a shell is a real vulnerability.
A credential-like name followed by ``_type``, ``_scheme`` or the like names a kind of
credential, not one.

Expected to remain red until the stdlib models restrict those sources.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import TaintKind

REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"


def source_kinds(symbol: str) -> TaintKind:
    manager = engine.build_manager(engine.build_hir(SourceManager().add_source("e.py", "")))
    table = engine.plugin_models(l.plugin for l in engine.load_plugins([PLUGINS], manager))
    return table.source(SymbolId(f"python.{symbol}")).kinds  # type: ignore[union-attr]


MISSING = None if not source_kinds("os.environ") & TaintKind.COMMAND else "environment still carries COMMAND"


@pytest.fixture(autouse=True)
def require_operator_sources() -> None:
    if MISSING is not None:
        pytest.fail(f"operator-controlled sources are not modelled yet: {MISSING}")


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("m.py", text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[str]:
    return sorted(f.rule_id for f in findings)


def test_source_kinds_reflect_who_controls_them() -> None:
    assert source_kinds("os.environ") == TaintKind.ALL & ~(TaintKind.COMMAND | TaintKind.PATH)
    assert source_kinds("subprocess.check_output") == TaintKind.ALL & ~TaintKind.PATH
    assert source_kinds("sys.argv") == TaintKind.ALL & ~TaintKind.PATH
    assert source_kinds("builtins.input") == TaintKind.ALL


def test_environment_does_not_inject_commands_or_paths_but_still_reaches_urls_and_statements() -> None:
    assert check("import os\n\ndef run():\n    os.system(os.environ['CMD'])\n") == ()
    assert check("import os\n\ndef run():\n    open(os.environ['CONFIG']).read()\n") == ()
    assert rules(check("import os\nfrom urllib.request import urlopen\n\ndef run():\n    urlopen(os.environ['TARGET'])\n")) == ["ssrf"]
    assert rules(
        check("import os\nimport sqlite3\n\ndef run():\n    sqlite3.connect('db').cursor().execute(os.environ['QUERY'])\n")
    ) == ["sql-injection"]


def test_process_output_does_not_traverse_paths_but_still_injects_commands() -> None:
    assert check("import subprocess\n\ndef run():\n    open(subprocess.check_output(['pwd']).strip())\n") == ()
    assert rules(check("import os\nimport subprocess\n\ndef run():\n    os.system(subprocess.check_output(['ls']))\n")) == [
        "command-injection"
    ]


def test_names_of_credential_kinds_are_not_credentials() -> None:
    assert check("token_type = 'bearer'\nauth_scheme = 'Bearer'\nhash_algorithm = 'sha256'\npassword_kind = 'plain'\n") == ()
    assert rules(check("token = 'bearer-abcdef123456'\n")) == ["hardcoded-credential"]
