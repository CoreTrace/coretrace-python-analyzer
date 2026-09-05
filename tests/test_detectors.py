"""Acceptance tests for the first detectors (``docs/architecture.md`` §15, §25, §35, §36).

Detectors consume generic facts. Two reusable bases live in the plugin API:
``TaintDetector`` turns the flows of one taint kind into findings, and
``SymbolCallDetector`` reports calls resolving to a set of canonical symbols. Any plugin
may contribute security models through ``Plugin.models``; the engine collects them from
every loaded plugin before providing the table, so a model plugin and a detector plugin
compose without knowing each other.

Shipped under ``plugins/``: a ``python-stdlib`` model plugin, the ``sql-injection``,
``command-injection``, ``path-traversal``, ``ssrf`` and ``xss`` taint detectors, and the
``dangerous-eval`` and ``weak-crypto`` syntax detectors.

Expected to remain red until the detector bases, ``Plugin.models`` and the shipped
plugins exist.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

import pytest

from coretrace_python import engine
from coretrace_python.cli import main
from coretrace_python.findings import Finding, Severity
from coretrace_python.plugins import Plugin, discover_plugins, run_plugins
from coretrace_python.reporters import render_sarif
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import SecurityModelRegistry, Sink, Source, TaintKind

try:
    from coretrace_python.plugins import ModelPlugin, SymbolCallDetector, TaintDetector
except ImportError as error:  # pragma: no cover - red until detector bases land
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_detectors() -> None:
    if MISSING is not None:
        pytest.fail(f"detector bases are not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"


def check(source_text: str, *extra_roots: Path, name: str = "app.py") -> tuple[Finding, ...]:
    source = SourceManager().add_source(name, source_text)
    return engine.check(source, [PLUGINS, *extra_roots])


def rules(findings: tuple[Finding, ...]) -> list[str]:
    return [f.rule_id for f in findings]


# --------------------------------------------------------------------------- bases


if MISSING is None:

    class CommandFlows(TaintDetector):
        name: ClassVar[str] = "test.command"
        rule_id: ClassVar[str] = "test-command"
        kind: ClassVar[TaintKind] = TaintKind.COMMAND
        severity: ClassVar[Severity] = Severity.CRITICAL
        title: ClassVar[str] = "Command injection"

    class SqlFlows(TaintDetector):
        name: ClassVar[str] = "test.sql"
        rule_id: ClassVar[str] = "test-sql"
        kind: ClassVar[TaintKind] = TaintKind.SQL
        severity: ClassVar[Severity] = Severity.HIGH
        title: ClassVar[str] = "SQL injection"

    class PrintCalls(SymbolCallDetector):
        name: ClassVar[str] = "test.print"
        rule_id: ClassVar[str] = "test-print"
        symbols: ClassVar[frozenset[SymbolId]] = frozenset({SymbolId("python.builtins.print")})
        severity: ClassVar[Severity] = Severity.INFO
        message_template: ClassVar[str] = "call to {symbol}"

    class WebModels(ModelPlugin):
        name: ClassVar[str] = "test.web-models"
        models = (
            Source(SymbolId("python.web.param"), "http"),
            Sink(SymbolId("python.db.execute"), TaintKind.SQL),
            Sink(SymbolId("python.web.render"), TaintKind.HTML),
        )


def manager_with_models(source_text: str):  # type: ignore[no-untyped-def]
    registry = SecurityModelRegistry()
    registry.register(*WebModels.models, Sink(SymbolId("python.os.system"), TaintKind.COMMAND))
    module = engine.build_hir(SourceManager().add_source("app.py", source_text))
    return engine.build_manager(module, registry)


def test_taint_detector_reports_flows_of_its_kind_only() -> None:
    manager = manager_with_models(
        "import os\nimport db\nfrom web import param\n\n"
        "def run():\n"
        "    value = param('x')\n"
        "    os.system(value)\n"
        "    db.execute(value)\n"
    )

    findings = run_plugins(manager, [CommandFlows(), SqlFlows()])

    assert rules(findings) == ["test-command", "test-sql"]
    command = findings[0]
    assert command.severity is Severity.CRITICAL
    assert command.span.start_line == 7
    assert command.function == "run"
    assert command.message == "Command injection: http input reaches python.os.system"
    assert dict(command.metadata) == {
        "source": "python.web.param",
        "source_label": "http",
        "sink": "python.os.system",
        "verdict": "vulnerability",
        "evidence": "no guard on the path to the sink",
    }


def test_taint_detector_declares_taint_and_refutation() -> None:
    from coretrace_python.findings.refutation import RefutationAnalysis
    from coretrace_python.taint import TaintAnalysis

    assert CommandFlows.requires == frozenset({TaintAnalysis, RefutationAnalysis})


def test_symbol_call_detector_reports_resolved_calls() -> None:
    manager = manager_with_models("def f(x):\n    print(x)\n    show = print\n    show(x)\n")

    findings = run_plugins(manager, [PrintCalls()])

    assert [(f.rule_id, f.span.start_line, f.message) for f in findings] == [
        ("test-print", 2, "call to python.builtins.print"),
        ("test-print", 4, "call to python.builtins.print"),
    ]
    assert findings[0].severity is Severity.INFO


def test_plugins_may_carry_models_and_model_plugins_report_nothing() -> None:
    assert Plugin.models == ()
    assert len(WebModels.models) == 3
    manager = manager_with_models("def f():\n    pass\n")
    assert run_plugins(manager, [WebModels()]) == ()


# --------------------------------------------------------------------------- shipped plugins


def test_shipped_plugins_load_with_their_manifests() -> None:
    module = engine.build_hir(SourceManager().add_source("empty.py", ""))
    loaded = discover_plugins(PLUGINS, engine.build_manager(module))
    by_name = {plugin.manifest.name: plugin.manifest for plugin in loaded}

    assert set(by_name) == {
        "cli-models",
        "command-injection",
        "config-secrets",
        "credential-models",
        "dangerous-eval",
        "dependency-policy",
        "django-models",
        "fastapi-models",
        "flask-debug",
        "flask-models",
        "hardcoded-secrets",
        "http-client-models",
        "insecure-deserialization",
        "missing-timeout",
        "open-redirect",
        "path-traversal",
        "plaintext-credentials",
        "python-stdlib-models",
        "reachable-vulnerability",
        "sample-advisories",
        "sql-injection",
        "sqlalchemy-models",
        "ssrf",
        "vulnerable-dependency",
        "weak-crypto",
        "xss",
    }
    for rule in ("sql-injection", "command-injection", "path-traversal", "ssrf", "xss"):
        assert by_name[rule].requires == ("taint.flows", "findings.refutation")
        assert by_name[rule].provides == (f"vulnerability.{rule}",)
    assert by_name["python-stdlib-models"].provides == ("model.python-stdlib",)
    assert by_name["weak-crypto"].provides == ("vulnerability.weak-crypto",)


def test_stdin_to_os_system_is_a_command_injection() -> None:
    findings = check("import os\n\ndef run():\n    cmd = input()\n    os.system(cmd)\n")

    assert rules(findings) == ["command-injection"]
    assert findings[0].severity is Severity.HIGH
    assert findings[0].span.start_line == 5
    assert findings[0].metadata["source_label"] == "stdin"


def test_shlex_quote_sanitizes_command_arguments() -> None:
    findings = check(
        "import os\nimport shlex\n\ndef run():\n    cmd = shlex.quote(input())\n    os.system(cmd)\n"
    )
    assert findings == ()


def test_stdin_to_open_is_a_path_traversal_but_argv_is_not() -> None:
    findings = check("def read():\n    return open(input())\n")
    assert rules(findings) == ["path-traversal"]
    # A command-line tool is expected to open the paths it is given.
    assert check("import sys\n\ndef read():\n    return open(sys.argv[1])\n") == ()


def test_environment_to_urlopen_is_ssrf() -> None:
    findings = check(
        "import os\nfrom urllib.request import urlopen\n\n"
        "def fetch():\n    return urlopen(os.environ['TARGET'])\n"
    )
    assert rules(findings) == ["ssrf"]


def test_one_flow_produces_one_finding() -> None:
    findings = check("import subprocess\n\ndef run():\n    subprocess.run(input())\n")
    assert rules(findings) == ["command-injection"]


def test_weak_hashes_are_reported() -> None:
    findings = check(
        "import hashlib\n\ndef digest(data):\n    a = hashlib.md5(data)\n    b = hashlib.sha1(data)\n    return hashlib.sha256(data)\n"
    )

    assert rules(findings) == ["weak-crypto", "weak-crypto"]
    assert [f.span.start_line for f in findings] == [4, 5]
    assert findings[0].severity is Severity.MEDIUM
    assert "python.hashlib.md5" in findings[0].message


def test_dangerous_eval_still_reports_syntactically() -> None:
    findings = check("def run(code):\n    eval(code)\n")
    assert rules(findings) == ["dangerous-eval"]


# --------------------------------------------------------------------------- composition


def write_model_plugin(directory: Path) -> Path:
    plugin_dir = directory / "web_models"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.toml").write_text(
        'name = "web-models"\nversion = "1.0.0"\nplugin_api = ">=1,<2"\n'
        'requires = []\nprovides = ["model.http-sources", "model.sql-sinks", "model.html-sinks"]\n\n'
        '[entrypoint]\nmodule = "web_models"\nclass = "WebModels"\n',
        encoding="utf-8",
    )
    (plugin_dir / "web_models.py").write_text(
        "from typing import ClassVar\n\n"
        "from coretrace_python.plugins import ModelPlugin\n"
        "from coretrace_python.semantic.symbols import SymbolId\n"
        "from coretrace_python.taint import Sink, Source, TaintKind\n\n\n"
        "class WebModels(ModelPlugin):\n"
        '    name: ClassVar[str] = "web-models"\n'
        "    models = (\n"
        '        Source(SymbolId("python.web.param"), "http"),\n'
        '        Sink(SymbolId("python.db.execute"), TaintKind.SQL),\n'
        '        Sink(SymbolId("python.web.render"), TaintKind.HTML),\n'
        "    )\n",
        encoding="utf-8",
    )
    return directory


def test_model_plugins_compose_with_detectors(tmp_path: Path) -> None:
    findings = check(
        "import db\nfrom web import param, render\n\n"
        "def lookup():\n"
        "    ident = param('id')\n"
        "    db.execute('SELECT * FROM users WHERE id = ' + ident)\n"
        "    render('<b>' + ident + '</b>')\n",
        write_model_plugin(tmp_path),
    )

    assert rules(findings) == ["sql-injection", "xss"]
    assert [f.span.start_line for f in findings] == [6, 7]


def test_without_the_model_plugin_the_same_code_is_silent() -> None:
    findings = check(
        "import db\nfrom web import param\n\n"
        "def lookup():\n    db.execute('SELECT ' + param('id'))\n"
    )
    assert findings == ()


def test_end_to_end_sarif_report(tmp_path: Path) -> None:
    findings = check(
        "import db\nfrom web import param\n\ndef lookup():\n    db.execute(param('id'))\n",
        write_model_plugin(tmp_path),
        name="routes.py",
    )

    document = json.loads(render_sarif(engine.report(findings)))
    (result,) = document["runs"][0]["results"]

    assert result["ruleId"] == "sql-injection"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "routes.py"


def test_cli_reports_taint_findings(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = tmp_path / "run.py"
    source.write_text("import os\n\ndef run():\n    os.system(input())\n", encoding="utf-8")

    exit_code = main(["--check", str(source), "--plugins", str(PLUGINS)])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert output.startswith("run.py:4:5: high command-injection: Command injection: stdin input reaches python.os.system [run]\n")
