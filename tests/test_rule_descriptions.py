"""Acceptance tests: the SARIF log describes every rule it lists (#270).

A rule's title and description belong to whoever defines the rule: a plugin declares those
of the rules it reports, bundled or third-party; the engine those of its own notes. They
travel with the analysis to the report. A plugin that declares nothing still loads and
reports, its rules listed by id alone.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

from coretrace_python.cli import main

MANIFEST = (
    'name = "{name}"\nversion = "1.0.0"\nplugin_api = ">=1,<2"\n'
    'requires = ["ir.ssa"]\nprovides = []\n\n'
    '[entrypoint]\nmodule = "{module}"\nclass = "{cls}"\n'
)

DESCRIBED = """
from typing import ClassVar

from coretrace_python.findings import Severity
from coretrace_python.findings.rules import RuleDescription
from coretrace_python.plugins import SymbolCallDetector
from coretrace_python.semantic.symbols import SymbolId


class ForbiddenCall(SymbolCallDetector):
    name: ClassVar[str] = "forbidden-call"
    rule_id: ClassVar[str] = "forbidden-call"
    symbols: ClassVar[frozenset[SymbolId]] = frozenset({SymbolId("python.tempfile.gettempdir")})
    severity: ClassVar[Severity] = Severity.LOW
    message_template: ClassVar[str] = "call to {symbol} is forbidden here"
    rules = {"forbidden-call": RuleDescription("Forbidden call", "A call to a function the project forbids.")}
"""

UNDESCRIBED = """
from typing import ClassVar

from coretrace_python.findings import Severity
from coretrace_python.plugins import SymbolCallDetector
from coretrace_python.semantic.symbols import SymbolId


class QuietCall(SymbolCallDetector):
    name: ClassVar[str] = "quiet-call"
    rule_id: ClassVar[str] = "quiet-call"
    symbols: ClassVar[frozenset[SymbolId]] = frozenset({SymbolId("python.tempfile.gettempprefix")})
    severity: ClassVar[Severity] = Severity.LOW
    message_template: ClassVar[str] = "call to {symbol}"
"""


def plugin(root: Path, name: str, module: str, cls: str, code: str) -> None:
    directory = root / name
    directory.mkdir(parents=True)
    (directory / "plugin.toml").write_text(MANIFEST.format(name=name, module=module, cls=cls))
    (directory / f"{module}.py").write_text(code)


def sarif_rules(tmp_path: Path, source: str) -> dict[str, dict[str, object]]:
    plugins = tmp_path / "plugins"
    plugin(plugins, "forbidden-call", "forbidden", "ForbiddenCall", DESCRIBED)
    plugin(plugins, "quiet-call", "quiet", "QuietCall", UNDESCRIBED)
    path = tmp_path / "app.py"
    path.write_text(source)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        main(["--check", str(path), "--format", "sarif", "--plugins", str(plugins)])
    rules = json.loads(out.getvalue())["runs"][0]["tool"]["driver"]["rules"]
    return {rule["id"]: rule for rule in rules}


def test_a_plugin_describes_the_rules_it_reports(tmp_path: Path) -> None:
    rules = sarif_rules(tmp_path, "import tempfile\n\ndef run():\n    return tempfile.gettempdir()\n")

    assert rules["forbidden-call"] == {
        "id": "forbidden-call",
        "shortDescription": {"text": "Forbidden call"},
        "fullDescription": {"text": "A call to a function the project forbids."},
    }


def test_a_plugin_that_describes_nothing_still_reports_by_id(tmp_path: Path) -> None:
    rules = sarif_rules(tmp_path, "import tempfile\n\ndef run():\n    return tempfile.gettempprefix()\n")

    assert rules["quiet-call"] == {"id": "quiet-call"}
