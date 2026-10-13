"""Review of #240 (PR #250): a sink that selects code by name stays one when the models
of several plugins are merged.

Two plugins may declare the same sink; the registry merges them (``Sink.merged``). The
merged sink selects code by name when either declaration says so, whatever the order the
plugins load in, so a check of the shape of the name still leaves a hotspot.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import Sink, TaintKind

IMPORT_MODULE = SymbolId("python.importlib.import_module")


@pytest.mark.parametrize(
    ("first", "second"),
    [(True, False), (False, True), (True, True), (False, False)],
)
def test_a_merged_sink_selects_when_either_declaration_does(first: bool, second: bool) -> None:
    left = Sink(IMPORT_MODULE, TaintKind.CODE, ((TaintKind.CODE, (0,)),), selects=first)
    right = Sink(IMPORT_MODULE, TaintKind.CODE, ((TaintKind.CODE, (0,)),), selects=second)

    assert left.merged(right).selects is (first or second)
    assert right.merged(left).selects is (first or second)


MANIFEST = (
    'name = "import-sink"\nversion = "1.0.0"\nplugin_api = ">=1,<2"\nrequires = []\n'
    'provides = []\n\n[entrypoint]\nmodule = "import_sink"\nclass = "ImportSink"\n'
)
# Another plugin declaring the import sink, without ``selects``.
PLUGIN = '''
from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import Sink, TaintKind


class ImportSink(ModelPlugin):
    name: ClassVar[str] = "import-sink"
    models: ClassVar = (Sink(SymbolId("python.importlib.import_module"), TaintKind.CODE),)
'''
APP = (
    "import importlib\n\nfrom flask import request\n\n\n"
    "def load():\n    name = request.args['name']\n    if name.isidentifier():\n        importlib.import_module(name)\n"
)


@pytest.mark.parametrize("extra_first", [True, False], ids=["extra-plugin-first", "bundled-first"])
def test_another_plugin_declaring_the_sink_keeps_the_hotspot(tmp_path: Path, extra_first: bool) -> None:
    plugin = tmp_path / "plugins" / "import_sink"
    plugin.mkdir(parents=True)
    (plugin / "plugin.toml").write_text(MANIFEST, encoding="utf-8")
    (plugin / "import_sink.py").write_text(PLUGIN, encoding="utf-8")
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text(APP, encoding="utf-8")
    roots = [tmp_path / "plugins", engine.BUNDLED_PLUGINS]

    findings = engine.analyze_project(root, roots if extra_first else roots[::-1]).findings

    assert [(f.metadata["verdict"], f.confidence.value) for f in findings if f.rule_id == "code-injection"] == [
        ("hotspot", "medium")
    ]
