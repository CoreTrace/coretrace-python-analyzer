"""Acceptance tests for project discovery robustness, found on real repositories.

A virtual environment is skipped whatever its directory is called, detected by the
``pyvenv.cfg`` the ``venv`` module writes at its root. A module or package whose name
is not a Python identifier (``network-topologer``, ``docutils-script.py``) cannot be
imported by that name but still deserves analysis: its project symbols use a sanitised
name instead of raising.

Expected to remain red until ``discover_sources`` and ``project_symbol`` handle both.
"""

from __future__ import annotations

from pathlib import Path

from coretrace_python import engine
from coretrace_python.interprocedural import discover_sources, project_symbol
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager


def project(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def test_virtual_environments_are_skipped_whatever_their_name(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "env/pyvenv.cfg": "home = /usr/bin\n",
            "env/Scripts/docutils-script.py": "import os\nos.system(input())\n",
            "env/Lib/site-packages/thing.py": "x = 1\n",
            "tools/pyvenv.cfg": "",
            "tools/helper.py": "y = 2\n",
            "app.py": "z = 3\n",
        },
    )

    names = [source.module_name for source in discover_sources(root, SourceManager())]

    assert names == ["app"]


def test_project_symbols_tolerate_non_identifier_module_names() -> None:
    assert project_symbol("network-topologer.main", "run") == SymbolId("python.network_topologer.main.run")
    assert project_symbol("docutils-script", "load") == SymbolId("python.docutils_script.load")
    assert project_symbol("2fa.codes", "verify") == SymbolId("python._2fa.codes.verify")
    assert project_symbol("app.views", "Ping.get") == SymbolId("python.app.views.Ping.get")


def test_dashed_packages_are_analysed_instead_of_crashing(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "network-topologer/__init__.py": "",
            "network-topologer/traceroute.py": "import os\n\ndef probe(host):\n    os.system('ping ' + host)\n",
            "network-topologer/__main__.py": "import os\n\ndef main():\n    os.system(input())\n",
            "env/pyvenv.cfg": "",
            "env/Scripts/docutils-script.py": "def importlib_load_entry_point():\n    return 1\n",
        },
    )

    analysis = engine.analyze_project(root, [Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"])

    assert set(analysis.keys) == {"network-topologer", "network-topologer.traceroute", "network-topologer.__main__"}
    assert [(f.rule_id, Path(str(f.span.source_id)).name, f.span.start_line) for f in analysis.findings] == [
        ("command-injection", "__main__.py", 4)
    ]
    assert SymbolId("python.network_topologer.traceroute.probe") in analysis.index.symbols


def test_undecodable_files_become_notes_and_the_rest_is_analysed(tmp_path: Path) -> None:
    root = project(tmp_path, {"app.py": "import os\n\ndef run():\n    os.system(input())\n"})
    (root / "legacy.py").write_bytes(b"print('x')\n\xff")

    analysis = engine.analyze_project(root, [Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"])

    notes = [(f.rule_id, Path(str(f.span.source_id)).name) for f in analysis.findings]
    assert ("syntax-error", "legacy.py") in notes
    assert ("command-injection", "app.py") in notes
    assert set(analysis.keys) == {"app"}
    assert any("codec" in f.message for f in analysis.findings if f.rule_id == "syntax-error")


def test_utf16_dependency_files_are_read(tmp_path: Path) -> None:
    root = project(tmp_path, {"app.py": "x = 1\n"})
    (root / "requirements.txt").write_bytes("pyyaml==5.3.1\r\nflask==2.0.0\r\n".encode("utf-16"))

    analysis = engine.analyze_project(root, [Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"])

    assert analysis.dependencies.names == ("flask", "pyyaml")
    assert sorted(f.rule_id for f in analysis.findings) == ["vulnerable-dependency", "vulnerable-dependency"]


def test_duplicate_qualified_names_get_distinct_call_graph_names() -> None:
    from coretrace_python.interprocedural import CallGraphAnalysis
    from coretrace_python.taint import TaintAnalysis

    source = SourceManager().add_source(
        "props.py",
        "import os\n\nclass Box:\n    @property\n    def cmd(self):\n        return self._cmd\n\n"
        "    @cmd.setter\n    def cmd(self, value):\n        self._cmd = value\n        os.system(input())\n\n"
        "def run():\n    return 1\n\ndef run():\n    return 2\n",
    )
    module = engine.build_hir(source)
    manager = engine.build_manager(module)
    graph = manager.get(CallGraphAnalysis)

    assert graph.functions == ("Box.cmd", "Box.cmd__2", "run", "run__2")
    setter = module.body[1].body[1]  # type: ignore[union-attr]
    assert graph.name_of(setter) == "Box.cmd__2"  # type: ignore[arg-type]
    assert manager.get(TaintAnalysis, setter) is not None  # type: ignore[arg-type]
    findings = engine.check(source, [Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"])
    assert [(f.rule_id, f.span.start_line) for f in findings] == [("command-injection", 11)]
