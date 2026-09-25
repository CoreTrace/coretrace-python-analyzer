"""A plugin may contribute models read from the project it analyses.

``Plugin.project_models(root)`` is called once per directory check, with the project's
root, in every process that analyses its modules. The models it returns join the
plugin's own, so a project can declare its validators in a file (``_allow_redirect``,
which accepts relative URLs only). They are part of what cached results depend on. A
single-file check reads no project. A model the project declares wrongly stops the
check with a message, not a traceback.
"""

from __future__ import annotations

from pathlib import Path

from coretrace_python import engine
from coretrace_python.cache import ProjectCache
from coretrace_python.cli import main
from coretrace_python.source import SourceManager

MANIFEST = (
    'name = "declared-validators"\nversion = "1.0.0"\nplugin_api = ">=1,<2"\nrequires = []\n'
    'provides = ["model.declared-validators"]\n\n[entrypoint]\nmodule = "declared"\nclass = "Declared"\n'
)
PLUGIN = '''
from pathlib import Path
from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import ModelError, Validator


class Declared(ModelPlugin):
    name: ClassVar[str] = "declared-validators"

    def project_models(self, root: Path):
        path = root / "validators.txt"
        if not path.is_file():
            return ()
        names = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if any(not name.startswith("python.") for name in names):
            raise ModelError(f"{path}: a validator is a symbol such as python.app.views.check")
        return tuple(Validator(SymbolId(name)) for name in names)
'''
VIEWS = (
    "from django.http import HttpRequest\n"
    "from django.shortcuts import redirect\n\n"
    "def _allow_redirect(url):\n"
    "    return url.startswith('/') and not url.startswith('//')\n\n"
    "def login(request: HttpRequest):\n"
    "    target = request.GET['next']\n"
    "    if target and _allow_redirect(target):\n"
    "        return redirect(target)\n"
    "    return redirect('/')\n"
)


def setup(tmp_path: Path, declared: str | None) -> tuple[Path, Path]:
    plugins = tmp_path / "plugins" / "declared"
    plugins.mkdir(parents=True)
    (plugins / "plugin.toml").write_text(MANIFEST, encoding="utf-8")
    (plugins / "declared.py").write_text(PLUGIN, encoding="utf-8")
    root = tmp_path / "project"
    (root / "hc").mkdir(parents=True)
    (root / "hc" / "__init__.py").write_text("", encoding="utf-8")
    (root / "hc" / "views.py").write_text(VIEWS, encoding="utf-8")
    if declared is not None:
        (root / "validators.txt").write_text(declared, encoding="utf-8")
    return root, tmp_path / "plugins"


def redirects(root: Path, plugins: Path, **options: object) -> list[str]:
    findings = engine.analyze_project(root, [engine.BUNDLED_PLUGINS, plugins], **options).findings  # type: ignore[arg-type]
    return [f.metadata["verdict"] for f in findings if f.rule_id == "open-redirect"]


def test_a_validator_the_project_declares_refutes_the_flow_it_guards(tmp_path: Path) -> None:
    root, plugins = setup(tmp_path, "python.hc.views._allow_redirect\n")

    assert redirects(root, plugins) == []
    (root / "validators.txt").unlink()
    assert redirects(root, plugins) == ["hotspot"]


def test_modules_analysed_in_other_processes_see_the_project_models(tmp_path: Path) -> None:
    root, plugins = setup(tmp_path, "python.hc.views._allow_redirect\n")
    (root / "hc" / "other.py").write_text("X = 1\n", encoding="utf-8")

    assert redirects(root, plugins, jobs=2) == []


def test_project_models_are_part_of_what_cached_results_depend_on(tmp_path: Path) -> None:
    root, plugins = setup(tmp_path, "python.hc.views._allow_redirect\n")
    cache = ProjectCache(tmp_path / "cache")

    first = redirects(root, plugins, cache=cache)
    (root / "validators.txt").write_text("python.hc.views.other_check\n", encoding="utf-8")
    second = engine.analyze_project(root, [engine.BUNDLED_PLUGINS, plugins], cache=cache)

    assert first == []
    assert second.reused == ()
    assert [f.metadata["verdict"] for f in second.findings if f.rule_id == "open-redirect"] == ["hotspot"]


def test_a_single_file_check_reads_no_project(tmp_path: Path) -> None:
    root, plugins = setup(tmp_path, "python.hc.views._allow_redirect\n")

    findings = engine.check(SourceManager().load_file(root / "hc" / "views.py"), [engine.BUNDLED_PLUGINS, plugins])

    assert [f.metadata["verdict"] for f in findings if f.rule_id == "open-redirect"] == ["hotspot"]


def test_a_model_the_project_declares_wrongly_stops_the_check_with_a_message(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    root, plugins = setup(tmp_path, "_allow_redirect\n")

    assert main(["--check", str(root), "--plugins", str(plugins)]) == 2
    assert "a validator is a symbol" in capsys.readouterr().err
