"""Acceptance tests for the persistent cache (``docs/architecture.md`` §11, §38 Phase 10).

``ProjectCache`` stores, per module, its function summaries, its call sites and its
findings under a key derived from the source text, the engine, schema and plugin
versions, the security models, the advisories, the dependency graph and the keys of the
modules it imports transitively. On a later run a module whose key is unchanged is
served from the cache and never lowered again; its summaries seed the project index, so
changing one file re-analyses that file and its importers only.

Expected to remain red until ``coretrace_python.cache`` and the ``--cache`` option exist.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cli import main
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.source import SourceId, SourceSpan

try:
    from coretrace_python.cache import CachedModule, ProjectCache, decode, encode
except ImportError as error:  # pragma: no cover - red until the cache lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_cache() -> None:
    if MISSING is not None:
        pytest.fail(f"persistent cache is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "plugins"

HELPERS = "import os\n\ndef execute(command):\n    os.system(command)\n"
MAIN = "from app.helpers import execute\n\ndef run():\n    execute(input())\n"
CLEAN = "def ok():\n    return 1\n"


def project(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def standard(root: Path) -> Path:
    return project(
        root / "src",
        {"app/__init__.py": "", "app/helpers.py": HELPERS, "app/main.py": MAIN, "app/clean.py": CLEAN},
    )


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, str, int]]:
    return sorted((Path(str(f.span.source_id)).name, f.rule_id, f.span.start_line) for f in findings)


# --------------------------------------------------------------------------- codec


def test_findings_and_summaries_round_trip_through_json() -> None:
    from coretrace_python.interprocedural import ExternalCall, FunctionSummary
    from coretrace_python.semantic.symbols import SymbolId

    span = SourceSpan(SourceId("/p/a.py"), 3, 5, 3, 9)
    finding = Finding("r", "m", Severity.HIGH, Confidence.MEDIUM, span, "f", {"k": "v"})
    summary = FunctionSummary(
        "f",
        2,
        frozenset({0}),
        (ExternalCall(SymbolId("python.os.system"), (frozenset({0}), frozenset()), frozenset({1}), span, None),),
        False,
        frozenset({SymbolId("python.builtins.input")}),
    )

    text = json.dumps(encode(CachedModule(("f",), {"f": summary}, (), (finding,))))
    restored = decode(json.loads(text))

    assert restored.findings == (finding,)
    assert restored.summaries["f"] == summary
    assert restored.functions == ("f",)


# --------------------------------------------------------------------------- keys


def test_keys_depend_on_source_configuration_and_imports(tmp_path: Path) -> None:
    root = standard(tmp_path)
    first = engine.analyze_project(root, [PLUGINS]).keys
    (root / "app" / "clean.py").write_text("def ok():\n    return 2\n", encoding="utf-8")
    changed_clean = engine.analyze_project(root, [PLUGINS]).keys
    (root / "app" / "helpers.py").write_text(HELPERS + "\n", encoding="utf-8")
    changed_helpers = engine.analyze_project(root, [PLUGINS]).keys
    without_plugins = engine.analyze_project(root).keys

    assert set(first) == {"app", "app.helpers", "app.main", "app.clean"}
    assert changed_clean["app.clean"] != first["app.clean"]
    assert changed_clean["app.main"] == first["app.main"]
    assert changed_helpers["app.helpers"] != changed_clean["app.helpers"]
    assert changed_helpers["app.main"] != changed_clean["app.main"]
    assert changed_helpers["app.clean"] == changed_clean["app.clean"]
    assert without_plugins["app.clean"] != changed_helpers["app.clean"]


def test_keys_depend_on_dependency_files(tmp_path: Path) -> None:
    root = standard(tmp_path)
    before = engine.analyze_project(root, [PLUGINS]).keys
    (root / "requirements.txt").write_text("pyyaml==5.3.1\n", encoding="utf-8")
    after = engine.analyze_project(root, [PLUGINS]).keys

    assert all(after[name] != before[name] for name in before)


# --------------------------------------------------------------------------- reuse


def test_second_run_reuses_every_module_and_reports_the_same_findings(tmp_path: Path) -> None:
    root = standard(tmp_path)
    cache = ProjectCache(tmp_path / "cache")

    first = engine.analyze_project(root, [PLUGINS], cache=cache)
    second = engine.analyze_project(root, [PLUGINS], cache=cache)

    assert first.reused == ()
    assert set(second.reused) == {"app", "app.helpers", "app.main", "app.clean"}
    assert second.findings == first.findings
    assert rules(second.findings) == [("main.py", "command-injection", 4)]
    assert second.index == first.index
    assert list((tmp_path / "cache").glob("*.json"))


def test_changing_a_file_reanalyses_it_and_its_importers_only(tmp_path: Path) -> None:
    root = standard(tmp_path)
    cache = ProjectCache(tmp_path / "cache")
    engine.analyze_project(root, [PLUGINS], cache=cache)

    (root / "app" / "helpers.py").write_text("import os\n\ndef execute(command):\n    os.system('ls')\n", encoding="utf-8")
    result = engine.analyze_project(root, [PLUGINS], cache=cache)

    assert set(result.reused) == {"app", "app.clean"}
    assert result.findings == ()


def test_changing_an_importer_leaves_the_callee_cached(tmp_path: Path) -> None:
    root = standard(tmp_path)
    cache = ProjectCache(tmp_path / "cache")
    engine.analyze_project(root, [PLUGINS], cache=cache)

    (root / "app" / "main.py").write_text("from app.helpers import execute\n\ndef run():\n    execute('ls')\n", encoding="utf-8")
    result = engine.analyze_project(root, [PLUGINS], cache=cache)

    assert set(result.reused) == {"app", "app.helpers", "app.clean"}
    assert result.findings == ()


def test_cached_modules_still_serve_project_plugins_and_correlation(tmp_path: Path) -> None:
    root = project(
        tmp_path / "src",
        {
            "requirements.txt": "pyyaml==5.3.1\n",
            "app/__init__.py": "",
            "app/config.py": "import yaml\n\ndef parse(text):\n    return yaml.load(text)\n",
            "app/main.py": "from app.config import parse\n\ndef run():\n    parse(input())\n",
        },
    )
    cache = ProjectCache(tmp_path / "cache")

    first = engine.analyze_project(root, [PLUGINS], cache=cache)
    second = engine.analyze_project(root, [PLUGINS], cache=cache)

    assert set(second.reused) == {"app", "app.config", "app.main"}
    assert rules(second.findings) == rules(first.findings)
    assert ("config.py", "reachable-vulnerability", 4) in rules(second.findings)
    assert ("main.py", "exploitable-vulnerability", 4) in rules(second.findings)


def test_unsupported_and_syntax_notes_are_cached_too(tmp_path: Path) -> None:
    root = project(tmp_path / "src", {"nested.py": "def outer():\n    class Inner:\n        pass\n    return Inner\n"})
    cache = ProjectCache(tmp_path / "cache")

    first = engine.analyze_project(root, [PLUGINS], cache=cache)
    second = engine.analyze_project(root, [PLUGINS], cache=cache)

    assert rules(first.findings) == [("nested.py", "unsupported-syntax", 1)]
    assert second.findings == first.findings
    assert second.reused == ("nested",)


def test_corrupt_or_foreign_cache_entries_are_ignored(tmp_path: Path) -> None:
    root = standard(tmp_path)
    cache = ProjectCache(tmp_path / "cache")
    engine.analyze_project(root, [PLUGINS], cache=cache)
    for path in (tmp_path / "cache").glob("*.json"):
        path.write_text("{not json", encoding="utf-8")

    result = engine.analyze_project(root, [PLUGINS], cache=cache)

    assert result.reused == ()
    assert rules(result.findings) == [("main.py", "command-injection", 4)]


def test_cache_directory_is_created_on_demand(tmp_path: Path) -> None:
    root = standard(tmp_path)
    cache = ProjectCache(tmp_path / "nested" / "cache")

    engine.analyze_project(root, [PLUGINS], cache=cache)

    assert (tmp_path / "nested" / "cache").is_dir()


# --------------------------------------------------------------------------- CLI


def test_check_accepts_a_cache_directory(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    root = standard(tmp_path)
    cache_dir = tmp_path / "cache"

    first = main(["--check", str(root), "--plugins", str(PLUGINS), "--cache", str(cache_dir)])
    first_output = capsys.readouterr().out
    second = main(["--check", str(root), "--plugins", str(PLUGINS), "--cache", str(cache_dir)])
    second_output = capsys.readouterr().out

    assert first == second == 1
    assert first_output == second_output
    assert "command-injection" in second_output


def test_cache_option_requires_a_check(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = tmp_path / "x.py"
    source.write_text("", encoding="utf-8")

    assert main(["--emit-ir", "--cache", str(tmp_path / "c"), str(source)]) == 2
    assert "--cache" in capsys.readouterr().err
