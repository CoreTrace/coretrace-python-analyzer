"""Acceptance tests for the plugin API, manifests, loader and registry.

``docs/architecture.md`` §13 Plugin API, §14 Plugin Manifests, §23 Findings, §32 Stable
API, §33 Versioning, §34 Plugin Isolation.

Contract under test:

- ``Plugin`` subclasses declare ``name`` and ``requires`` and implement
  ``analyze(ctx) -> Sequence[Finding]``. The context only serves declared analyses.
- ``Finding`` is an immutable record with lightweight fields, never a graph copy.
- A plugin directory holds ``plugin.toml`` (name, version, plugin_api, requires,
  provides, entrypoint) next to its module. The loader checks the API range, the
  entrypoint and that manifest ``requires`` match the class.
- The reference ``dangerous_eval`` plugin under ``plugins/syntax`` runs end to end.

Expected to remain red until ``coretrace_python.plugins`` and
``coretrace_python.findings`` exist.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import ClassVar

import pytest

from coretrace_python.analysis import AnalysisManager, UndeclaredDependencyError
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.semantic import SEMANTIC_ANALYSES
from coretrace_python.semantic.scopes import ScopeAnalysis
from coretrace_python.semantic.symbols import SymbolAnalysis, SymbolId
from coretrace_python.source import SourceId, SourceManager, SourceSpan

try:
    from coretrace_python.findings import FINDING_SCHEMA_VERSION, Confidence, Finding, Severity
    from coretrace_python.plugins import (
        PLUGIN_API_VERSION,
        IncompatiblePluginError,
        LoadedPlugin,
        ManifestError,
        Plugin,
        PluginContext,
        PluginManifest,
        PluginRegistry,
        VersionRange,
        discover_plugins,
        load_manifest,
        load_plugin,
        run_plugins,
    )
except ImportError as error:  # pragma: no cover - red until the plugin API lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_plugin_api() -> None:
    if MISSING is not None:
        pytest.fail(f"plugin API is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
DANGEROUS_EVAL = REPO / "src" / "coretrace_python" / "bundled" / "syntax" / "dangerous_eval"


def manager_for(source_text: str) -> AnalysisManager:
    from coretrace_python.cfg import CFGAnalysis, DominanceAnalysis
    from coretrace_python.ir.lowering import PyIRAnalysis
    from coretrace_python.ir.ssa import SSAAnalysis

    module = build_hir(SourceManager().add_source("plugged.py", source_text))
    manager = AnalysisManager(module)
    manager.register(*SEMANTIC_ANALYSES, CFGAnalysis, DominanceAnalysis, PyIRAnalysis, SSAAnalysis)
    return manager


def span(line: int = 1, column: int = 1) -> SourceSpan:
    return SourceSpan(SourceId("plugged.py"), line, column)


# --------------------------------------------------------------------------- stub plugins


if MISSING is None:  # the stubs subclass the base class under test

    class CountFunctions(Plugin):
        name: ClassVar[str] = "test.count-functions"

        def analyze(self, ctx: PluginContext) -> list[Finding]:
            return [
                Finding(
                    rule_id="test.function",
                    message=f"function {function.name}",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    span=function.span,
                    function=function.name,
                )
                for function in ctx.functions()
            ]

    class UsesSymbols(Plugin):
        name: ClassVar[str] = "test.uses-symbols"
        requires: ClassVar[frozenset[type[object]]] = frozenset({ScopeAnalysis, SymbolAnalysis})

        def analyze(self, ctx: PluginContext) -> list[Finding]:
            scopes = ctx.get(ScopeAnalysis)
            symbols = ctx.get(SymbolAnalysis)
            findings = []
            for function in ctx.functions():
                symbol = symbols.resolve(scopes.scope_for(function).id, "os")
                if symbol == SymbolId("python.os"):
                    findings.append(
                        Finding("test.os", "uses os", Severity.LOW, Confidence.MEDIUM, function.span)
                    )
            return findings

    class Sneaky(Plugin):
        """Requests an analysis it did not declare."""

        name: ClassVar[str] = "test.sneaky"

        def analyze(self, ctx: PluginContext) -> list[Finding]:
            ctx.get(SymbolAnalysis)
            return []


# --------------------------------------------------------------------------- findings


def test_findings_are_immutable_lightweight_records() -> None:
    finding = Finding("rule", "message", Severity.HIGH, Confidence.HIGH, span(2, 5))

    assert finding.function is None
    assert dict(finding.metadata) == {}
    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.message = "other"  # type: ignore[misc]
    with pytest.raises(TypeError):
        finding.metadata["k"] = "v"  # type: ignore[index]


def test_versions_are_declared() -> None:
    assert PLUGIN_API_VERSION == 1
    assert FINDING_SCHEMA_VERSION >= 1


# --------------------------------------------------------------------------- plugin contract


def test_plugins_receive_the_module_and_its_functions() -> None:
    manager = manager_for("def a():\n    pass\n\ndef b():\n    pass\n")

    findings = run_plugins(manager, [CountFunctions()])

    assert [f.function for f in findings] == ["a", "b"]
    assert findings[0].rule_id == "test.function"
    assert findings[0].span.start_line == 1
    assert findings[1].span.start_line == 4


def test_plugins_consume_declared_analyses() -> None:
    manager = manager_for("import os\n\ndef run(c):\n    os.system(c)\n\ndef idle(os):\n    pass\n")

    findings = run_plugins(manager, [UsesSymbols()])

    assert [f.rule_id for f in findings] == ["test.os"]
    assert findings[0].span.start_line == 3


def test_undeclared_analysis_requests_are_rejected() -> None:
    manager = manager_for("def a():\n    pass\n")

    with pytest.raises(UndeclaredDependencyError, match="test.sneaky.*semantic.symbols"):
        run_plugins(manager, [Sneaky()])


def test_analyses_are_shared_between_plugins() -> None:
    manager = manager_for("import os\n\ndef run(c):\n    os.system(c)\n")

    run_plugins(manager, [UsesSymbols(), UsesSymbols()])

    assert manager.is_cached(SymbolAnalysis)
    assert manager.get(SymbolAnalysis) is manager.get(SymbolAnalysis)


def test_findings_are_returned_in_plugin_order() -> None:
    manager = manager_for("import os\n\ndef run(c):\n    os.system(c)\n")

    findings = run_plugins(manager, [UsesSymbols(), CountFunctions()])

    assert [f.rule_id for f in findings] == ["test.os", "test.function"]


# --------------------------------------------------------------------------- version ranges


@pytest.mark.parametrize(
    "spec, inside, outside",
    [
        (">=1,<2", [1], [0, 2]),
        ("1", [1], [0, 2]),
        ("==1", [1], [2]),
        (">=1", [1, 5], [0]),
    ],
)
def test_version_ranges(spec: str, inside: list[int], outside: list[int]) -> None:
    version_range = VersionRange.parse(spec)
    assert all(version_range.contains(v) for v in inside)
    assert not any(version_range.contains(v) for v in outside)


@pytest.mark.parametrize("spec", ["", "~1", ">=", "1.0", ">=1,,<2"])
def test_invalid_version_ranges_are_rejected(spec: str) -> None:
    with pytest.raises(ManifestError):
        VersionRange.parse(spec)


# --------------------------------------------------------------------------- manifests


def test_reference_manifest_is_parsed() -> None:
    manifest = load_manifest(DANGEROUS_EVAL / "plugin.toml")

    assert isinstance(manifest, PluginManifest)
    assert manifest.name == "dangerous-eval"
    assert manifest.version == "1.0.0"
    assert manifest.plugin_api.contains(PLUGIN_API_VERSION)
    assert manifest.requires == ("ir.ssa",)
    assert manifest.provides == ("vulnerability.dangerous-eval",)
    assert manifest.entrypoint.module == "dangerous_eval"
    assert manifest.entrypoint.class_name == "DangerousEvalPlugin"


def write_manifest(directory: Path, **overrides: object) -> Path:
    fields: dict[str, object] = {
        "name": "sample",
        "version": "0.1.0",
        "plugin_api": ">=1,<2",
        "requires": [],
        "provides": ["test.sample"],
    }
    fields.update({k: v for k, v in overrides.items() if k != "entrypoint"})
    entrypoint = overrides.get("entrypoint", {"module": "sample", "class": "SamplePlugin"})
    lines = []
    for key, value in fields.items():
        if isinstance(value, list):
            lines.append(f"{key} = [{', '.join(repr(v) for v in value)}]")
        else:
            lines.append(f"{key} = {value!r}")
    if entrypoint is not None:
        assert isinstance(entrypoint, dict)
        lines.append("[entrypoint]")
        lines.extend(f"{k} = {v!r}" for k, v in entrypoint.items())
    path = directory / "plugin.toml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_plugin(directory: Path, requires: str = "frozenset()") -> None:
    (directory / "sample.py").write_text(
        "from typing import ClassVar\n\n"
        "from coretrace_python.plugins import Plugin, PluginContext\n"
        "from coretrace_python.semantic.scopes import ScopeAnalysis\n"
        "from coretrace_python.semantic.symbols import SymbolAnalysis\n\n\n"
        "class SamplePlugin(Plugin):\n"
        '    name: ClassVar[str] = "sample"\n'
        f"    requires = {requires}\n\n"
        "    def analyze(self, ctx: PluginContext) -> list:\n"
        "        return []\n\n\n"
        "class NotAPlugin:\n"
        "    pass\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "missing", ["name", "version", "plugin_api", "requires", "provides", "entrypoint"]
)
def test_manifest_requires_every_field(tmp_path: Path, missing: str) -> None:
    path = write_manifest(tmp_path, **{missing: None})
    if missing != "entrypoint":
        text = "\n".join(
            line for line in path.read_text().splitlines() if not line.startswith(f"{missing} =")
        )
        path.write_text(text + "\n", encoding="utf-8")

    with pytest.raises(ManifestError, match=missing):
        load_manifest(path)


# --------------------------------------------------------------------------- loader


def test_loads_the_reference_plugin() -> None:
    loaded = load_plugin(DANGEROUS_EVAL, manager_for(""))

    assert isinstance(loaded, LoadedPlugin)
    assert loaded.manifest.name == "dangerous-eval"
    assert isinstance(loaded.plugin, Plugin)
    assert loaded.plugin.name == "dangerous-eval"
    from coretrace_python.ir.ssa import SSAAnalysis

    assert loaded.plugin.requires == frozenset({SSAAnalysis})


def test_incompatible_plugin_api_is_rejected(tmp_path: Path) -> None:
    write_manifest(tmp_path, plugin_api=">=2,<3")
    write_plugin(tmp_path)

    with pytest.raises(IncompatiblePluginError, match="sample.*>=2,<3"):
        load_plugin(tmp_path, manager_for(""))


def test_manifest_requires_must_name_registered_analyses(tmp_path: Path) -> None:
    write_manifest(tmp_path, requires=["analysis.taint"])
    write_plugin(tmp_path)

    with pytest.raises(ManifestError, match="analysis.taint"):
        load_plugin(tmp_path, manager_for(""))


def test_manifest_requires_must_match_the_class(tmp_path: Path) -> None:
    write_manifest(tmp_path, requires=["semantic.scopes"])
    write_plugin(tmp_path, requires="frozenset({ScopeAnalysis, SymbolAnalysis})")

    with pytest.raises(ManifestError, match="semantic.symbols"):
        load_plugin(tmp_path, manager_for(""))


def test_entrypoint_must_be_a_plugin(tmp_path: Path) -> None:
    write_manifest(tmp_path, entrypoint={"module": "sample", "class": "NotAPlugin"})
    write_plugin(tmp_path)

    with pytest.raises(ManifestError, match="NotAPlugin"):
        load_plugin(tmp_path, manager_for(""))


def test_missing_entrypoint_module_is_reported(tmp_path: Path) -> None:
    write_manifest(tmp_path, entrypoint={"module": "absent", "class": "SamplePlugin"})

    with pytest.raises(ManifestError, match="absent"):
        load_plugin(tmp_path, manager_for(""))


def test_discovers_plugins_recursively_in_sorted_order(tmp_path: Path) -> None:
    for name in ("b/second", "a/first"):
        directory = tmp_path / name
        directory.mkdir(parents=True)
        write_manifest(directory, name=name.split("/")[1])
        write_plugin(directory)

    loaded = discover_plugins(tmp_path, manager_for(""))

    assert [plugin.manifest.name for plugin in loaded] == ["first", "second"]


# --------------------------------------------------------------------------- registry


def test_registry_indexes_plugins_by_name_and_capability() -> None:
    loaded = load_plugin(DANGEROUS_EVAL, manager_for(""))
    registry = PluginRegistry()

    registry.add(loaded)

    assert registry.plugin("dangerous-eval") is loaded
    assert registry.providers("vulnerability.dangerous-eval") == (loaded,)
    assert registry.providers("vulnerability.sql-injection") == ()
    assert [plugin.manifest.name for plugin in registry] == ["dangerous-eval"]


def test_registry_rejects_duplicate_names() -> None:
    registry = PluginRegistry()
    registry.add(load_plugin(DANGEROUS_EVAL, manager_for("")))

    with pytest.raises(ManifestError, match="dangerous-eval"):
        registry.add(load_plugin(DANGEROUS_EVAL, manager_for("")))


# --------------------------------------------------------------------------- reference plugin


def test_dangerous_eval_reports_builtin_eval_calls() -> None:
    manager = manager_for("def run(code):\n    eval(code)\n    return exec(code)\n")
    loaded = load_plugin(DANGEROUS_EVAL, manager)

    findings = run_plugins(manager, [loaded.plugin])

    assert [(f.rule_id, f.span.start_line, f.function) for f in findings] == [
        ("dangerous-eval", 2, "run"),
        ("dangerous-eval", 3, "run"),
    ]
    assert findings[0].severity is Severity.HIGH
    assert "python.builtins.eval" in findings[0].message
    assert "python.builtins.exec" in findings[1].message


def test_dangerous_eval_follows_symbols_not_names() -> None:
    manager = manager_for(
        "from ast import literal_eval as eval\n\n"
        "def parse(text):\n"
        "    return eval(text)\n\n"
        "def shadowed(eval, text):\n"
        "    return eval(text)\n"
    )
    loaded = load_plugin(DANGEROUS_EVAL, manager)

    assert run_plugins(manager, [loaded.plugin]) == ()


def test_dangerous_eval_ignores_modules_without_functions() -> None:
    manager = manager_for("x = 1\n")
    loaded = load_plugin(DANGEROUS_EVAL, manager)

    assert run_plugins(manager, [loaded.plugin]) == ()


def test_plugin_context_is_a_narrow_view() -> None:
    manager = manager_for("def a():\n    pass\n")
    seen: list[object] = []

    class Inspect(Plugin):
        name: ClassVar[str] = "test.inspect"

        def analyze(self, ctx: PluginContext) -> list[Finding]:
            seen.append(ctx)
            return []

    run_plugins(manager, [Inspect()])

    ctx = seen[0]
    assert isinstance(ctx.module, nodes.Module)
    assert not hasattr(ctx, "register")
    assert not hasattr(ctx, "run")
