"""A report names what its result was produced with, besides the engine and the sources.

Advisories decide the dependency findings and the VEX statements, and they come from
plugins and advisory files that change on their own schedule. A directory check lists
each loaded plugin, by manifest name and version, and each advisory file it read, by
path; each with the SHA-256 digest of its content. Every report format shows them, and
every finding citing an advisory names, in ``advisory_source``, the plugin or the file
that provided it.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from coretrace_python import engine
from coretrace_python.cache import ProjectCache, directory_fingerprint
from coretrace_python.cli import main
from coretrace_python.dependency import (
    Advisory,
    AdvisoryEntryPoint,
    dump_advisories,
    render_sbom,
    render_vex,
)
from coretrace_python.findings import Component, Severity
from coretrace_python.reporters.json_format import render_json
from coretrace_python.reporters.sarif import render_sarif
from coretrace_python.semantic.symbols import SymbolId

MANIFEST = (
    'name = "vuln-data"\nversion = "2026.09.25"\nplugin_api = ">=1,<2"\nrequires = []\n'
    'provides = ["advisories.vuln-data"]\n\n[entrypoint]\nmodule = "vuln_data"\nclass = "VulnData"\n'
)
PLUGIN = '''
import json
from pathlib import Path
from typing import ClassVar

from coretrace_python.dependency import load_advisories
from coretrace_python.plugins import ModelPlugin


class VulnData(ModelPlugin):
    name: ClassVar[str] = "vuln-data"
    advisories: ClassVar = load_advisories(Path(__file__).parent / "data.json")
'''
PARSE = Advisory(
    "CVE-2099-0701",
    "vulnlib",
    "<1.1",
    "parse runs code from the document",
    Severity.HIGH,
    entry_points=(AdvisoryEntryPoint(SymbolId("python.vulnlib.parse"), "commit abc1234"),),
    modules=("vulnlib",),
)
APP = "import vulnlib\n\ndef run():\n    return vulnlib.parse(input())\n"
RULES = ("vulnerable-dependency", "reachable-vulnerability", "exploitable-vulnerability")


def project(tmp_path: Path) -> tuple[Path, Path]:
    plugin = tmp_path / "plugins" / "vuln_data"
    plugin.mkdir(parents=True)
    (plugin / "plugin.toml").write_text(MANIFEST, encoding="utf-8")
    (plugin / "vuln_data.py").write_text(PLUGIN, encoding="utf-8")
    (plugin / "data.json").write_text(dump_advisories((PARSE,)), encoding="utf-8")
    root = tmp_path / "project"
    root.mkdir()
    (root / "requirements.txt").write_text("vulnlib==1.0\n", encoding="utf-8")
    (root / "app.py").write_text(APP, encoding="utf-8")
    return root, tmp_path / "plugins"


def analyse(root: Path, plugins: Path, **options: object) -> engine.ProjectAnalysis:
    return engine.analyze_project(root, [engine.BUNDLED_PLUGINS, plugins], **options)  # type: ignore[arg-type]


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def sources(analysis: engine.ProjectAnalysis) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for finding in analysis.findings:
        if finding.rule_id in RULES:
            found.setdefault(finding.rule_id, set()).add(finding.metadata["advisory_source"])
    return found


# --------------------------------------------------------------------------- components


def test_a_directory_check_names_each_plugin_and_advisory_file_with_its_digest(tmp_path: Path) -> None:
    root, plugins = project(tmp_path)
    (root / "advisories.json").write_text(dump_advisories(()), encoding="utf-8")
    extra = tmp_path / "feed.json"
    extra.write_text(dump_advisories(()), encoding="utf-8")

    components = analyse(root, plugins, advisory_files=(extra,)).components

    plugin = plugins / "vuln_data"
    assert Component("plugin", "vuln-data", "sha256:" + directory_fingerprint(plugin), "2026.09.25") in components
    assert Component("advisories", "advisories.json", sha256(root / "advisories.json")) in components
    assert Component("advisories", str(extra), sha256(extra)) in components
    assert {c.name for c in components if c.kind == "plugin"} >= {"vuln-data", "sample-advisories"}


def test_a_plugin_digest_follows_its_data_and_ignores_bytecode(tmp_path: Path) -> None:
    root, plugins = project(tmp_path)
    plugin = plugins / "vuln_data"

    def digest() -> str:
        (component,) = [c for c in analyse(root, plugins).components if c.name == "vuln-data"]
        return component.digest

    first = digest()
    (plugin / "__pycache__").mkdir(exist_ok=True)
    (plugin / "__pycache__" / "vuln_data.cpython-312.pyc").write_bytes(b"compiled")
    assert digest() == first
    (plugin / "data.json").write_text(dump_advisories((PARSE, PARSE)), encoding="utf-8")
    assert digest() != first


def test_an_advisory_file_that_does_not_load_is_no_component(tmp_path: Path) -> None:
    root, plugins = project(tmp_path)
    (root / "advisories.json").write_text("{not json", encoding="utf-8")

    analysis = analyse(root, plugins)

    assert [c for c in analysis.components if c.kind == "advisories"] == []
    assert any(f.rule_id == "syntax-error" for f in analysis.findings)


# --------------------------------------------------------------------------- findings


def test_every_advisory_finding_names_the_plugin_that_provided_its_advisory(tmp_path: Path) -> None:
    root, plugins = project(tmp_path)

    assert sources(analyse(root, plugins)) == {rule: {"vuln-data@2026.09.25"} for rule in RULES}


def test_an_advisory_file_that_redefines_an_advisory_is_its_source(tmp_path: Path) -> None:
    root, plugins = project(tmp_path)
    (root / "advisories.json").write_text(dump_advisories((PARSE,)), encoding="utf-8")

    assert sources(analyse(root, plugins)) == {rule: {"advisories.json"} for rule in RULES}


def test_findings_served_from_the_cache_name_their_source_too(tmp_path: Path) -> None:
    root, plugins = project(tmp_path)
    cache = ProjectCache(tmp_path / "cache")
    analyse(root, plugins, cache=cache)

    second = analyse(root, plugins, cache=cache)

    assert second.reused == ("app",)
    assert sources(second) == {rule: {"vuln-data@2026.09.25"} for rule in RULES}


# --------------------------------------------------------------------------- reports


def test_every_report_format_shows_the_components(tmp_path: Path) -> None:
    root, plugins = project(tmp_path)
    analysis = analyse(root, plugins)
    (plugin,) = [c for c in analysis.components if c.name == "vuln-data"]
    report = engine.report(analysis.findings, analysis.coverage, root, components=analysis.components)

    listed = json.loads(render_json(report))["tool"]["components"]
    assert {"kind": "plugin", "name": "vuln-data", "version": "2026.09.25", "digest": plugin.digest} in listed

    extensions = json.loads(render_sarif(report))["runs"][0]["tool"]["extensions"]
    assert {"name": "vuln-data", "version": "2026.09.25", "properties": {"kind": "plugin", "digest": plugin.digest}} in extensions

    tools = json.loads(
        render_sbom(analysis.dependencies, analysis.advisories, engine.TOOL_NAME, "0.0.0", analysis.components)
    )["metadata"]["tools"]["components"]
    assert {
        "type": "application",
        "name": "vuln-data",
        "version": "2026.09.25",
        "hashes": [{"alg": "SHA-256", "content": plugin.digest.removeprefix("sha256:")}],
    } in tools

    def vex() -> dict[str, object]:
        again = analyse(root, plugins)
        return json.loads(
            render_vex(
                again.dependencies,
                again.advisories,
                again.findings,
                again.coverage,
                root,
                engine.TOOL_NAME,
                "0.0.0",
                datetime(2026, 9, 25, tzinfo=UTC),
                again.components,
            )
        )

    first = vex()
    assert f"vuln-data 2026.09.25 ({plugin.digest})" in str(first["tooling"])
    (plugins / "vuln_data" / "data.json").write_text(dump_advisories((PARSE, PARSE)), encoding="utf-8")
    assert vex()["@id"] != first["@id"]


def test_an_advisory_file_is_a_data_component_of_the_sbom(tmp_path: Path) -> None:
    root, plugins = project(tmp_path)
    (root / "advisories.json").write_text(dump_advisories((PARSE,)), encoding="utf-8")
    analysis = analyse(root, plugins)

    tools = json.loads(
        render_sbom(analysis.dependencies, analysis.advisories, engine.TOOL_NAME, "0.0.0", analysis.components)
    )["metadata"]["tools"]["components"]

    digest = sha256(root / "advisories.json").removeprefix("sha256:")
    assert {"type": "data", "name": "advisories.json", "hashes": [{"alg": "SHA-256", "content": digest}]} in tools


def test_the_command_line_lists_components_for_a_directory_only(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    root, plugins = project(tmp_path)

    main(["--check", str(root), "--plugins", str(plugins), "--format", "json"])
    directory = json.loads(capsys.readouterr().out)
    main(["--check", str(root / "app.py"), "--plugins", str(plugins), "--format", "json"])
    single = json.loads(capsys.readouterr().out)

    assert "vuln-data" in {c["name"] for c in directory["tool"]["components"]}
    assert "components" not in single["tool"]
