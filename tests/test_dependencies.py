"""Acceptance tests for dependency analysis (``docs/architecture.md`` §26).

The engine resolves the requirements declared in ``requirements.txt``,
``pyproject.toml``, ``poetry.lock`` and ``uv.lock`` into a ``DependencyGraph`` and
provides it to the analyses as the ``dependency.graph`` input. Plugins may contribute
``Advisory`` records (package, vulnerable range, affected APIs) and may run once per
project as ``ProjectPlugin``s with a ``ProjectContext`` that exposes the module graph,
the dependency graph, the advisories and every module's imports.

Shipped under ``plugins/dependency``: a sample advisory database, the
``vulnerable-dependency`` detector (a requirement allows a vulnerable version) and the
``reachable-vulnerability`` detector (an affected API is imported by a project module).

Expected to remain red until ``coretrace_python.dependency`` and the project plugin
kind exist.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest

from coretrace_python import engine
from coretrace_python.cli import main
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceId, SourceManager

try:
    from coretrace_python.dependency import (
        Advisory,
        DependencyAnalysis,
        DependencyGraph,
        Requirement,
        Version,
        parse_dependencies,
    )
    from coretrace_python.plugins import ProjectContext, ProjectPlugin
except ImportError as error:  # pragma: no cover - red until dependency analysis lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_dependencies() -> None:
    if MISSING is not None:
        pytest.fail(f"dependency analysis is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"


def project(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def source(name: str, text: str):  # type: ignore[no-untyped-def]
    return SourceManager().add_source(name, text)


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, str, int]]:
    return [(Path(str(f.span.source_id)).name, f.rule_id, f.span.start_line) for f in findings]


# --------------------------------------------------------------------------- parsing


def test_requirements_txt_lines_become_requirements() -> None:
    graph = parse_dependencies(
        source(
            "requirements.txt",
            "# pinned\nPyYAML==5.3.1\nrequests[security]>=2.18, <3\n-r other.txt\n"
            "flask ; python_version >= '3.8'\n\nDjango~=4.2.0  # lts\n",
        )
    )

    assert isinstance(graph, DependencyGraph)
    assert graph.names == ("django", "flask", "pyyaml", "requests")
    yaml = graph.requirement("PyYAML")
    assert isinstance(yaml, Requirement)
    assert yaml.name == "pyyaml"
    assert yaml.specifier == "==5.3.1"
    assert yaml.pinned == Version.parse("5.3.1")
    assert yaml.span.source_id == SourceId("requirements.txt")
    assert yaml.span.start_line == 2
    assert graph.requirement("requests").specifier == ">=2.18,<3"  # type: ignore[union-attr]
    assert graph.requirement("requests").pinned is None  # type: ignore[union-attr]
    assert graph.requirement("flask").specifier == ""  # type: ignore[union-attr]
    assert graph.requirement("django").specifier == "~=4.2.0"  # type: ignore[union-attr]


def test_pyproject_dependencies_pep621_and_poetry() -> None:
    graph = parse_dependencies(
        source(
            "pyproject.toml",
            '[project]\nname = "app"\ndependencies = ["requests>=2.20", "pyyaml"]\n\n'
            '[project.optional-dependencies]\ndev = ["pytest>=8"]\n\n'
            '[tool.poetry.dependencies]\npython = "^3.11"\njinja2 = "^2.11"\nflask = { version = ">=2.0", extras = ["async"] }\n',
        )
    )

    assert graph.names == ("flask", "jinja2", "pytest", "pyyaml", "requests")
    assert graph.requirement("jinja2").specifier == "^2.11"  # type: ignore[union-attr]
    assert graph.requirement("flask").specifier == ">=2.0"  # type: ignore[union-attr]
    assert graph.requirement("pytest").optional is True  # type: ignore[union-attr]
    assert graph.requirement("requests").optional is False  # type: ignore[union-attr]
    assert graph.requirement("requests").span.start_line == 3  # type: ignore[union-attr]


def test_lockfiles_pin_versions() -> None:
    poetry = parse_dependencies(
        source("poetry.lock", '[[package]]\nname = "pyyaml"\nversion = "5.3.1"\n\n[[package]]\nname = "Requests"\nversion = "2.31.0"\n')
    )
    uv = parse_dependencies(
        source("uv.lock", 'version = 1\n\n[[package]]\nname = "urllib3"\nversion = "1.26.4"\nsource = { registry = "https://pypi.org/simple" }\n')
    )

    assert poetry.requirement("pyyaml").pinned == Version.parse("5.3.1")  # type: ignore[union-attr]
    assert poetry.requirement("requests").pinned == Version.parse("2.31.0")  # type: ignore[union-attr]
    assert uv.requirement("urllib3").pinned == Version.parse("1.26.4")  # type: ignore[union-attr]
    assert uv.requirement("urllib3").span.start_line == 4  # type: ignore[union-attr]


def test_unknown_files_and_malformed_content_are_ignored_or_reported() -> None:
    assert parse_dependencies(source("setup.py", "x = 1\n")).names == ()
    graph = parse_dependencies(source("pyproject.toml", "not = [toml\n"))
    assert graph.names == ()
    assert graph.errors and "pyproject.toml" in graph.errors[0]


def test_graphs_merge_and_locks_pin_declared_requirements() -> None:
    declared = parse_dependencies(source("requirements.txt", "pyyaml>=5\n"))
    locked = parse_dependencies(source("poetry.lock", '[[package]]\nname = "pyyaml"\nversion = "5.3.1"\n'))

    merged = declared.merge(locked)

    assert merged.requirement("pyyaml").specifier == ">=5"  # type: ignore[union-attr]
    assert merged.requirement("pyyaml").pinned == Version.parse("5.3.1")  # type: ignore[union-attr]
    assert merged.names == ("pyyaml",)


# --------------------------------------------------------------------------- versions


@pytest.mark.parametrize(
    "version, specifier, expected",
    [
        ("5.3.1", "<5.4", True),
        ("5.4", "<5.4", False),
        ("2.19.1", ">=2.18,<2.20.0", True),
        ("2.20.0", ">=2.18,<2.20.0", False),
        ("4.2.7", "~=4.2.0", True),
        ("4.3.0", "~=4.2.0", False),
        ("2.11.3", "==2.11.3", True),
        ("1.26.4", ">=1.26.5", False),
        ("2.11.0", "^2.11", True),
        ("3.0.0", "^2.11", False),
    ],
)
def test_version_matching(version: str, specifier: str, expected: bool) -> None:
    assert Version.parse(version).satisfies(specifier) is expected


def test_requirements_may_allow_a_vulnerable_version() -> None:
    pinned = Requirement.parse("pyyaml==5.3.1", SourceId("r.txt"), 1)
    floor = Requirement.parse("pyyaml>=5.1", SourceId("r.txt"), 1)
    safe = Requirement.parse("pyyaml>=5.4", SourceId("r.txt"), 1)
    unspecified = Requirement.parse("pyyaml", SourceId("r.txt"), 1)

    assert pinned.may_match("<5.4") is True
    assert Requirement.parse("pyyaml==6.0", SourceId("r.txt"), 1).may_match("<5.4") is False
    assert floor.may_match("<5.4") is True
    assert safe.may_match("<5.4") is False
    assert unspecified.may_match("<5.4") is True


# --------------------------------------------------------------------------- engine


def test_projects_resolve_their_dependency_files(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "requirements.txt": "pyyaml>=5\nrequests==2.31.0\n",
            "poetry.lock": '[[package]]\nname = "pyyaml"\nversion = "5.3.1"\n',
            "app/__init__.py": "",
            "app/main.py": "import yaml\n",
        },
    )

    result = engine.analyze_project(root)

    assert result.dependencies.names == ("pyyaml", "requests")
    assert result.dependencies.requirement("pyyaml").pinned == Version.parse("5.3.1")  # type: ignore[union-attr]
    assert DependencyAnalysis.name == "dependency.graph"


def test_single_files_see_an_empty_dependency_graph() -> None:
    manager = engine.build_manager(engine.build_hir(source("x.py", "")))
    assert manager.get(DependencyAnalysis).names == ()


if MISSING is None:

    class CountRequirements(ProjectPlugin):
        name: ClassVar[str] = "test.count-requirements"
        runs: ClassVar[int] = 0

        def analyze_project(self, ctx: ProjectContext) -> list[Finding]:
            CountRequirements.runs += 1
            return [
                Finding(
                    "test.requirement",
                    f"{requirement.name} in {len(ctx.graph.modules)} modules",
                    Severity.INFO,
                    Confidence.HIGH,
                    requirement.span,
                )
                for requirement in ctx.dependencies.requirements
            ]


def test_project_plugins_run_once_per_project(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {"requirements.txt": "pyyaml\nrequests\n", "a.py": "", "b.py": ""},
    )
    CountRequirements.runs = 0

    findings = engine.analyze_project(root, plugins=[CountRequirements()]).findings

    assert CountRequirements.runs == 1
    assert [(f.rule_id, f.message) for f in findings] == [
        ("test.requirement", "pyyaml in 2 modules"),
        ("test.requirement", "requests in 2 modules"),
    ]
    assert rules(findings) == [("requirements.txt", "test.requirement", 1), ("requirements.txt", "test.requirement", 2)]


# --------------------------------------------------------------------------- shipped plugins


def test_advisory_records() -> None:
    advisory = Advisory(
        id="CVE-2020-1747",
        package="pyyaml",
        vulnerable="<5.4",
        summary="yaml.load can execute arbitrary code",
        severity=Severity.CRITICAL,
        affected_symbols=(SymbolId("python.yaml.load"), SymbolId("python.yaml.full_load")),
    )
    assert advisory.affects(Requirement.parse("pyyaml==5.3.1", SourceId("r"), 1))
    assert not advisory.affects(Requirement.parse("pyyaml==6.0", SourceId("r"), 1))


def test_sample_advisories_are_shipped() -> None:
    from coretrace_python.plugins import discover_plugins

    loaded = {p.manifest.name: p for p in discover_plugins(PLUGINS, engine.build_manager(engine.build_hir(source("e.py", ""))))}

    assert loaded["sample-advisories"].manifest.provides == ("advisories.sample",)
    advisories = loaded["sample-advisories"].plugin.advisories
    assert any(a.package == "pyyaml" and "CVE" in a.id for a in advisories)
    assert loaded["vulnerable-dependency"].manifest.requires == ("dependency.graph",)
    assert loaded["reachable-vulnerability"].manifest.requires == ("dependency.graph", "interprocedural.callgraph")


def test_vulnerable_requirement_is_reported_at_its_line(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {"requirements.txt": "requests==2.31.0\npyyaml==5.3.1\n", "app.py": "x = 1\n"},
    )

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert rules(findings) == [("requirements.txt", "vulnerable-dependency", 2)]
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].confidence is Confidence.HIGH
    assert "CVE-2020-1747" in findings[0].message
    assert findings[0].metadata["advisory"] == "CVE-2020-1747"
    assert findings[0].metadata["package"] == "pyyaml"


def test_unpinned_requirements_that_allow_a_vulnerable_version_are_medium_confidence(tmp_path: Path) -> None:
    root = project(tmp_path, {"requirements.txt": "pyyaml>=5.1\n", "app.py": ""})

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert rules(findings) == [("requirements.txt", "vulnerable-dependency", 1)]
    assert findings[0].confidence is Confidence.MEDIUM


def test_safe_versions_are_silent(tmp_path: Path) -> None:
    root = project(tmp_path, {"requirements.txt": "pyyaml>=6.0\nrequests>=2.31\n", "app.py": ""})
    assert engine.analyze_project(root, [PLUGINS]).findings == ()


def test_imported_affected_api_is_a_reachable_vulnerability(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "requirements.txt": "pyyaml==5.3.1\n",
            "app/__init__.py": "",
            "app/config.py": "import yaml\n\ndef load(text):\n    return yaml.load(text)\n",
            "app/other.py": "from yaml import safe_load\n",
        },
    )

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert rules(findings) == [
        ("config.py", "reachable-vulnerability", 4),
        ("requirements.txt", "vulnerable-dependency", 1),
    ]
    reachable = findings[0]
    assert reachable.severity is Severity.CRITICAL
    assert reachable.function == "load"
    assert reachable.metadata["symbol"] == "python.yaml.load"
    assert reachable.metadata["advisory"] == "CVE-2020-1747"


def test_reachability_needs_a_vulnerable_requirement(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {"requirements.txt": "pyyaml==6.0\n", "app.py": "import yaml\n\ndef load(t):\n    return yaml.load(t)\n"},
    )
    assert engine.analyze_project(root, [PLUGINS]).findings == ()


def test_cli_reports_dependency_findings(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    root = project(tmp_path, {"requirements.txt": "pyyaml==5.3.1\n", "app.py": ""})

    exit_code = main(["--check", str(root), "--plugins", str(PLUGINS)])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert output.startswith("requirements.txt:1:1: critical vulnerable-dependency:")
