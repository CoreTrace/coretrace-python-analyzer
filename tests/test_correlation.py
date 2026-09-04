"""Acceptance tests for the correlation engine (``docs/architecture.md`` §27).

SCA, SAST, the call graph and taint combine into one high-confidence finding: a package
required in a vulnerable version, an API the advisory affects, a call to that API
reachable in the project, and attacker-controlled data reaching that call. The engine
registers the affected APIs of vulnerable requirements as sinks of the ``ADVISORY``
taint kind, so interprocedural taint and refutation apply unchanged, and correlates the
resulting flows into ``exploitable-vulnerability`` findings.

Expected to remain red until ``TaintKind.ADVISORY`` and ``dependency.correlation`` exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import SecurityModelRegistry, Sink, TaintKind

try:
    from coretrace_python.dependency.correlation import advisory_sinks, affected_symbols, correlate
except ImportError as error:  # pragma: no cover - red until correlation lands
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_correlation() -> None:
    if MISSING is not None or not hasattr(TaintKind, "ADVISORY"):
        pytest.fail(f"correlation is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "plugins"

VULNERABLE = "pyyaml==5.3.1\n"


def project(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, str, int]]:
    return sorted((Path(str(f.span.source_id)).name, f.rule_id, f.span.start_line) for f in findings)


def exploitable(findings: tuple[Finding, ...]) -> list[Finding]:
    return [f for f in findings if f.rule_id == "exploitable-vulnerability"]


# --------------------------------------------------------------------------- models


def test_advisory_taint_kind_exists_and_is_part_of_all() -> None:
    assert TaintKind.ADVISORY in TaintKind.ALL
    assert TaintKind.ADVISORY & TaintKind.COMMAND == TaintKind.NONE


def test_model_tables_extend_with_advisory_sinks_merging_kinds() -> None:
    registry = SecurityModelRegistry()
    registry.register(Sink(SymbolId("python.requests.get"), TaintKind.SSRF))
    table = registry.freeze()

    extended = table.extended(
        Sink(SymbolId("python.requests.get"), TaintKind.ADVISORY),
        Sink(SymbolId("python.yaml.load"), TaintKind.ADVISORY),
    )

    assert extended.sink(SymbolId("python.requests.get")).kinds == TaintKind.SSRF | TaintKind.ADVISORY  # type: ignore[union-attr]
    assert extended.sink(SymbolId("python.yaml.load")).kinds == TaintKind.ADVISORY  # type: ignore[union-attr]
    assert table.sink(SymbolId("python.yaml.load")) is None


def test_only_affected_apis_of_vulnerable_requirements_become_sinks(tmp_path: Path) -> None:
    from coretrace_python.dependency import parse_dependencies

    graph = parse_dependencies(SourceManager().add_source("requirements.txt", "pyyaml==5.3.1\nrequests==2.31.0\n"))
    loaded = engine.load_plugins([PLUGINS], engine.build_manager(engine.build_hir(SourceManager().add_source("e.py", ""))))
    advisories = tuple(a for p in loaded for a in p.plugin.advisories)

    affected = affected_symbols(graph, advisories)
    sinks = advisory_sinks(affected)

    assert SymbolId("python.yaml.load") in affected
    assert SymbolId("python.requests.get") not in affected
    assert all(sink.kinds == TaintKind.ADVISORY for sink in sinks)
    assert {sink.symbol for sink in sinks} == set(affected)


# --------------------------------------------------------------------------- end to end


def test_tainted_call_to_an_affected_api_is_exploitable(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {"requirements.txt": VULNERABLE, "app.py": "import yaml\n\ndef load():\n    return yaml.load(input())\n"},
    )

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert rules(findings) == [
        ("app.py", "exploitable-vulnerability", 4),
        ("app.py", "reachable-vulnerability", 4),
        ("requirements.txt", "vulnerable-dependency", 1),
    ]
    (finding,) = exploitable(findings)
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence is Confidence.HIGH
    assert finding.function == "load"
    assert finding.metadata["advisory"] == "CVE-2020-1747"
    assert finding.metadata["package"] == "pyyaml"
    assert finding.metadata["symbol"] == "python.yaml.load"
    assert finding.metadata["source_label"] == "stdin"
    assert "CVE-2020-1747" in finding.message and "stdin" in finding.message


def test_untainted_calls_are_reachable_but_not_exploitable(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {"requirements.txt": VULNERABLE, "app.py": "import yaml\n\ndef load():\n    return yaml.load('a: 1')\n"},
    )

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert exploitable(findings) == []
    assert ("app.py", "reachable-vulnerability", 4) in rules(findings)


def test_safe_versions_produce_nothing(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {"requirements.txt": "pyyaml==6.0\n", "app.py": "import yaml\n\ndef load():\n    return yaml.load(input())\n"},
    )
    assert engine.analyze_project(root, [PLUGINS]).findings == ()


def test_correlation_crosses_functions_and_files(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "requirements.txt": VULNERABLE,
            "app/__init__.py": "",
            "app/config.py": "import yaml\n\ndef parse(text):\n    return yaml.load(text)\n",
            "app/main.py": "from app.config import parse\n\ndef run():\n    parse(input())\n",
        },
    )

    findings = engine.analyze_project(root, [PLUGINS]).findings

    (finding,) = exploitable(findings)
    assert Path(str(finding.span.source_id)).name == "main.py"
    assert finding.span.start_line == 4
    assert finding.function == "run"
    assert finding.metadata["through"] == "app.config.parse"
    assert finding.metadata["sink_line"] == "4"


def test_refuted_flows_are_not_exploitable(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "requirements.txt": VULNERABLE,
            "app.py": "import yaml\n\ndef load():\n    data = input()\n    if not data.isdigit():\n        return None\n    return yaml.load(data)\n",
        },
    )

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert exploitable(findings) == []
    assert ("app.py", "reachable-vulnerability", 7) in rules(findings)


def test_hotspot_flows_are_reported_with_medium_confidence(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "requirements.txt": VULNERABLE,
            "app.py": "import yaml\n\ndef load():\n    data = input()\n    if data:\n        return yaml.load(data)\n",
        },
    )

    (finding,) = exploitable(engine.analyze_project(root, [PLUGINS]).findings)

    assert finding.confidence is Confidence.MEDIUM
    assert finding.metadata["verdict"] == "hotspot"


def test_advisory_sinks_do_not_trigger_the_generic_detectors(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {"requirements.txt": VULNERABLE, "app.py": "import yaml\n\ndef load():\n    return yaml.load(input())\n"},
    )

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert not any(f.rule_id in {"command-injection", "sql-injection", "xss", "ssrf", "path-traversal"} for f in findings)


def test_single_files_have_no_dependency_context() -> None:
    findings = engine.check(
        SourceManager().add_source("one.py", "import yaml\n\ndef load():\n    return yaml.load(input())\n"),
        [PLUGINS],
    )
    assert findings == ()


def test_correlate_is_a_pure_function() -> None:
    assert correlate("f", (), None, {}) == ()
