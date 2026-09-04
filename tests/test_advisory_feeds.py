"""Acceptance tests for local advisory feeds and dependency policies (``docs/architecture.md``
§26; roadmap issue #37, last point).

The analysis stays offline and deterministic: ``--import-advisories SRC OUT`` converts a
public OSV dump (a JSON file, a directory of them or a zip archive) into a local advisory
file once, and a directory check reads ``advisories.json`` at the project root or the
files passed with ``--advisories``. A ``coretrace-policy.toml`` at the root, or the file
passed with ``--policy``, denies packages, requires pins and accepts advisories.

Expected to remain red until ``coretrace_python.dependency.advisories``,
``coretrace_python.dependency.policy``, the ``dependency-policy`` plugin and the CLI
options exist.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cli import main
from coretrace_python.dependency import Advisory
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.semantic.symbols import SymbolId

try:
    from coretrace_python.dependency.advisories import (
        AdvisoryFileError,
        dump_advisories,
        import_osv,
        load_advisories,
        read_osv,
    )
    from coretrace_python.dependency.policy import Policy, apply_policy, load_policy
except ImportError as error:  # pragma: no cover - red until feeds and policies land
    MISSING: Exception | None = error
else:
    MISSING = None
    if "aliases" not in Advisory.__dataclass_fields__:
        MISSING = AttributeError("Advisory has no aliases")


@pytest.fixture(autouse=True)
def require_feeds() -> None:
    if MISSING is not None:
        pytest.fail(f"advisory feeds are not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "plugins"


def osv(identifier: str, package: str, events: list[dict[str, str]], **extra: object) -> dict[str, object]:
    return {
        "id": identifier,
        "summary": f"{identifier} summary",
        "details": "Long details.\nSecond line.",
        "aliases": ["CVE-2000-0001"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": package},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }
        ],
        **extra,
    }


def project(root: Path, files: dict[str, str]) -> Path:
    for relative, text in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def rules(findings: tuple[Finding, ...]) -> list[tuple[str, str, int]]:
    return sorted((Path(str(f.span.source_id)).name, f.rule_id, f.span.start_line) for f in findings)


# --------------------------------------------------------------------------- OSV import


def test_osv_ranges_become_version_specifiers() -> None:
    advisories = import_osv(
        [
            osv("GHSA-1", "PyYAML", [{"introduced": "0"}, {"fixed": "5.4"}]),
            osv("GHSA-2", "requests", [{"introduced": "1.0"}, {"fixed": "2.0"}]),
            osv("GHSA-3", "flask", [{"introduced": "1.0"}, {"last_affected": "1.5"}]),
            osv("GHSA-4", "django", [{"introduced": "3.0"}]),
        ]
    )

    assert [(a.id, a.package, a.vulnerable) for a in advisories] == [
        ("GHSA-1", "pyyaml", "<5.4"),
        ("GHSA-2", "requests", ">=1.0,<2.0"),
        ("GHSA-3", "flask", ">=1.0,<=1.5"),
        ("GHSA-4", "django", ">=3.0"),
    ]
    assert advisories[0].summary == "GHSA-1 summary"
    assert advisories[0].aliases == ("CVE-2000-0001",)
    assert advisories[0].affected_symbols == ()


def test_osv_severity_summary_and_ecosystem_handling() -> None:
    critical = osv("GHSA-5", "a", [{"introduced": "0"}], database_specific={"severity": "CRITICAL"})
    moderate = osv("GHSA-6", "b", [{"introduced": "0"}], database_specific={"severity": "MODERATE"})
    unknown = osv("GHSA-7", "c", [{"introduced": "0"}])
    unknown["summary"] = ""
    npm = osv("GHSA-8", "d", [{"introduced": "0"}])
    npm["affected"][0]["package"]["ecosystem"] = "npm"  # type: ignore[index]
    two_ranges = osv("GHSA-9", "e", [{"introduced": "0"}, {"fixed": "1.1"}])
    two_ranges["affected"][0]["ranges"].append(  # type: ignore[index]
        {"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}, {"fixed": "2.1"}]}
    )

    advisories = import_osv([critical, moderate, unknown, npm, two_ranges])

    assert [(a.id, a.severity) for a in advisories] == [
        ("GHSA-5", Severity.CRITICAL),
        ("GHSA-6", Severity.MEDIUM),
        ("GHSA-7", Severity.MEDIUM),
        ("GHSA-9", Severity.MEDIUM),
        ("GHSA-9", Severity.MEDIUM),
    ]
    assert advisories[2].summary == "Long details."
    assert [a.vulnerable for a in advisories if a.id == "GHSA-9"] == ["<1.1", ">=2.0,<2.1"]


def test_osv_dumps_are_read_from_files_directories_and_archives(tmp_path: Path) -> None:
    record = osv("GHSA-1", "pyyaml", [{"introduced": "0"}, {"fixed": "5.4"}])
    single = tmp_path / "one.json"
    single.write_text(json.dumps(record), encoding="utf-8")
    listed = tmp_path / "list.json"
    listed.write_text(json.dumps([record, record | {"id": "GHSA-2"}]), encoding="utf-8")
    folder = tmp_path / "osv"
    folder.mkdir()
    (folder / "a.json").write_text(json.dumps(record | {"id": "GHSA-3"}), encoding="utf-8")
    (folder / "b.json").write_text(json.dumps(record | {"id": "GHSA-4"}), encoding="utf-8")
    (folder / "notes.txt").write_text("ignored", encoding="utf-8")
    archive = tmp_path / "all.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("GHSA-5.json", json.dumps(record | {"id": "GHSA-5"}))
        bundle.writestr("README", "ignored")

    assert [r["id"] for r in read_osv(single)] == ["GHSA-1"]
    assert [r["id"] for r in read_osv(listed)] == ["GHSA-1", "GHSA-2"]
    assert [r["id"] for r in read_osv(folder)] == ["GHSA-3", "GHSA-4"]
    assert [r["id"] for r in read_osv(archive)] == ["GHSA-5"]


# --------------------------------------------------------------------------- local file


ADVISORY = (
    Advisory(
        "CVE-2020-1747",
        "pyyaml",
        "<5.4",
        "unsafe load",
        Severity.CRITICAL,
        (SymbolId("python.yaml.load"),),
        ("GHSA-8q59-q68h-6hv4",),
    )
    if MISSING is None
    else None
)


def test_advisory_files_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "advisories.json"
    path.write_text(dump_advisories((ADVISORY,)), encoding="utf-8")

    assert load_advisories(path) == (ADVISORY,)
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["schema"] == 1
    assert document["advisories"][0]["affected_symbols"] == ["python.yaml.load"]


def test_malformed_advisory_files_are_reported(tmp_path: Path) -> None:
    path = tmp_path / "advisories.json"
    path.write_text('{"schema": 1, "advisories": [{"id": "x"}]}', encoding="utf-8")
    with pytest.raises(AdvisoryFileError):
        load_advisories(path)
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(AdvisoryFileError):
        load_advisories(path)


def test_the_cli_imports_an_osv_dump(tmp_path: Path) -> None:
    source = tmp_path / "osv.json"
    source.write_text(json.dumps([osv("GHSA-1", "PyYAML", [{"introduced": "0"}, {"fixed": "5.4"}])]), encoding="utf-8")
    out = tmp_path / "advisories.json"

    assert main(["--import-advisories", str(source), str(out)]) == 0

    (advisory,) = load_advisories(out)
    assert (advisory.id, advisory.package, advisory.vulnerable) == ("GHSA-1", "pyyaml", "<5.4")


# --------------------------------------------------------------------------- feeds in a check


def test_projects_read_advisories_json_at_their_root(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "requirements.txt": "left-pad==1.0\n",
            "app.py": "x = 1\n",
            "advisories.json": dump_advisories(
                (Advisory("GHSA-LP", "left-pad", "<1.1", "padding overflow", Severity.HIGH),)
            ),
        },
    )

    analysis = engine.analyze_project(root, [PLUGINS])

    assert rules(analysis.findings) == [("requirements.txt", "vulnerable-dependency", 1)]
    assert any(a.id == "GHSA-LP" for a in analysis.advisories)


def test_advisory_files_are_passed_explicitly_and_feed_the_correlation(tmp_path: Path) -> None:
    feed = tmp_path / "feed.json"
    feed.write_text(dump_advisories((ADVISORY,)), encoding="utf-8")
    root = project(
        tmp_path / "src",
        {"requirements.txt": "pyyaml==5.3.1\n", "app.py": "import yaml\n\ndef load():\n    return yaml.load(input())\n"},
    )

    findings = engine.analyze_project(root, [PLUGINS], advisory_files=[feed]).findings

    assert rules(findings) == [
        ("app.py", "exploitable-vulnerability", 4),
        ("app.py", "insecure-deserialization", 4),
        ("app.py", "reachable-vulnerability", 4),
        ("requirements.txt", "vulnerable-dependency", 1),
    ]


def test_malformed_advisory_files_become_notes(tmp_path: Path) -> None:
    root = project(tmp_path, {"advisories.json": "{not json", "app.py": "x = 1\n"})

    (note,) = engine.analyze_project(root, [PLUGINS]).findings

    assert (note.rule_id, Path(str(note.span.source_id)).name) == ("syntax-error", "advisories.json")


def test_cli_accepts_advisory_files(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    feed = tmp_path / "feed.json"
    feed.write_text(dump_advisories((ADVISORY,)), encoding="utf-8")
    root = project(tmp_path / "src", {"requirements.txt": "pyyaml==5.3.1\n", "app.py": "x = 1\n"})

    assert main(["--check", str(root), "--plugins", str(PLUGINS), "--advisories", str(feed)]) == 1
    assert "vulnerable-dependency" in capsys.readouterr().out
    assert main(["--emit-ir", "--advisories", str(feed), str(root / "app.py")]) == 2
    assert "--advisories" in capsys.readouterr().err


# --------------------------------------------------------------------------- policies


POLICY = (
    "[dependencies]\n"
    'deny = ["pycrypto", "left-pad"]\n'
    "require_pinned = true\n\n"
    "[advisories]\n"
    'ignore = ["CVE-2020-1747"]\n'
)


def test_policies_load_from_toml(tmp_path: Path) -> None:
    path = tmp_path / "coretrace-policy.toml"
    path.write_text(POLICY, encoding="utf-8")

    policy = load_policy(path)

    assert policy == Policy(deny=("pycrypto", "left-pad"), require_pinned=True, ignore=("CVE-2020-1747",))
    assert Policy() == Policy(deny=(), require_pinned=False, ignore=())
    path.write_text("[dependencies]\ndeny = 3\n", encoding="utf-8")
    with pytest.raises(AdvisoryFileError):
        load_policy(path)


def test_accepted_advisories_drop_their_findings() -> None:
    from coretrace_python.source import SourceId, SourceSpan

    span = SourceSpan(SourceId("r.txt"), 1, 1)
    kept = Finding("vulnerable-dependency", "m", Severity.HIGH, Confidence.HIGH, span, None, {"advisory": "GHSA-X"})
    dropped = Finding("exploitable-vulnerability", "m", Severity.HIGH, Confidence.HIGH, span, "f", {"advisory": "CVE-2020-1747"})
    other = Finding("command-injection", "m", Severity.HIGH, Confidence.HIGH, span, "f")

    assert apply_policy(Policy(ignore=("CVE-2020-1747",)), (kept, dropped, other)) == (kept, other)


def test_denied_and_unpinned_requirements_are_reported(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "requirements.txt": "pycrypto==2.6.1\nrequests>=2.20\nflask==3.0.0\n",
            "coretrace-policy.toml": POLICY,
            "app.py": "x = 1\n",
        },
    )

    findings = engine.analyze_project(root, [PLUGINS]).findings

    assert rules(findings) == [
        ("requirements.txt", "denied-dependency", 1),
        ("requirements.txt", "unpinned-dependency", 2),
    ]
    denied = next(f for f in findings if f.rule_id == "denied-dependency")
    assert denied.severity is Severity.HIGH and denied.metadata["package"] == "pycrypto"
    unpinned = next(f for f in findings if f.rule_id == "unpinned-dependency")
    assert unpinned.severity is Severity.LOW and unpinned.metadata["specifier"] == ">=2.20"


def test_policies_silence_accepted_advisories_in_a_project(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "requirements.txt": "pyyaml==5.3.1\n",
            "coretrace-policy.toml": '[advisories]\nignore = ["CVE-2020-1747"]\n',
            "app.py": "import yaml\n\ndef load():\n    return yaml.load(input())\n",
        },
    )

    # The accepted advisory is silenced; the deserialization itself is not an advisory.
    assert [f.rule_id for f in engine.analyze_project(root, [PLUGINS]).findings] == ["insecure-deserialization"]


def test_policy_plugin_is_shipped_and_sees_the_policy() -> None:
    from coretrace_python.frontend import build_hir
    from coretrace_python.plugins import ProjectContext, discover_plugins
    from coretrace_python.source import SourceManager

    module = build_hir(SourceManager().add_source("empty.py", ""))
    loaded = {p.manifest.name: p.manifest for p in discover_plugins(PLUGINS, engine.build_manager(module))}

    assert loaded["dependency-policy"].provides == ("policy.dependencies",)
    assert "policy" in ProjectContext.__init__.__code__.co_varnames


def test_cli_accepts_a_policy_file(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    policy = tmp_path / "policy.toml"
    policy.write_text('[dependencies]\ndeny = ["flask"]\n', encoding="utf-8")
    root = project(tmp_path / "src", {"requirements.txt": "flask==3.0.0\n", "app.py": "x = 1\n"})

    assert main(["--check", str(root), "--plugins", str(PLUGINS), "--policy", str(policy)]) == 1
    assert "denied-dependency" in capsys.readouterr().out
    assert main(["--check", "--policy", str(policy), str(root / "app.py")]) == 2
    assert "--policy" in capsys.readouterr().err


def test_malformed_policies_become_notes(tmp_path: Path) -> None:
    root = project(tmp_path, {"coretrace-policy.toml": "deny = [", "app.py": "x = 1\n"})

    (note,) = engine.analyze_project(root, [PLUGINS]).findings

    assert (note.rule_id, Path(str(note.span.source_id)).name) == ("syntax-error", "coretrace-policy.toml")
