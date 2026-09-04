"""Acceptance tests for secret detection and SBOM generation (``docs/architecture.md``
§25 plugins/secrets, §26; roadmap issue #37).

Secrets are string literals of the PyHIR: a ``SecretDetector`` base walks every literal
with the name it is bound to (assignment target, keyword, dictionary key) and reports at
most one finding per literal, provider patterns first, then credential-like names, then
entropy alone. Messages and metadata never contain the secret itself.

The SBOM is a CycloneDX document rendered from the dependency graph and the advisories
that affect it; ``--sbom PATH`` writes it during a directory check.

Expected to remain red until ``coretrace_python.plugins.secrets``,
``coretrace_python.dependency.sbom``, the ``hardcoded-secrets`` plugin and ``--sbom`` exist.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cli import main
from coretrace_python.dependency import Advisory, parse_dependencies
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.frontend import build_hir
from coretrace_python.plugins import run_plugins
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager

try:
    from coretrace_python.dependency.sbom import render_sbom
    from coretrace_python.plugins.secrets import (
        SecretDetector,
        SecretPattern,
        literals,
        shannon_entropy,
    )
except ImportError as error:  # pragma: no cover - red until secrets and SBOM land
    MISSING = error
else:
    MISSING = None


@pytest.fixture(autouse=True)
def require_secrets() -> None:
    if MISSING is not None:
        pytest.fail(f"secrets and SBOM are not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
RANDOM_BASE64 = "Qm9vdHN0cmFwcGluZyBhIHJhbmRvbSBrZXkgMjA0OA=="
RANDOM_HEX = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("settings.py", text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[str]:
    return [f.rule_id for f in findings]


# --------------------------------------------------------------------------- base


def test_shannon_entropy_measures_bits_per_character() -> None:
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == 2
    assert shannon_entropy(RANDOM_HEX) > 3.5
    assert shannon_entropy(RANDOM_BASE64) > 4.5
    assert shannon_entropy("the quick brown fox jumps over the lazy dog") < 4.5


def test_literals_carry_the_name_they_are_bound_to() -> None:
    module = build_hir(
        SourceManager().add_source(
            "m.py",
            "PASSWORD = 'a'\n"
            "db.connect(host='h', password='b')\n"
            "config = {'api_key': 'c', 'debug': True}\n"
            "def f():\n    token = 'd'\n    return 'e'\n"
            "class C:\n    secret = 'f'\n"
            "x: str = 'g'\n"
            "y: int\n",
        )
    )

    found = [(value, name, span.start_line, function) for value, name, span, function in literals(module)]

    assert found == [
        ("a", "PASSWORD", 1, None),
        ("h", "host", 2, None),
        ("b", "password", 2, None),
        ("c", "api_key", 3, None),
        ("d", "token", 5, "f"),
        ("e", None, 6, "f"),
        ("f", "secret", 8, None),
        ("g", "x", 9, None),
    ]


def test_a_detector_reports_one_finding_per_literal_provider_first() -> None:
    class Detector(SecretDetector):
        name = "d"
        patterns = (SecretPattern("acme", r"acme_[a-z0-9]{16}"),)
        credential_names = ("secret",)

    module = build_hir(
        SourceManager().add_source("m.py", "secret = 'acme_0123456789abcdef'\nother = 'acme_fedcba9876543210'\n")
    )
    findings = run_plugins(engine.build_manager(module), [Detector()])

    assert [(f.rule_id, f.metadata["provider"], f.span.start_line) for f in findings] == [
        ("hardcoded-secret", "acme", 1),
        ("hardcoded-secret", "acme", 2),
    ]


# --------------------------------------------------------------------------- shipped plugin


def test_shipped_secret_plugin_loads() -> None:
    from coretrace_python.plugins import discover_plugins

    module = build_hir(SourceManager().add_source("empty.py", ""))
    loaded = {p.manifest.name: p.manifest for p in discover_plugins(PLUGINS, engine.build_manager(module))}

    assert loaded["hardcoded-secrets"].provides == ("secret.provider-patterns", "secret.credentials", "secret.entropy")
    assert loaded["hardcoded-secrets"].requires == ()


def test_provider_keys_are_high_confidence_and_never_echoed() -> None:
    (finding,) = check(f"AWS_ACCESS_KEY_ID = '{AWS_KEY}'\n")

    assert finding.rule_id == "hardcoded-secret"
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.HIGH
    assert finding.metadata["provider"] == "aws"
    assert finding.metadata["name"] == "AWS_ACCESS_KEY_ID"
    assert finding.span.start_line == 1
    assert AWS_KEY not in finding.message
    assert all(AWS_KEY not in value for value in finding.metadata.values())
    assert "AKIA" in finding.message and "20 characters" in finding.message


@pytest.mark.parametrize(
    ("provider", "literal"),
    [
        ("aws", AWS_KEY),
        ("github", GITHUB_TOKEN),
        ("github", "github_pat_" + "A" * 22 + "_" + "b" * 59),
        ("slack", "xoxb-" + "1234567890-1234567890123-" + "AbCdEfGhIjKlMnOpQrStUvWx"),
        ("stripe", "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"),
        ("google", "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"),
        ("private-key", "-----BEGIN RSA PRIVATE KEY-----\\nMIIE\\n-----END RSA PRIVATE KEY-----"),
        ("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
        ("sendgrid", "SG." + "a" * 22 + "." + "b" * 43),
        ("twilio", "SK" + "0123456789abcdef" * 2),
    ],
)
def test_provider_patterns(provider: str, literal: str) -> None:
    (finding,) = check(f"value = '{literal}'\n")
    assert (finding.rule_id, finding.metadata["provider"]) == ("hardcoded-secret", provider)


def test_credential_names_with_a_real_value_are_medium_confidence() -> None:
    findings = check(
        "password = 'hunter2'\n"
        "db.connect(host='localhost', passwd='s3cr3t!')\n"
        "settings = {'api_key': 'k-1234', 'timeout': '30'}\n"
        "SECRET_KEY = 'django-insecure-abc'\n"
    )

    assert rules(findings) == ["hardcoded-credential"] * 4
    assert [f.confidence for f in findings] == [Confidence.MEDIUM] * 4
    assert [f.metadata["name"] for f in findings] == ["password", "passwd", "api_key", "SECRET_KEY"]
    assert "hunter2" not in findings[0].message


def test_placeholders_and_indirections_are_not_credentials() -> None:
    assert check(
        "password = ''\n"
        "token = 'changeme'\n"
        "api_key = '<your-api-key>'\n"
        "secret = '${DB_SECRET}'\n"
        "passwd = os.environ['PASSWD']\n"
        "password = input()\n"
        "PASSWORD_FIELD = 'password'\n"
        "key = 'xxxxxxxx'\n"
        "secret_name = 'db-secret'\n"
    ) == ()


def test_high_entropy_tokens_without_context_are_low_confidence() -> None:
    (finding,) = check(f"blob = '{RANDOM_BASE64}'\n")

    assert finding.rule_id == "high-entropy-string"
    assert finding.confidence is Confidence.LOW
    assert finding.severity is Severity.MEDIUM
    assert finding.metadata["entropy"].startswith("4.")
    assert RANDOM_BASE64 not in finding.message


def test_hex_digests_count_as_high_entropy() -> None:
    (finding,) = check(f"digest = '{RANDOM_HEX}'\n")
    assert finding.rule_id == "high-entropy-string"


def test_prose_urls_and_short_strings_are_not_secrets() -> None:
    assert check(
        "MESSAGE = 'The quick brown fox jumps over the lazy dog and keeps running'\n"
        "URL = 'https://example.com/api/v1/resources/0123456789abcdef'\n"
        "PATH = '/usr/local/lib/python3.12/site-packages/x'\n"
        "SHORT = 'abc123'\n"
        "ident = 'f47ac10b-58cc-4372-a567-0e02b2c3d479'\n"
    ) == ()


def test_secrets_are_found_inside_functions_and_classes() -> None:
    findings = check(
        f"def connect():\n    return client(token='{GITHUB_TOKEN}')\n\n"
        "class Settings:\n    password = 'hunter2'\n"
    )

    assert [(f.rule_id, f.span.start_line, f.function) for f in findings] == [
        ("hardcoded-secret", 2, "connect"),
        ("hardcoded-credential", 5, None),
    ]


def test_secret_findings_render_with_a_redacted_message(capsys) -> None:  # type: ignore[no-untyped-def]
    path = Path(__file__).parent / "_secret_sample.py"
    path.write_text(f"token = '{GITHUB_TOKEN}'\n", encoding="utf-8")
    try:
        code = main(["--check", str(path), "--plugins", str(PLUGINS), "--format", "json"])
        output = capsys.readouterr().out
    finally:
        path.unlink()

    assert code == 1
    assert "hardcoded-secret" in output
    assert GITHUB_TOKEN not in output


# --------------------------------------------------------------------------- SBOM


ADVISORY = Advisory("CVE-2020-1747", "pyyaml", "<5.4", "unsafe load", Severity.CRITICAL, (SymbolId("python.yaml.load"),))


def graph_for(text: str, name: str = "requirements.txt"):  # type: ignore[no-untyped-def]
    return parse_dependencies(SourceManager().add_source(name, text))


def test_sbom_is_cyclonedx_with_one_component_per_requirement() -> None:
    document = json.loads(render_sbom(graph_for("pyyaml==5.3.1\nrequests>=2.20\nFlask\n"), (), "coretrace", "0.1.0"))

    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert document["metadata"]["tools"]["components"] == [{"type": "application", "name": "coretrace", "version": "0.1.0"}]
    assert [c["name"] for c in document["components"]] == ["flask", "pyyaml", "requests"]
    pyyaml = document["components"][1]
    assert pyyaml == {
        "type": "library",
        "bom-ref": "pkg:pypi/pyyaml@5.3.1",
        "name": "pyyaml",
        "version": "5.3.1",
        "purl": "pkg:pypi/pyyaml@5.3.1",
        "properties": [{"name": "coretrace:specifier", "value": "==5.3.1"}],
    }
    assert "version" not in document["components"][2]
    assert document["components"][2]["purl"] == "pkg:pypi/requests"
    assert document["vulnerabilities"] == []


def test_sbom_lists_advisories_affecting_the_requirements() -> None:
    document = json.loads(render_sbom(graph_for("pyyaml==5.3.1\nrequests==2.31.0\n"), (ADVISORY,), "coretrace", "0.1.0"))

    assert document["vulnerabilities"] == [
        {
            "id": "CVE-2020-1747",
            "description": "unsafe load",
            "ratings": [{"severity": "critical"}],
            "affects": [{"ref": "pkg:pypi/pyyaml@5.3.1"}],
        }
    ]


def test_sbom_marks_optional_requirements_and_is_stable() -> None:
    text = '[project]\nname = "x"\ndependencies = ["a==1.0"]\n[project.optional-dependencies]\ndev = ["b>=2"]\n'
    first = render_sbom(graph_for(text, "pyproject.toml"), (), "coretrace", "0.1.0")
    second = render_sbom(graph_for(text, "pyproject.toml"), (), "coretrace", "0.1.0")

    assert first == second
    (a, b) = json.loads(first)["components"]
    assert a["properties"] == [{"name": "coretrace:specifier", "value": "==1.0"}]
    assert b["properties"] == [
        {"name": "coretrace:specifier", "value": ">=2"},
        {"name": "coretrace:optional", "value": "true"},
    ]


def test_project_analysis_exposes_the_advisories_it_used(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("pyyaml==5.3.1\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    analysis = engine.analyze_project(tmp_path, [PLUGINS])

    assert any(a.id == "CVE-2020-1747" for a in analysis.advisories)
    assert engine.analyze_project(tmp_path).advisories == ()


def test_check_writes_the_sbom_next_to_the_report(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    root = tmp_path / "src"
    root.mkdir()
    (root / "requirements.txt").write_text("pyyaml==5.3.1\n", encoding="utf-8")
    (root / "app.py").write_text("import yaml\n\ndef load(t):\n    return yaml.load(t)\n", encoding="utf-8")
    sbom = tmp_path / "bom.json"

    code = main(["--check", str(root), "--plugins", str(PLUGINS), "--sbom", str(sbom)])
    output = capsys.readouterr().out

    assert code == 1
    assert "vulnerable-dependency" in output
    document = json.loads(sbom.read_text(encoding="utf-8"))
    assert [c["purl"] for c in document["components"]] == ["pkg:pypi/pyyaml@5.3.1"]
    assert [v["id"] for v in document["vulnerabilities"]] == ["CVE-2020-1747"]


def test_sbom_option_requires_a_directory_check(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = tmp_path / "x.py"
    source.write_text("", encoding="utf-8")

    assert main(["--check", "--sbom", str(tmp_path / "bom.json"), str(source)]) == 2
    assert "--sbom" in capsys.readouterr().err
