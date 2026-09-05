"""Acceptance tests for credentials in test code and example files (issue #71).

On real projects most ``hardcoded-credential`` findings sit in test fixtures (37 of 39 in
healthchecks) or in ``.env.example`` files: a password there is a fixture or a template,
not a leak, but a real one can still slip in. Such findings are reported at low
confidence with the context in their metadata; provider-format secrets keep their
confidence wherever they are, since a real key in a test is still a key.

Expected to remain red until ``coretrace_python.plugins.secrets.credential_context`` exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Confidence, Finding
from coretrace_python.plugins import secrets
from coretrace_python.source import SourceManager

MISSING = None if hasattr(secrets, "credential_context") else "credential_context is missing"


@pytest.fixture(autouse=True)
def require_context() -> None:
    if MISSING is not None:
        pytest.fail(f"credential context is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"

PASSWORD = "password = 'hunter2-not-a-placeholder'\n"
AWS = "key = 'AKIAIOSFODNN7EXAMPLE'\n"


def check(name: str, text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source(name, text), [PLUGINS])


def test_paths_are_classified() -> None:
    assert secrets.credential_context("app/tests/test_login.py") == "test"
    assert secrets.credential_context("app/test_views.py") == "test"
    assert secrets.credential_context("app/views_test.py") == "test"
    assert secrets.credential_context("conftest.py") == "test"
    assert secrets.credential_context("fixtures/users.json") == "test"
    assert secrets.credential_context("docker/.env.example") == "example"
    assert secrets.credential_context("config.yaml.sample") == "example"
    assert secrets.credential_context("settings.template.toml") is None
    assert secrets.credential_context("app/views.py") is None
    assert secrets.credential_context("latest_results.py") is None


def test_credentials_in_test_code_are_low_confidence() -> None:
    (finding,) = check("app/tests/test_login.py", PASSWORD)

    assert finding.rule_id == "hardcoded-credential"
    assert finding.confidence is Confidence.LOW
    assert finding.metadata["context"] == "test"


def test_credentials_in_production_code_keep_medium_confidence() -> None:
    (finding,) = check("app/views.py", PASSWORD)

    assert finding.confidence is Confidence.MEDIUM
    assert "context" not in finding.metadata


def test_provider_secrets_keep_their_confidence_in_tests() -> None:
    (finding,) = check("app/tests/test_s3.py", AWS)

    assert finding.rule_id == "hardcoded-secret"
    assert finding.confidence is Confidence.HIGH


def test_example_configuration_files_are_low_confidence(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("", encoding="utf-8")
    (tmp_path / ".env.example").write_text("DB_PASSWORD=hunter2-not-a-placeholder\n", encoding="utf-8")
    (tmp_path / "docker-compose.yml").write_text("services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: hunter2-not-a-placeholder\n", encoding="utf-8")

    findings = sorted(engine.analyze_project(tmp_path, [PLUGINS]).findings, key=lambda f: str(f.span.source_id))

    assert [(Path(str(f.span.source_id)).name, f.confidence) for f in findings] == [
        (".env.example", Confidence.LOW),
        ("docker-compose.yml", Confidence.MEDIUM),
    ]
