"""Acceptance tests for hex digests in the secret scanners (issue #71).

On real projects, pure-hex strings of digest length (MD5, SHA-1, SHA-256, SHA-512) under
names such as ``version``, ``sha`` or ``checksum`` flooded ``high-entropy-string``: 5 500
findings in one library's benchmark results, all commit ids. A hex digest is not a secret
unless its name says so: a digest-shaped value, or a hex value whose name names a hash,
is skipped by the entropy rule, while a credential-like name still reports it.

Expected to remain red until ``coretrace_python.plugins.secrets.looks_like_digest`` exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.plugins import secrets
from coretrace_python.source import SourceManager

MISSING = None if hasattr(secrets, "looks_like_digest") else "looks_like_digest is missing"


@pytest.fixture(autouse=True)
def require_digests() -> None:
    if MISSING is not None:
        pytest.fail(f"hex digest handling is not implemented yet: {MISSING}")


REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "src" / "coretrace_python" / "bundled"

SHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
SHA1 = "0a3fcb9c2b4d6e8f1a3c5e7b9d1f3a5c7e9b1d3f"
MD5 = "d41d8cd98f00b204e9800998ecf8427e"
HEX48 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822c"


def check(text: str) -> tuple[Finding, ...]:
    return engine.check(SourceManager().add_source("m.py", text), [PLUGINS])


def rules(findings: tuple[Finding, ...]) -> list[str]:
    return sorted(f.rule_id for f in findings)


def test_digest_shaped_hex_values_are_not_secrets() -> None:
    assert looks(SHA256, None) and looks(SHA1, "commit") and looks(MD5, "checksum_md5")
    assert not looks(HEX48, None)
    assert not looks("Qm9vdHN0cmFwcGluZyBhIHJhbmRvbSBrZXkgMjA0OA==", "digest")
    assert check(f"digest = '{SHA256}'\nCOMMIT = '{SHA1}'\nchecksum = '{MD5}'\nblob = '{SHA256}'\n") == ()


def looks(value: str, name: str | None) -> bool:
    return secrets.looks_like_digest(value, name)


def test_hex_values_named_after_a_hash_are_not_secrets_whatever_their_length() -> None:
    assert looks(HEX48, "file_sha") and looks(HEX48, "etag") and looks(HEX48, "fingerprint")
    assert check(f"file_sha = '{HEX48}'\n") == ()


def test_other_hex_values_and_credential_names_are_still_reported() -> None:
    assert rules(check(f"blob = '{HEX48}'\n")) == ["high-entropy-string"]
    assert rules(check(f"api_key = '{SHA256}'\n")) == ["hardcoded-credential"]
    assert rules(check(f"password_hash = '{SHA256}'\n")) == ["hardcoded-credential"]


SRI = "sha512-Qm9vdHN0cmFwcGluZyBhIHJhbmRvbSBrZXkgMjA0OA/Qm9vdHN0cmFwcGluZyBhIHJhbmRvbSBrZXkgMjA0OA=="


def test_subresource_integrity_hashes_and_alphabets_are_not_secrets(tmp_path: Path) -> None:
    assert looks(SRI, None) and looks(SRI, "integrity")
    assert check("BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'\n") == ()
    (tmp_path / "app.py").write_text("", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(f'{{"integrity": "{SRI}"}}\n', encoding="utf-8")

    assert engine.analyze_project(tmp_path, [PLUGINS]).findings == ()


def test_configuration_files_follow_the_same_rule(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("", encoding="utf-8")
    (tmp_path / "results.json").write_text(f'{{"version": "{SHA256}", "token": "{SHA256}"}}\n', encoding="utf-8")

    findings = engine.analyze_project(tmp_path, [PLUGINS]).findings

    assert [(f.rule_id, f.metadata["name"]) for f in findings] == [("hardcoded-credential", "token")]
