"""Acceptance tests for issue #210: dependency maps of npm lock files.

In ``package-lock.json`` and ``npm-shrinkwrap.json``, the keys of a dependency map
(``dependencies``, ``devDependencies``, ``peerDependencies``, ``optionalDependencies``,
``requires``) are package names and its values version ranges: ``"js-tokens": "^4.0.0"``
is not a credential named ``js-tokens``. The keys of a ``bin`` map are command names and
its values paths: ``"secretlint": "bin/secretlint.js"`` is not a secret either. The lock file is still scanned: a ``resolved``
URL carrying a private-registry credential is a real leak, and a credential-named key
outside a dependency map is still a credential. Other JSON files are judged as before.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding

PLUGINS = Path(__file__).resolve().parent.parent / "src" / "coretrace_python" / "bundled"
TOKEN = "Zx81kQpLw0RtY7vBn3MsD9cF2hJ6gK4a"


def scan(tmp_path: Path, name: str, document: object) -> list[Finding]:
    (tmp_path / name).write_text(json.dumps(document, indent=2), encoding="utf-8")
    findings = engine.analyze_project(tmp_path, [PLUGINS]).findings
    return [f for f in findings if f.rule_id in ("hardcoded-credential", "hardcoded-secret")]


LOCK_V3 = {
    "name": "web",
    "lockfileVersion": 3,
    "packages": {
        "": {"dependencies": {"js-tokens": "^4.0.0"}, "devDependencies": {"tokenizer": "^1.0.0"}},
        "node_modules/loose-envify": {
            "version": "1.4.0",
            "dependencies": {"js-tokens": "^3.0.0 || ^4.0.0"},
            "peerDependencies": {"secret-handshake": ">=1"},
            "optionalDependencies": {"api-key-utils": "^2.0.0"},
        },
        "node_modules/secretlint": {"version": "9.0.0", "bin": {"secretlint": "bin/secretlint.js"}},
    },
}
LOCK_V1 = {
    "name": "web",
    "lockfileVersion": 1,
    "dependencies": {"loose-envify": {"version": "1.4.0", "requires": {"js-tokens": "^4.0.0"}}},
}


@pytest.mark.parametrize("name", ["package-lock.json", "npm-shrinkwrap.json"])
@pytest.mark.parametrize("document", [LOCK_V3, LOCK_V1], ids=["v3", "v1"])
def test_package_names_in_dependency_maps_are_not_credentials(
    tmp_path: Path, name: str, document: object
) -> None:
    assert scan(tmp_path, name, document) == []


def test_a_resolved_url_carrying_a_credential_is_still_reported(tmp_path: Path) -> None:
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "node_modules/js-tokens": {
                "version": "4.0.0",
                "resolved": f"https://ci:{TOKEN}@npm.registry.example/js-tokens/-/js-tokens-4.0.0.tgz",
            }
        },
    }

    (finding,) = scan(tmp_path, "package-lock.json", lock)

    assert (finding.rule_id, finding.metadata["provider"]) == ("hardcoded-secret", "url")


def test_a_credential_name_outside_a_dependency_map_is_still_reported(tmp_path: Path) -> None:
    (finding,) = scan(tmp_path, "package-lock.json", {"lockfileVersion": 3, "auth_token": TOKEN})

    assert finding.rule_id == "hardcoded-credential"


def test_dependency_maps_of_other_json_files_are_judged_as_before(tmp_path: Path) -> None:
    (finding,) = scan(tmp_path, "settings.json", {"dependencies": {"api_token": TOKEN}})

    assert finding.rule_id == "hardcoded-credential"
