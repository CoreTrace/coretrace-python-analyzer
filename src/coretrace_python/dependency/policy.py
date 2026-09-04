"""Dependency policies (architecture §26).

A ``coretrace-policy.toml`` at the project root, or the file passed with ``--policy``,
denies packages, requires pinned versions and lists the advisories a project accepts,
whose findings are dropped whatever produced them.
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from coretrace_python.dependency.advisories import AdvisoryFileError
from coretrace_python.dependency.graph import normalize
from coretrace_python.findings import Finding

POLICY_FILE = "coretrace-policy.toml"


@dataclass(frozen=True)
class Policy:
    deny: tuple[str, ...] = ()
    require_pinned: bool = False
    ignore: tuple[str, ...] = ()

    def denies(self, package: str) -> bool:
        return normalize(package) in {normalize(name) for name in self.deny}


def load_policy(path: Path) -> Policy:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        dependencies = data.get("dependencies", {})
        advisories = data.get("advisories", {})
        return Policy(
            _strings(dependencies.get("deny", []), "dependencies.deny"),
            _boolean(dependencies.get("require_pinned", False), "dependencies.require_pinned"),
            _strings(advisories.get("ignore", []), "advisories.ignore"),
        )
    except AdvisoryFileError as error:
        raise AdvisoryFileError(f"{path}: {error}") from error
    except (OSError, tomllib.TOMLDecodeError, AttributeError) as error:
        raise AdvisoryFileError(f"{path}: {error}") from error


def _strings(value: Any, key: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise AdvisoryFileError(f"{key} must be a list of strings")
    return tuple(value)


def _boolean(value: Any, key: str) -> bool:
    if not isinstance(value, bool):
        raise AdvisoryFileError(f"{key} must be true or false")
    return value


def apply_policy(policy: Policy, findings: Iterable[Finding]) -> tuple[Finding, ...]:
    """The findings minus those about an advisory the policy accepts."""

    ignored = set(policy.ignore)
    return tuple(f for f in findings if f.metadata.get("advisory") not in ignored)
