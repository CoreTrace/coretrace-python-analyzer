"""Plugin manifests (architecture §14, §33).

A manifest is a ``plugin.toml`` file next to the plugin module::

    name = "sql-injection"
    version = "1.0.0"
    plugin_api = ">=1,<2"
    requires = ["semantic.symbols", "analysis.taint"]
    provides = ["vulnerability.sql-injection"]

    [entrypoint]
    module = "sql_injection"
    class = "SQLInjectionPlugin"
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path


class ManifestError(Exception):
    """A manifest that cannot be read, or that disagrees with its plugin."""


_CONSTRAINT = re.compile(r"^(>=|<=|==|>|<)?(\d+)$")
_COMPARE = {
    "==": lambda actual, wanted: actual == wanted,
    ">=": lambda actual, wanted: actual >= wanted,
    "<=": lambda actual, wanted: actual <= wanted,
    ">": lambda actual, wanted: actual > wanted,
    "<": lambda actual, wanted: actual < wanted,
}


@dataclass(frozen=True)
class VersionRange:
    """Integer API version constraints such as ``">=1,<2"`` or ``"1"``."""

    spec: str
    constraints: tuple[tuple[str, int], ...]

    @classmethod
    def parse(cls, spec: str) -> VersionRange:
        constraints: list[tuple[str, int]] = []
        for part in spec.split(","):
            match = _CONSTRAINT.match(part.strip())
            if match is None:
                raise ManifestError(f"invalid plugin_api range: {spec!r}")
            operator, number = match.groups()
            constraints.append((operator or "==", int(number)))
        return cls(spec, tuple(constraints))

    def contains(self, version: int) -> bool:
        return all(_COMPARE[operator](version, wanted) for operator, wanted in self.constraints)

    def __str__(self) -> str:
        return self.spec


@dataclass(frozen=True)
class Entrypoint:
    module: str
    class_name: str


@dataclass(frozen=True)
class PluginManifest:
    name: str
    version: str
    plugin_api: VersionRange
    requires: tuple[str, ...]
    provides: tuple[str, ...]
    entrypoint: Entrypoint


def load_manifest(path: Path) -> PluginManifest:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ManifestError(f"{path}: {error}") from error

    def string(key: str) -> str:
        value = data.get(key)
        if not isinstance(value, str) or not value:
            raise ManifestError(f"{path}: missing or invalid field '{key}'")
        return value

    def strings(key: str) -> tuple[str, ...]:
        value = data.get(key)
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ManifestError(f"{path}: missing or invalid field '{key}'")
        return tuple(value)

    entrypoint = data.get("entrypoint")
    if not isinstance(entrypoint, dict):
        raise ManifestError(f"{path}: missing or invalid field 'entrypoint'")
    module = entrypoint.get("module")
    class_name = entrypoint.get("class")
    if not isinstance(module, str) or not isinstance(class_name, str):
        raise ManifestError(f"{path}: entrypoint needs 'module' and 'class'")

    return PluginManifest(
        name=string("name"),
        version=string("version"),
        plugin_api=VersionRange.parse(string("plugin_api")),
        requires=strings("requires"),
        provides=strings("provides"),
        entrypoint=Entrypoint(module, class_name),
    )
