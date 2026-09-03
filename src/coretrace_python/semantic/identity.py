"""Canonical symbol identities (architecture §4.3).

A ``SymbolId`` names a Python object independently of how a file spells it: every way
of importing ``os.system`` yields ``python.os.system``. Framework models may live in
their own namespaces, such as ``flask.request.args``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class SymbolId:
    """A stable, import-style-independent, namespace-qualified dotted name."""

    canonical_name: str

    def __post_init__(self) -> None:
        components = self.canonical_name.split(".")
        if len(components) < 2:
            raise ValueError("a canonical symbol needs a namespace and a path")
        if not all(component.isidentifier() for component in components):
            raise ValueError(f"invalid canonical symbol: {self.canonical_name!r}")

    @classmethod
    def from_python_path(cls, path: str) -> SymbolId:
        normalized_path = path.removeprefix("python.")
        if not normalized_path or normalized_path.startswith("."):
            raise ValueError("a Python symbol path cannot be empty")
        return cls(f"python.{normalized_path}")

    def attribute(self, name: str) -> SymbolId:
        if not name or "." in name:
            raise ValueError("an attribute name must be one non-empty component")
        return SymbolId(f"{self.canonical_name}.{name}")

    def __str__(self) -> str:
        return self.canonical_name
