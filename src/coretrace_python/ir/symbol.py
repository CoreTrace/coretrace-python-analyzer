"""Canonical symbol identities stored in PyIR."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class SymbolId:
    """A stable, import-style-independent name for a Python object."""

    canonical_name: str

    def __post_init__(self) -> None:
        if not self.canonical_name.startswith("python."):
            raise ValueError("canonical Python symbols must start with 'python.'")

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

