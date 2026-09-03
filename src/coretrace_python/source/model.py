"""Immutable source files and locations shared by engine layers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, order=True)
class SourceId:
    """Stable identity for a source unit within an analysis invocation."""

    value: str

    def __post_init__(self) -> None:
        if not self.value:
            raise ValueError("source ID cannot be empty")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class SourceSpan:
    """One-based, half-open source range."""

    source_id: SourceId
    start_line: int
    start_column: int
    end_line: int | None = None
    end_column: int | None = None

    def __post_init__(self) -> None:
        if self.start_line < 1 or self.start_column < 1:
            raise ValueError("source span start must be one-based")
        if (self.end_line is None) != (self.end_column is None):
            raise ValueError("source span end line and column must be provided together")
        if self.end_line is not None and self.end_column is not None:
            if self.end_line < self.start_line:
                raise ValueError("source span cannot end before it starts")
            if self.end_line == self.start_line and self.end_column < self.start_column:
                raise ValueError("source span cannot end before it starts")

    def display(self) -> str:
        return f"{self.source_id}:{self.start_line}:{self.start_column}"


@dataclass(frozen=True)
class SourceFile:
    """Decoded source text, its identity and its dotted module name."""

    source_id: SourceId
    text: str
    module_name: str
    path: Path | None = None
    is_package: bool = False

