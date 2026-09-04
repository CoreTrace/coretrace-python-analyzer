"""Analysis coverage: which files and functions a run actually looked at.

"No findings" only means something when the reader knows what was analysed. Each file
is ``analysed``, a ``syntax-error`` (the frontend rejected it) or ``unreadable`` (it could
not be decoded); analysed files count their functions and how many lowered.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FileCoverage:
    path: str
    status: str
    functions: int
    analysed: int


@dataclass(frozen=True)
class Coverage:
    details: tuple[FileCoverage, ...] = ()

    @property
    def files(self) -> int:
        return len(self.details)

    @property
    def files_analysed(self) -> int:
        return sum(1 for d in self.details if d.status == "analysed")

    @property
    def functions(self) -> int:
        return sum(d.functions for d in self.details)

    @property
    def functions_analysed(self) -> int:
        return sum(d.analysed for d in self.details)

    def summary(self) -> str:
        return (
            f"coverage: {self.files_analysed}/{self.files} files, "
            f"{self.functions_analysed}/{self.functions} functions"
        )
