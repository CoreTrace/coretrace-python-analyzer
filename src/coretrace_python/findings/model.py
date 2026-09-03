"""Normalized findings (architecture §23).

A finding references lightweight data only: a rule, a message, a source span and the
name of the enclosing function. It never carries CFG or taint-path copies; those are
reconstructed at report time.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType

from coretrace_python.source import SourceSpan

FINDING_SCHEMA_VERSION = 1


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


def _no_metadata() -> Mapping[str, str]:
    return MappingProxyType({})


@dataclass(frozen=True)
class Finding:
    rule_id: str
    message: str
    severity: Severity
    confidence: Confidence
    span: SourceSpan
    function: str | None = None
    metadata: Mapping[str, str] = field(default_factory=_no_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
