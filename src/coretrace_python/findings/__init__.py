"""Normalized findings produced by plugins and consumed by reporters."""

from coretrace_python.findings.coverage import Coverage, FileCoverage
from coretrace_python.findings.model import (
    FINDING_SCHEMA_VERSION,
    Confidence,
    Finding,
    RelatedLocation,
    Severity,
)
from coretrace_python.findings.provenance import ADVISORIES, PLUGIN, Component
from coretrace_python.findings.rules import RuleDescription

__all__ = [
    "ADVISORIES",
    "FINDING_SCHEMA_VERSION",
    "PLUGIN",
    "Component",
    "Confidence",
    "Coverage",
    "FileCoverage",
    "Finding",
    "RelatedLocation",
    "RuleDescription",
    "Severity",
]
