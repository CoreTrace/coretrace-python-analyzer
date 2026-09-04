"""Normalized findings produced by plugins and consumed by reporters."""

from coretrace_python.findings.coverage import Coverage, FileCoverage
from coretrace_python.findings.model import FINDING_SCHEMA_VERSION, Confidence, Finding, Severity

__all__ = [
    "FINDING_SCHEMA_VERSION",
    "Confidence",
    "Coverage",
    "FileCoverage",
    "Finding",
    "Severity",
]
