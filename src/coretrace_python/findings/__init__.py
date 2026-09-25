"""Normalized findings produced by plugins and consumed by reporters."""

from coretrace_python.findings.coverage import Coverage, FileCoverage
from coretrace_python.findings.model import FINDING_SCHEMA_VERSION, Confidence, Finding, Severity
from coretrace_python.findings.provenance import ADVISORIES, PLUGIN, Component

__all__ = [
    "ADVISORIES",
    "FINDING_SCHEMA_VERSION",
    "PLUGIN",
    "Component",
    "Confidence",
    "Coverage",
    "FileCoverage",
    "Finding",
    "Severity",
]
