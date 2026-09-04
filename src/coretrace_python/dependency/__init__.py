"""Dependency resolution and advisories (architecture §26)."""

from coretrace_python.dependency.graph import (
    DEPENDENCY_FILES,
    Advisory,
    DependencyAnalysis,
    DependencyGraph,
    Requirement,
    Version,
    normalize,
    parse_dependencies,
)
from coretrace_python.dependency.sbom import render_sbom

__all__ = [
    "DEPENDENCY_FILES",
    "Advisory",
    "DependencyAnalysis",
    "DependencyGraph",
    "Requirement",
    "Version",
    "normalize",
    "parse_dependencies",
    "render_sbom",
]
