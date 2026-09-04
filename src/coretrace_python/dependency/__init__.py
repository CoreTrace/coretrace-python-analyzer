"""Dependency resolution and advisories (architecture §26)."""

from coretrace_python.dependency.advisories import (
    ADVISORY_FILE,
    AdvisoryFileError,
    dump_advisories,
    import_osv,
    load_advisories,
    read_osv,
)
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
from coretrace_python.dependency.policy import POLICY_FILE, Policy, apply_policy, load_policy
from coretrace_python.dependency.sbom import render_sbom

__all__ = [
    "ADVISORY_FILE",
    "DEPENDENCY_FILES",
    "POLICY_FILE",
    "Advisory",
    "AdvisoryFileError",
    "DependencyAnalysis",
    "DependencyGraph",
    "Policy",
    "Requirement",
    "Version",
    "apply_policy",
    "dump_advisories",
    "import_osv",
    "load_advisories",
    "load_policy",
    "normalize",
    "parse_dependencies",
    "read_osv",
    "render_sbom",
]
