"""Requirements the project's policy denies or leaves unpinned."""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar

from coretrace_python.analysis import AnyAnalysis
from coretrace_python.dependency import DependencyAnalysis
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.plugins import ProjectContext, ProjectPlugin


class DependencyPolicyPlugin(ProjectPlugin):
    name: ClassVar[str] = "dependency-policy"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({DependencyAnalysis})

    def analyze_project(self, ctx: ProjectContext) -> Sequence[Finding]:
        findings: list[Finding] = []
        for requirement in ctx.dependencies.requirements:
            metadata = {"package": requirement.name, "specifier": requirement.specifier}
            if ctx.policy.denies(requirement.name):
                findings.append(
                    Finding(
                        "denied-dependency",
                        f"{requirement.name} is denied by the dependency policy",
                        Severity.HIGH,
                        Confidence.HIGH,
                        requirement.span,
                        None,
                        metadata,
                    )
                )
            elif ctx.policy.require_pinned and requirement.pinned is None:
                findings.append(
                    Finding(
                        "unpinned-dependency",
                        f"{requirement.name}{requirement.specifier} is not pinned to one version",
                        Severity.LOW,
                        Confidence.HIGH,
                        requirement.span,
                        None,
                        metadata,
                    )
                )
        return findings
