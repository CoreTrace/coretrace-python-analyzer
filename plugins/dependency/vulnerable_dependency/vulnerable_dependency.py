"""Requirements that allow a version an advisory marks as vulnerable."""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar

from coretrace_python.analysis import AnyAnalysis
from coretrace_python.dependency import DependencyAnalysis
from coretrace_python.findings import Confidence, Finding
from coretrace_python.plugins import ProjectContext, ProjectPlugin


class VulnerableDependencyPlugin(ProjectPlugin):
    name: ClassVar[str] = "vulnerable-dependency"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({DependencyAnalysis})

    def analyze_project(self, ctx: ProjectContext) -> Sequence[Finding]:
        findings: list[Finding] = []
        for requirement in ctx.dependencies.requirements:
            for advisory in ctx.advisories:
                if not advisory.affects(requirement):
                    continue
                pinned = requirement.pinned is not None
                findings.append(
                    Finding(
                        rule_id="vulnerable-dependency",
                        message=(
                            f"{advisory.id}: {advisory.package} {advisory.vulnerable} is "
                            f"{'required' if pinned else 'allowed'} by {requirement.name}"
                            f"{requirement.specifier or ''}: {advisory.summary}"
                        ),
                        severity=advisory.severity,
                        confidence=Confidence.HIGH if pinned else Confidence.MEDIUM,
                        span=requirement.span,
                        metadata={
                            "advisory": advisory.id,
                            "package": advisory.package,
                            "specifier": requirement.specifier,
                        },
                    )
                )
        return findings
