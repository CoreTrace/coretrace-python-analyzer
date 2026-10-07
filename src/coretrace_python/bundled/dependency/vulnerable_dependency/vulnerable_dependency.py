"""Requirements that allow a version an advisory marks as vulnerable."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import PurePath
from typing import ClassVar

from coretrace_python.analysis import AnyAnalysis
from coretrace_python.dependency import Advisory, DependencyAnalysis, Requirement
from coretrace_python.dependency.correlation import (
    affected_entries,
    affected_symbols,
    check_conditions,
    ruled_out,
    suffix_index,
)
from coretrace_python.findings import Confidence, Finding
from coretrace_python.interprocedural import CallGraphAnalysis, ExternalSymbol
from coretrace_python.plugins import ProjectContext, ProjectPlugin


class VulnerableDependencyPlugin(ProjectPlugin):
    name: ClassVar[str] = "vulnerable-dependency"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({DependencyAnalysis, CallGraphAnalysis})

    def analyze_project(self, ctx: ProjectContext) -> Sequence[Finding]:
        findings: list[Finding] = []
        imported = [s for module in ctx.modules for s in ctx.imports(module).all_symbols()]
        excluded = _ruled_out(ctx)
        for requirement in ctx.dependencies.requirements:
            for advisory in ctx.advisories:
                if not advisory.affects(requirement):
                    continue
                pinned = requirement.pinned is not None
                level = "imported" if advisory.imported_by(imported) else "declared"
                metadata = {
                    "advisory": advisory.id,
                    "package": advisory.package,
                    "specifier": requirement.specifier,
                    "level": level,
                }
                if excluded.get(advisory.id):
                    metadata["ruled_out"] = "; ".join(excluded[advisory.id])
                findings.append(
                    Finding(
                        rule_id="vulnerable-dependency",
                        message=_message(ctx, advisory, requirement),
                        severity=advisory.severity,
                        confidence=Confidence.HIGH if pinned else Confidence.MEDIUM,
                        span=requirement.span,
                        metadata=metadata,
                    )
                )
        return findings


def _message(ctx: ProjectContext, advisory: Advisory, requirement: Requirement) -> str:
    """The evidence: for a locked package, the version the lock file pins and the
    packages that require it; for a declared requirement, the specifier that allows or
    requires a vulnerable version."""

    if requirement.locked is None:
        verb = "required" if requirement.pinned is not None else "allowed"
        return (
            f"{advisory.id}: {advisory.package} {advisory.vulnerable} is {verb} by "
            f"{requirement.name}{requirement.specifier or ''}: {advisory.summary}"
        )
    lock = PurePath(str(requirement.span.source_id)).name
    dependents = sorted(ctx.dependencies.required_by(requirement.name) or ())
    required = f" (required by {', '.join(dependents)})" if dependents else ""
    return (
        f"{advisory.id}: {advisory.package} {requirement.locked}, pinned in {lock}, "
        f"is in {advisory.vulnerable}{required}: {advisory.summary}"
    )


def _ruled_out(ctx: ProjectContext) -> dict[str, list[str]]:
    """By advisory, the calls to its entry points whose arguments contradict one of its
    conditions: the evidence that the requirement, imported, is not reached there."""

    affected = affected_symbols(ctx.dependencies, ctx.advisories)
    suffixes = suffix_index(affected, ctx.modules)
    excluded: dict[str, list[str]] = {}
    for module in sorted(ctx.modules):
        graph = ctx.call_graph(module)
        for function in graph.functions:
            for site in graph.sites(function):
                if not isinstance(site.target, ExternalSymbol):
                    continue
                for advisory, entry in affected_entries(site.target.symbol, affected, suffixes):
                    check = check_conditions(entry, site.arguments, prior_calls=site.prior_calls)
                    if check.contradicted is not None:
                        excluded.setdefault(advisory.id, []).append(ruled_out(module, site, check))
    return excluded
