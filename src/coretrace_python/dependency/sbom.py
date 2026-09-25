"""CycloneDX software bill of materials from the dependency graph (architecture §26)."""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence

from coretrace_python.dependency.graph import Advisory, DependencyGraph, Requirement
from coretrace_python.findings import PLUGIN, Component

SPEC_VERSION = "1.5"


def purl(requirement: Requirement) -> str:
    base = f"pkg:pypi/{requirement.name}"
    if requirement.pinned is None:
        return base
    return f"{base}@{'.'.join(str(part) for part in requirement.pinned.parts)}"


def _component(requirement: Requirement) -> dict[str, object]:
    reference = purl(requirement)
    component: dict[str, object] = {"type": "library", "bom-ref": reference, "name": requirement.name}
    if requirement.pinned is not None:
        component["version"] = ".".join(str(part) for part in requirement.pinned.parts)
    component["purl"] = reference
    properties: list[dict[str, str]] = []
    if requirement.specifier:
        properties.append({"name": "coretrace:specifier", "value": requirement.specifier})
    if requirement.optional:
        properties.append({"name": "coretrace:optional", "value": "true"})
    if properties:
        component["properties"] = properties
    return component


def _tool(component: Component) -> dict[str, object]:
    """A plugin as an application, an advisory file as data, each with its SHA-256."""

    tool: dict[str, object] = {"type": "application" if component.kind == PLUGIN else "data", "name": component.name}
    if component.version is not None:
        tool["version"] = component.version
    tool["hashes"] = [{"alg": "SHA-256", "content": component.digest.removeprefix("sha256:")}]
    return tool


def render_sbom(
    dependencies: DependencyGraph,
    advisories: Iterable[Advisory],
    tool_name: str,
    tool_version: str,
    components: Sequence[Component] = (),
) -> str:
    """A CycloneDX JSON document: one component per requirement, and the advisories
    affecting them as vulnerabilities. Deterministic for a given graph."""

    requirements = dependencies.requirements
    vulnerabilities: list[dict[str, object]] = []
    for advisory in sorted(advisories, key=lambda a: a.id):
        affected = [purl(r) for r in requirements if advisory.affects(r)]
        if affected:
            vulnerabilities.append(
                {
                    "id": advisory.id,
                    "description": advisory.summary,
                    "ratings": [{"severity": advisory.severity.value}],
                    "affects": [{"ref": reference} for reference in affected],
                }
            )
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {"type": "application", "name": tool_name, "version": tool_version},
                    *(_tool(component) for component in components),
                ]
            }
        },
        "components": [_component(requirement) for requirement in requirements],
        "vulnerabilities": vulnerabilities,
    }
    return json.dumps(document, indent=2) + "\n"
