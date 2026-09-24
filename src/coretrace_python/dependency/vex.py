"""OpenVEX statements from the evidence of a check (architecture §26).

One statement per advisory affecting a requirement, with the required package as the
subcomponent of the project:

- ``affected`` when the project's code reaches the vulnerable code: a reachable or
  exploitable finding, whatever the policy or a suppression did with it;
- ``not_affected``, as ``vulnerable_code_not_in_execute_path``, only when the advisory is
  curated (it names entry points), no code of the project reaches them, every file and
  function was analysed, and a lock file shows that no other package requires the
  vulnerable one, since the code of installed packages is not analysed;
- ``under_investigation`` otherwise, with the reason in its notes.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from coretrace_python.dependency.graph import Advisory, DependencyGraph, Requirement
from coretrace_python.dependency.sbom import purl
from coretrace_python.findings import Finding
from coretrace_python.findings.coverage import Coverage

CONTEXT = "https://openvex.dev/ns/v0.2.0"
# OpenVEX's shared namespace for documents without an IRI of their own, and the author
# OpenVEX tools such as govulncheck write when none is known.
NAMESPACE = "https://openvex.dev/docs/public/vex-"
AUTHOR = "Unknown Author"
# Evidence levels that put the vulnerable code in the project's execution path, lowest first.
REACHED = ("reachable", "exploitable")


def render_vex(
    dependencies: DependencyGraph,
    advisories: Iterable[Advisory],
    evidence: Iterable[Finding],
    coverage: Coverage,
    root: Path,
    tool_name: str,
    tool_version: str,
    timestamp: datetime,
) -> str:
    """The OpenVEX document of the project at ``root``. ``evidence`` is every finding of
    the check, those suppressed or accepted by the policy included. The document's
    identifier derives from its statements, not from ``timestamp``."""

    root = root.resolve()
    findings = tuple(evidence)
    # The product must be an IRI; the check knows the project by its directory only.
    product = f"pkg:generic/{quote(root.name, safe='')}"
    statements: list[dict[str, object]] = []
    for advisory in sorted(advisories, key=lambda a: (a.id, a.package)):
        about = [
            f
            for f in findings
            if f.metadata.get("advisory") == advisory.id and f.metadata.get("package") == advisory.package
        ]
        for requirement in dependencies.requirements:
            if advisory.affects(requirement):
                statements.append(
                    {
                        "vulnerability": _vulnerability(advisory),
                        "products": [{"@id": product, "subcomponents": [{"@id": purl(requirement)}]}],
                        **_status(advisory, requirement, about, dependencies, coverage, root),
                    }
                )
    tooling = f"{tool_name} {tool_version}"
    content = {
        "@context": CONTEXT,
        "author": AUTHOR,
        "version": 1,
        "tooling": tooling,
        "statements": statements,
    }
    digest = hashlib.sha256(json.dumps(content, sort_keys=True).encode("utf-8")).hexdigest()
    document = {
        "@context": CONTEXT,
        "@id": NAMESPACE + digest,
        "author": AUTHOR,
        "timestamp": timestamp.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "version": 1,
        "tooling": tooling,
        "statements": statements,
    }
    return json.dumps(document, indent=2) + "\n"


def _vulnerability(advisory: Advisory) -> dict[str, object]:
    vulnerability: dict[str, object] = {"name": advisory.id, "description": advisory.summary}
    if advisory.aliases:
        vulnerability["aliases"] = list(advisory.aliases)
    return vulnerability


def _status(
    advisory: Advisory,
    requirement: Requirement,
    findings: Sequence[Finding],
    dependencies: DependencyGraph,
    coverage: Coverage,
    root: Path,
) -> dict[str, str]:
    package = requirement.name
    reached = _reached(findings, root)
    if reached:
        return {
            "status": "affected",
            "action_statement": (
                f"Update {package} to a version outside the vulnerable range {advisory.vulnerable}."
            ),
            "status_notes": f"Reached by the project's code at {reached}.",
        }
    if not advisory.entry_points:
        return _investigating(
            "The advisory names no entry point, so whether the project reaches the vulnerable "
            "code is not known."
        )
    symbols = ", ".join(sorted(str(e.symbol) for e in advisory.entry_points))
    entries = f"the entry points of {advisory.id} ({symbols})"
    ruled_out = "; ".join(str(f.metadata["ruled_out"]) for f in findings if "ruled_out" in f.metadata)
    ruled = f" Calls ruled out by their arguments: {ruled_out}." if ruled_out else ""
    partial = sorted(
        _relative(d.path, root)
        for d in coverage.details
        if d.status != "analysed" or d.analysed < d.functions
    )
    if partial:
        return _investigating(
            f"No analysed code reaches {entries}, but {', '.join(partial)} could not be fully "
            f"analysed.{ruled}"
        )
    required_by = dependencies.required_by(package)
    if required_by is None:
        return _investigating(
            f"No code of the project reaches {entries}, but no lock file shows which installed "
            f"packages require {package}, and their code is not analysed.{ruled}"
        )
    if required_by:
        return _investigating(
            f"No code of the project reaches {entries}, but {package} is required by "
            f"{', '.join(sorted(required_by))}, whose code is not analysed.{ruled}"
        )
    return {
        "status": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
        "impact_statement": (
            f"No code of the project reaches {entries}, and no other locked package requires "
            f"{package}.{ruled}"
        ),
    }


def _reached(findings: Sequence[Finding], root: Path) -> str:
    """Where the project's code reaches the vulnerable code, each place at its highest
    level of evidence; empty when nothing reaches it."""

    levels: dict[tuple[str, int, str], str] = {}
    for finding in findings:
        level = finding.metadata.get("level")
        if level in REACHED:
            path = _relative(str(finding.span.source_id), root)
            place = (path, finding.span.start_line, str(finding.metadata.get("symbol")))
            levels[place] = max(level, levels.get(place, level), key=REACHED.index)
    return "; ".join(
        f"{path}:{line} {symbol} ({level})" for (path, line, symbol), level in sorted(levels.items())
    )


def _investigating(notes: str) -> dict[str, str]:
    return {"status": "under_investigation", "status_notes": notes}


def _relative(path: str, root: Path) -> str:
    try:
        return PurePosixPath(Path(path).relative_to(root)).as_posix()
    except ValueError:
        return path
