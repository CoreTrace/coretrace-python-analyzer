"""Correlation engine (architecture §27).

A package required in a vulnerable version, an API the advisory affects, a call to that
API reachable in the project, and attacker-controlled data reaching that call: the
affected APIs become sinks of the ``ADVISORY`` taint kind, so the shared taint engine,
the function summaries and the refutation engine do the work, and the flows they leave
are correlated here into one high-confidence ``exploitable-vulnerability`` finding.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from coretrace_python.dependency.graph import Advisory, DependencyGraph
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.findings.refutation import Status, Verdicts
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import Sink, TaintFlow, TaintKind


def affected_symbols(
    dependencies: DependencyGraph, advisories: Iterable[Advisory]
) -> Mapping[SymbolId, Advisory]:
    """The APIs affected by advisories whose package is required in a vulnerable version."""

    affected: dict[SymbolId, Advisory] = {}
    for requirement in dependencies.requirements:
        for advisory in advisories:
            if advisory.affects(requirement):
                for symbol in advisory.affected_symbols:
                    affected.setdefault(symbol, advisory)
    return affected


def advisory_sinks(affected: Mapping[SymbolId, Advisory]) -> tuple[Sink, ...]:
    return tuple(Sink(symbol, TaintKind.ADVISORY) for symbol in affected)


def correlate(
    function: str,
    flows: Iterable[TaintFlow],
    verdicts: Verdicts | None,
    affected: Mapping[SymbolId, Advisory],
) -> tuple[Finding, ...]:
    """Exploitable-vulnerability findings for the non-refuted ADVISORY flows of a function."""

    findings: list[Finding] = []
    for flow in flows:
        if not flow.kinds & TaintKind.ADVISORY:
            continue
        advisory = affected.get(flow.sink.symbol)
        if advisory is None:
            continue
        verdict = verdicts.verdict(flow) if verdicts is not None else None
        if verdict is not None and verdict.status is Status.REFUTED:
            continue
        hotspot = verdict is not None and verdict.status is Status.HOTSPOT
        message = (
            f"{advisory.id}: {flow.source.label} input reaches {flow.sink.symbol}, affected in "
            f"the required {advisory.package} {advisory.vulnerable}: {advisory.summary}"
        )
        metadata = {
            "advisory": advisory.id,
            "package": advisory.package,
            "symbol": str(flow.sink.symbol),
            "source": str(flow.source.symbol),
            "source_label": flow.source.label,
            "verdict": "hotspot" if hotspot else "vulnerability",
        }
        if verdict is not None:
            metadata["evidence"] = verdict.evidence
        if flow.through is not None and flow.sink_location is not None:
            message += f" through {flow.through}"
            metadata["through"] = flow.through
            metadata["sink_line"] = str(flow.sink_location.start_line)
        findings.append(
            Finding(
                rule_id="exploitable-vulnerability",
                message=message,
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM if hotspot else Confidence.HIGH,
                span=flow.location,
                function=function,
                metadata=metadata,
            )
        )
    return tuple(findings)
