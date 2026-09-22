"""Correlation engine (architecture §27).

A package required in a vulnerable version, an API the advisory affects, a call to that
API reachable in the project, and attacker-controlled data reaching that call: the
affected APIs become sinks of the ``ADVISORY`` taint kind, so the shared taint engine,
the function summaries and the refutation engine do the work, and the flows they leave
are correlated here into one high-confidence ``exploitable-vulnerability`` finding.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from coretrace_python.dependency.graph import DIRECT, Advisory, DependencyGraph
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.findings.refutation import Status, Verdict, Verdicts
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import Sink, TaintFlow, TaintKind

Affected = Mapping[SymbolId, tuple[Advisory, ...]]


def affected_symbols(dependencies: DependencyGraph, advisories: Iterable[Advisory]) -> Affected:
    """The APIs affected by advisories whose package is required in a vulnerable version,
    each with every such advisory: a call to ``yaml.load`` reaches every CVE of the
    pinned release, not the first one listed."""

    affected: dict[SymbolId, list[Advisory]] = {}
    for requirement in dependencies.requirements:
        for advisory in advisories:
            if advisory.affects(requirement):
                for symbol in advisory.reachable_symbols:
                    found = affected.setdefault(symbol, [])
                    if advisory not in found:
                        found.append(advisory)
    return {symbol: tuple(found) for symbol, found in affected.items()}


def advisory_sinks(affected: Affected) -> tuple[Sink, ...]:
    return tuple(Sink(symbol, TaintKind.ADVISORY) for symbol in affected)


def evidence(advisory: Advisory, symbol: SymbolId, level: str) -> dict[str, str]:
    """What a finding keeps of the advisory for ``symbol``: the level of evidence
    established, how the symbol relates to the vulnerability and under which
    conditions, the ones the engine could not check listed as pending review."""

    metadata = {"advisory": advisory.id, "package": advisory.package, "symbol": str(symbol), "level": level}
    entry = advisory.entry_point(symbol)
    if entry is None:
        metadata["justification"] = DIRECT
        return metadata
    metadata["entry_point"] = str(entry.symbol)
    metadata["justification"] = entry.justification
    if entry.conditions:
        metadata["conditions"] = "; ".join(c.text for c in entry.conditions)
        # ponytail: no condition is checked yet, so every one awaits review; argument
        # conditions get checked at the call site once call sites carry argument symbols.
        metadata["conditions_pending_review"] = "; ".join(c.text for c in entry.conditions)
    return metadata


def correlate(
    function: str,
    flows: Iterable[TaintFlow],
    verdicts: Verdicts | None,
    affected: Affected,
) -> tuple[Finding, ...]:
    """Exploitable-vulnerability findings for the non-refuted ADVISORY flows of a function,
    one per advisory the sink is affected by."""

    findings: list[Finding] = []
    for flow in flows:
        if not flow.kinds & TaintKind.ADVISORY:
            continue
        verdict = verdicts.verdict(flow) if verdicts is not None else None
        if verdict is not None and verdict.status is Status.REFUTED:
            continue
        hotspot = verdict is not None and verdict.status is Status.HOTSPOT
        findings.extend(
            _exploitable(function, flow, advisory, verdict, hotspot) for advisory in affected.get(flow.sink.symbol, ())
        )
    return tuple(findings)


def _exploitable(
    function: str, flow: TaintFlow, advisory: Advisory, verdict: Verdict | None, hotspot: bool
) -> Finding:
    message = (
        f"{advisory.id}: {flow.source.label} input reaches {flow.sink.symbol}, affected in "
        f"the required {advisory.package} {advisory.vulnerable}: {advisory.summary}"
    )
    metadata = {
        **evidence(advisory, flow.sink.symbol, "exploitable"),
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
    return Finding(
        rule_id="exploitable-vulnerability",
        message=message,
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM if hotspot else Confidence.HIGH,
        span=flow.location,
        function=function,
        metadata=metadata,
    )
