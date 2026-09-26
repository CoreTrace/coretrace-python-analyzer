"""Correlation engine (architecture §27).

A package required in a vulnerable version, an API the advisory affects, a call to that
API reachable in the project, and attacker-controlled data reaching that call: the
affected APIs become sinks of the ``ADVISORY`` taint kind, so the shared taint engine,
the function summaries and the refutation engine do the work, and the flows they leave
are correlated here into one high-confidence ``exploitable-vulnerability`` finding.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace

from coretrace_python.dependency.graph import (
    DIRECT,
    Advisory,
    AdvisoryEntryPoint,
    Condition,
    DependencyGraph,
)
from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.findings.refutation import Status, Verdict, Verdicts
from coretrace_python.interprocedural import Arguments, CallSite, ExternalSymbol
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import Sink, TaintFlow, TaintKind
from coretrace_python.taint.urls import UrlProof, redirects_disabled

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


@dataclass(frozen=True)
class ConditionCheck:
    """What one call tells of an entry point's conditions: those it meets, those left to
    review (every semantic one, and every argument one the call does not decide), and
    the argument condition it contradicts with what it passes instead (None: absent),
    in which case the call does not reach the vulnerability."""

    met: tuple[Condition, ...] = ()
    pending: tuple[Condition, ...] = ()
    contradicted: Condition | None = None
    passed: str | None = None


def check_conditions(
    entry: AdvisoryEntryPoint | None,
    arguments: Arguments | None,
    url: UrlProof | None = None,
    passed_as: frozenset[tuple[int | None, str | None]] = frozenset(),
) -> ConditionCheck:
    """Decide ``entry``'s conditions against what the call's ``arguments`` denote and, for
    a ``host`` condition, what ``url`` proves of the value the attacker's input is passed
    in (``passed_as``). A host the URL's constant text fixes rules the call out when the
    call disables redirects; otherwise a redirect may still lead to a host the attacker
    controls, and the condition stays pending with that uncertainty."""

    if entry is None:
        return ConditionCheck()
    met: list[Condition] = []
    pending: list[Condition] = []
    for condition in entry.conditions:
        if condition.kind == "host":
            origin = url.origin if url is not None and _passed_in(condition, passed_as) else None
            if origin is None:
                pending.append(condition)
            elif redirects_disabled(arguments):
                return ConditionCheck(tuple(met), tuple(pending), condition, repr(origin))
            else:
                text = f"the host is fixed by {origin!r}, but a redirect may lead to a host the attacker controls"
                pending.append(replace(condition, text=text))
            continue
        given = arguments.given(condition.argument, condition.position) if condition.checkable and arguments is not None else None
        if given is None:
            pending.append(condition)
            continue
        explicit, value = given
        if explicit and value is None:
            pending.append(condition)
            continue
        affected = value in condition.values if explicit else condition.default
        if not affected:
            return ConditionCheck(tuple(met), tuple(pending), condition, value)
        met.append(condition)
    return ConditionCheck(tuple(met), tuple(pending))


def _passed_in(condition: Condition, passed_as: frozenset[tuple[int | None, str | None]]) -> bool:
    """Whether a value passed as ``passed_as`` is the argument ``condition`` names."""

    return any(
        (keyword is not None and keyword == condition.argument)
        or (keyword is None and position is not None and position == condition.position)
        for position, keyword in passed_as
    )


def ruled_out(module: str, site: CallSite, check: ConditionCheck) -> str:
    """Which call a contradicted condition rules out, and why: ``app:12
    python.yaml.load(Loader=python.yaml.SafeLoader)``."""

    assert check.contradicted is not None and isinstance(site.target, ExternalSymbol)
    argument = check.contradicted.argument or f"#{check.contradicted.position}"
    passed = f"{argument} absent" if check.passed is None else f"{argument}={check.passed}"
    return f"{module}:{site.location.start_line} {site.target.symbol}({passed})"


def evidence(advisory: Advisory, symbol: SymbolId, level: str, check: ConditionCheck) -> dict[str, str]:
    """What a finding keeps of the advisory for ``symbol``: the level of evidence
    established, how the symbol relates to the vulnerability, and its conditions — those
    the call meets and those left to review."""

    metadata = {"advisory": advisory.id, "package": advisory.package, "symbol": str(symbol), "level": level}
    entry = advisory.entry_point(symbol)
    if entry is None:
        metadata["justification"] = DIRECT
        return metadata
    metadata["entry_point"] = str(entry.symbol)
    metadata["justification"] = entry.justification
    if entry.conditions:
        metadata["conditions"] = "; ".join(c.text for c in entry.conditions)
    if check.met:
        metadata["conditions_met"] = "; ".join(c.text for c in check.met)
    if check.pending:
        metadata["conditions_pending_review"] = "; ".join(c.text for c in check.pending)
    return metadata


def correlate(
    function: str,
    flows: Iterable[TaintFlow],
    verdicts: Verdicts | None,
    affected: Affected,
    urls: Mapping[TaintFlow, UrlProof] | None = None,
) -> tuple[Finding, ...]:
    """Exploitable-vulnerability findings for the non-refuted ADVISORY flows of a function,
    one per advisory the sink is affected by; ``urls`` holds what each flow's URL proves."""

    findings: list[Finding] = []
    for flow in flows:
        if not flow.kinds & TaintKind.ADVISORY:
            continue
        verdict = verdicts.verdict(flow) if verdicts is not None else None
        if verdict is not None and verdict.status is Status.REFUTED:
            continue
        hotspot = verdict is not None and verdict.status is Status.HOTSPOT
        for advisory in affected.get(flow.sink.symbol, ()):
            entry = advisory.entry_point(flow.sink.symbol)
            if entry is not None and not any(entry.exploitable_through(p, k) for p, k in flow.passed_as):
                continue
            check = check_conditions(entry, flow.sink_arguments, (urls or {}).get(flow), flow.passed_as)
            if check.contradicted is None:
                findings.append(_exploitable(function, flow, advisory, verdict, hotspot, check))
    return tuple(findings)


def _exploitable(
    function: str, flow: TaintFlow, advisory: Advisory, verdict: Verdict | None, hotspot: bool, check: ConditionCheck
) -> Finding:
    message = (
        f"{advisory.id}: {flow.source.label} input reaches {flow.sink.symbol}, affected in "
        f"the required {advisory.package} {advisory.vulnerable}: {advisory.summary}"
    )
    metadata = {
        **evidence(advisory, flow.sink.symbol, "exploitable", check),
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
