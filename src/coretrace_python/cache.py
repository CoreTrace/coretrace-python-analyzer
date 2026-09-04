"""Persistent per-module cache (architecture §11, §38 Phase 10).

A module's results are stored under a key derived from everything they depend on: its
source text and identity, the engine, schema and plugin API versions, the plugins and
their code, the security models, the advisories, the dependency graph, and the keys of
the project modules it imports transitively. A module whose key is unchanged on a later
run is served from the cache: its summaries seed the project index, its call sites serve
the project plugins and its findings are reported as they were. Entries are JSON, so a
tampered or foreign file can never execute anything; an unreadable entry is a miss.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from coretrace_python.findings import Confidence, Finding, Severity
from coretrace_python.interprocedural import (
    CallSite,
    ExternalCall,
    ExternalSymbol,
    FunctionSummary,
    KnownFunction,
    ModuleGraph,
    SummaryIndex,
    Target,
    UnknownTarget,
)
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceId, SourceSpan

CACHE_FORMAT = 1


@dataclass(frozen=True)
class CachedModule:
    """Everything a later run needs from one module without lowering it again."""

    functions: tuple[str, ...]
    summaries: Mapping[str, FunctionSummary]
    sites: tuple[CallSite, ...]
    findings: tuple[Finding, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "summaries", MappingProxyType(dict(self.summaries)))


# --------------------------------------------------------------------------- keys


def fingerprint(*parts: str) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def directory_fingerprint(directory: Path, suffixes: Iterable[str] = (".py", ".toml")) -> str:
    """A digest of the source files under ``directory``, so edited plugin code misses."""

    wanted = tuple(suffixes)
    parts: list[str] = []
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.suffix in wanted:
            parts.append(str(path.relative_to(directory)))
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
    return fingerprint(*parts)


def module_keys(graph: ModuleGraph, own: Mapping[str, str]) -> dict[str, str]:
    """The key of each module: its own key plus those of every module it imports,
    transitively, so a change anywhere below a module misses for that module too."""

    keys: dict[str, str] = {}
    for name in graph.modules:
        closure: set[str] = set()
        pending = [name]
        while pending:
            current = pending.pop()
            for imported in graph.imports(current):
                if imported in own and imported not in closure and imported != name:
                    closure.add(imported)
                    pending.append(imported)
        keys[name] = fingerprint(own[name], *(own[m] for m in sorted(closure)))
    return keys


# --------------------------------------------------------------------------- store


class ProjectCache:
    """A directory of JSON entries, one per module key."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def load(self, key: str) -> CachedModule | None:
        path = self.directory / f"{key}.json"
        try:
            with path.open(encoding="utf-8") as handle:
                return decode(json.load(handle))
        except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError):
            return None

    def store(self, key: str, module: CachedModule) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"{key}.json"
        temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        temporary.write_text(json.dumps(encode(module)), encoding="utf-8")
        temporary.replace(path)


# --------------------------------------------------------------------------- codec


def encode(module: CachedModule) -> dict[str, Any]:
    return {
        "format": CACHE_FORMAT,
        "functions": list(module.functions),
        "summaries": {name: _encode_summary(s) for name, s in module.summaries.items()},
        "sites": [_encode_site(site) for site in module.sites],
        "findings": [_encode_finding(finding) for finding in module.findings],
    }


def decode(data: Mapping[str, Any]) -> CachedModule:
    if data["format"] != CACHE_FORMAT:
        raise ValueError(f"unsupported cache format {data['format']!r}")
    return CachedModule(
        tuple(_string(name) for name in data["functions"]),
        {_string(name): _decode_summary(s) for name, s in data["summaries"].items()},
        tuple(_decode_site(site) for site in data["sites"]),
        tuple(_decode_finding(finding) for finding in data["findings"]),
    )


def encode_index(index: SummaryIndex) -> dict[str, Any]:
    """A summary index as plain data, to hand a worker process what it imports."""

    return {str(symbol): _encode_summary(index.summaries[symbol]) for symbol in index.symbols}


def decode_index(data: Mapping[str, Any]) -> SummaryIndex:
    return SummaryIndex({SymbolId(_string(k)): _decode_summary(v) for k, v in data.items()})


def _string(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError(f"expected a string, got {value!r}")
    return value


def _integer(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"expected an integer, got {value!r}")
    return value


def _indices(values: Any) -> frozenset[int]:
    return frozenset(_integer(v) for v in values)


def _encode_span(span: SourceSpan) -> list[Any]:
    return [str(span.source_id), span.start_line, span.start_column, span.end_line, span.end_column]


def _decode_span(data: Any) -> SourceSpan:
    file, line, column, end_line, end_column = data
    return SourceSpan(
        SourceId(_string(file)),
        _integer(line),
        _integer(column),
        None if end_line is None else _integer(end_line),
        None if end_column is None else _integer(end_column),
    )


def _encode_finding(finding: Finding) -> dict[str, Any]:
    return {
        "rule": finding.rule_id,
        "message": finding.message,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "span": _encode_span(finding.span),
        "function": finding.function,
        "metadata": dict(finding.metadata),
    }


def _decode_finding(data: Mapping[str, Any]) -> Finding:
    function = data["function"]
    return Finding(
        _string(data["rule"]),
        _string(data["message"]),
        Severity(data["severity"]),
        Confidence(data["confidence"]),
        _decode_span(data["span"]),
        None if function is None else _string(function),
        {_string(k): _string(v) for k, v in data["metadata"].items()},
    )


def _encode_call(call: ExternalCall) -> dict[str, Any]:
    return {
        "symbol": str(call.symbol),
        "arguments": [sorted(deps) for deps in call.argument_dependencies],
        "keywords": sorted(call.keyword_dependencies),
        "location": _encode_span(call.location),
        "call_site": None if call.call_site is None else _encode_span(call.call_site),
    }


def _decode_call(data: Mapping[str, Any]) -> ExternalCall:
    site = data["call_site"]
    return ExternalCall(
        SymbolId(_string(data["symbol"])),
        tuple(_indices(deps) for deps in data["arguments"]),
        _indices(data["keywords"]),
        _decode_span(data["location"]),
        None if site is None else _decode_span(site),
    )


def _encode_summary(summary: FunctionSummary) -> dict[str, Any]:
    return {
        "name": summary.name,
        "parameters": summary.parameters,
        "returns": sorted(summary.return_dependencies),
        "external_calls": [_encode_call(call) for call in summary.external_calls],
        "unsupported": summary.unsupported,
        "return_externals": sorted(str(s) for s in summary.return_externals),
    }


def _decode_summary(data: Mapping[str, Any]) -> FunctionSummary:
    return FunctionSummary(
        _string(data["name"]),
        _integer(data["parameters"]),
        _indices(data["returns"]),
        tuple(_decode_call(call) for call in data["external_calls"]),
        bool(data["unsupported"]),
        frozenset(SymbolId(_string(s)) for s in data["return_externals"]),
    )


def _encode_target(target: Target) -> dict[str, Any]:
    if isinstance(target, KnownFunction):
        return {"kind": "known", "name": target.name}
    if isinstance(target, ExternalSymbol):
        return {"kind": "external", "symbol": str(target.symbol)}
    return {"kind": "unknown"}


def _decode_target(data: Mapping[str, Any]) -> Target:
    kind = data["kind"]
    if kind == "known":
        return KnownFunction(_string(data["name"]))
    if kind == "external":
        return ExternalSymbol(SymbolId(_string(data["symbol"])))
    if kind == "unknown":
        return UnknownTarget()
    raise ValueError(f"unknown call target kind {kind!r}")


def _encode_site(site: CallSite) -> dict[str, Any]:
    return {
        "caller": site.caller,
        "location": _encode_span(site.location),
        "target": _encode_target(site.target),
        "arguments": site.arguments,
        "keywords": site.keywords,
    }


def _decode_site(data: Mapping[str, Any]) -> CallSite:
    return CallSite(
        _string(data["caller"]),
        _decode_span(data["location"]),
        _decode_target(data["target"]),
        _integer(data["arguments"]),
        _integer(data["keywords"]),
    )
