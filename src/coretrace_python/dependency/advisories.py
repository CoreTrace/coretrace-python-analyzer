"""Local advisory files and the OSV import (architecture §26).

The analysis never touches the network. ``import_osv`` converts the records of a public
OSV dump into ``Advisory`` values, keeping the PyPI ecosystem and turning each range of
events into a version specifier; ``dump_advisories`` writes them as a small JSON file
that a project keeps at its root as ``advisories.json`` or passes with ``--advisories``.
OSV records name no affected APIs, so imported advisories feed the requirement checks
and the SBOM; a file completed by hand with ``affected_symbols``, ``entry_points`` and
their ``conditions`` also feeds the reachability and correlation checks.
"""

from __future__ import annotations

import json
import zipfile
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

from coretrace_python.dependency.graph import (
    Advisory,
    AdvisoryEntryPoint,
    AttackerArgument,
    Condition,
    normalize,
)
from coretrace_python.findings import Severity
from coretrace_python.semantic.symbols import SymbolId

ADVISORY_FILE = "advisories.json"
ADVISORY_SCHEMA = 1

_SEVERITIES = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


class AdvisoryFileError(Exception):
    """An advisory or policy file could not be read."""


# --------------------------------------------------------------------------- OSV


def read_osv(path: Path) -> Iterator[Mapping[str, Any]]:
    """The records of an OSV dump: one JSON file (a record or a list), a directory of
    JSON files, or a zip archive of them."""

    if path.is_dir():
        for file in sorted(path.glob("*.json")):
            yield from _records(json.loads(file.read_text(encoding="utf-8")))
    elif path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for name in sorted(archive.namelist()):
                if name.endswith(".json"):
                    yield from _records(json.loads(archive.read(name).decode("utf-8")))
    else:
        yield from _records(json.loads(path.read_text(encoding="utf-8")))


def _records(data: Any) -> Iterator[Mapping[str, Any]]:
    if isinstance(data, list):
        for item in data:
            if isinstance(item, Mapping):
                yield item
    elif isinstance(data, Mapping):
        yield data


def import_osv(records: Iterable[Mapping[str, Any]]) -> tuple[Advisory, ...]:
    """The PyPI advisories of OSV records, one per affected range."""

    advisories: list[Advisory] = []
    for record in records:
        identifier = record.get("id")
        if not isinstance(identifier, str):
            continue
        summary = str(record.get("summary") or "").strip()
        if not summary:
            lines = str(record.get("details") or "").strip().splitlines()
            summary = lines[0] if lines else identifier
        aliases = tuple(str(a) for a in record.get("aliases") or [])
        severity = _severity(record)
        for affected in record.get("affected") or []:
            package = (affected.get("package") or {}) if isinstance(affected, Mapping) else {}
            if str(package.get("ecosystem", "")).lower() != "pypi" or not package.get("name"):
                continue
            name = normalize(str(package["name"]))
            specifiers = _specifiers(affected.get("ranges") or [])
            if specifiers:
                advisories.append(Advisory(identifier, name, " || ".join(specifiers), summary, severity, (), aliases))
    return tuple(advisories)


def _severity(record: Mapping[str, Any]) -> Severity:
    specific = record.get("database_specific") or {}
    label = specific.get("severity") if isinstance(specific, Mapping) else None
    return _SEVERITIES.get(str(label).upper(), Severity.MEDIUM)


def _specifiers(ranges: Iterable[Mapping[str, Any]]) -> list[str]:
    found: list[str] = []
    for entry in ranges:
        if entry.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        introduced: str | None = None
        for event in entry.get("events") or []:
            if "introduced" in event:
                introduced = str(event["introduced"])
            elif "fixed" in event or "last_affected" in event:
                bound = f"<{event['fixed']}" if "fixed" in event else f"<={event['last_affected']}"
                found.append(_clause(introduced, bound))
                introduced = None
        if introduced is not None:
            found.append(_clause(introduced, None))
    return found


def _clause(introduced: str | None, bound: str | None) -> str:
    parts: list[str] = []
    if introduced is not None and introduced != "0":
        parts.append(f">={introduced}")
    if bound is not None:
        parts.append(bound)
    return ",".join(parts) if parts else ">=0"


# --------------------------------------------------------------------------- local file


def dump_advisories(advisories: Iterable[Advisory]) -> str:
    document = {
        "schema": ADVISORY_SCHEMA,
        "advisories": [
            {
                "id": a.id,
                "package": a.package,
                "vulnerable": a.vulnerable,
                "summary": a.summary,
                "severity": a.severity.value,
                "affected_symbols": [str(s) for s in a.affected_symbols],
                "aliases": list(a.aliases),
                "entry_points": [_entry_point_entry(e) for e in a.entry_points],
                "modules": list(a.modules),
            }
            for a in advisories
        ],
    }
    return json.dumps(document, indent=2) + "\n"


def _entry_point_entry(entry_point: AdvisoryEntryPoint) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "symbol": str(entry_point.symbol),
        "justification": entry_point.justification,
        "conditions": [_condition_entry(c) for c in entry_point.conditions],
    }
    if entry_point.read:
        entry["read"] = True
    if entry_point.attacker_arguments:
        entry["attacker_arguments"] = [_attacker_argument_entry(a) for a in entry_point.attacker_arguments]
    return entry


def _attacker_argument_entry(argument: AttackerArgument) -> dict[str, Any]:
    entry: dict[str, Any] = {}
    if argument.argument is not None:
        entry["argument"] = argument.argument
    if argument.position is not None:
        entry["position"] = argument.position
    if argument.variadic:
        entry["variadic"] = True
    return entry


def _condition_entry(condition: Condition) -> dict[str, Any]:
    entry: dict[str, Any] = {"kind": condition.kind, "text": condition.text}
    if condition.argument is not None:
        entry["argument"] = condition.argument
    if condition.values:
        entry["values"] = list(condition.values)
    if condition.position is not None:
        entry["position"] = condition.position
    if condition.default:
        entry["default"] = True
    return entry


def load_advisories(path: Path) -> tuple[Advisory, ...]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("schema") != ADVISORY_SCHEMA:
            raise AdvisoryFileError(f"{path}: unsupported advisory schema {document.get('schema')!r}")
        return tuple(_advisory(entry) for entry in document["advisories"])
    except AdvisoryFileError:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        raise AdvisoryFileError(f"{path}: {error}") from error


def _advisory(entry: Mapping[str, Any]) -> Advisory:
    return Advisory(
        str(entry["id"]),
        normalize(str(entry["package"])),
        str(entry["vulnerable"]),
        str(entry["summary"]),
        Severity(entry["severity"]),
        tuple(SymbolId(str(s)) for s in entry.get("affected_symbols") or []),
        tuple(str(a) for a in entry.get("aliases") or []),
        tuple(_entry_point(e) for e in entry.get("entry_points") or []),
        tuple(str(m) for m in entry.get("modules") or []),
    )


def _entry_point(entry: Mapping[str, Any]) -> AdvisoryEntryPoint:
    read = entry.get("read", False)
    if not isinstance(read, bool):
        raise TypeError(f"entry point read must be true or false, got {read!r}")
    return AdvisoryEntryPoint(
        SymbolId(str(entry["symbol"])),
        str(entry["justification"]),
        tuple(_condition(c) for c in entry.get("conditions") or []),
        read,
        tuple(_attacker_argument(a) for a in entry.get("attacker_arguments") or []),
    )


def _attacker_argument(entry: Mapping[str, Any]) -> AttackerArgument:
    argument, position, variadic = entry.get("argument"), entry.get("position"), entry.get("variadic", False)
    if argument is not None and not isinstance(argument, str):
        raise TypeError(f"attacker argument name must be a string, got {argument!r}")
    if position is not None and (not isinstance(position, int) or isinstance(position, bool) or position < 0):
        raise TypeError(f"attacker argument position must be a non-negative integer, got {position!r}")
    if not isinstance(variadic, bool):
        raise TypeError(f"attacker argument variadic must be true or false, got {variadic!r}")
    if argument is None and position is None:
        raise ValueError("an attacker argument needs a name, a position or both")
    if variadic and position is None:
        raise ValueError("a variadic attacker argument needs the position it starts at")
    return AttackerArgument(argument, position, variadic)


def _condition(entry: Mapping[str, Any]) -> Condition:
    position = entry.get("position")
    if position is not None and (not isinstance(position, int) or isinstance(position, bool) or position < 0):
        raise TypeError(f"condition position must be a non-negative integer, got {position!r}")
    default = entry.get("default", False)
    if not isinstance(default, bool):
        raise TypeError(f"condition default must be true or false, got {default!r}")
    condition = Condition(
        str(entry["kind"]),
        str(entry["text"]),
        None if entry.get("argument") is None else str(entry["argument"]),
        tuple(str(v) for v in entry.get("values") or []),
        position,
        default,
    )
    if condition.kind == "host" and (
        (condition.argument is None and condition.position is None) or condition.values or condition.default
    ):
        raise ValueError("a host condition names the URL argument, by keyword or position, and nothing else")
    return condition
