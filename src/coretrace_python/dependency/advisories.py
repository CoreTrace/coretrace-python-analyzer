"""Local advisory files and the OSV import (architecture §26).

The analysis never touches the network. ``import_osv`` converts the records of a public
OSV dump into ``Advisory`` values, keeping the PyPI ecosystem and turning each range of
events into a version specifier; ``dump_advisories`` writes them as a small JSON file
that a project keeps at its root as ``advisories.json`` or passes with ``--advisories``.
OSV records name no affected APIs, so imported advisories feed the requirement checks
and the SBOM; a file completed by hand with ``affected_symbols`` also feeds the
reachability and correlation checks.
"""

from __future__ import annotations

import json
import zipfile
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

from coretrace_python.dependency.graph import Advisory, normalize
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
            for specifier in _specifiers(affected.get("ranges") or []):
                advisories.append(Advisory(identifier, name, specifier, summary, severity, (), aliases))
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
            }
            for a in advisories
        ],
    }
    return json.dumps(document, indent=2) + "\n"


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
    )
