"""Dependency resolution (architecture §26).

Requirements declared in ``requirements.txt``, ``pyproject.toml`` (PEP 621 and Poetry)
and pinned in ``poetry.lock`` or ``uv.lock`` become a ``DependencyGraph``; a lock file
also tells which other packages require each package. Versions are
compared with a small PEP 440 subset (``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``,
``~=`` and Poetry's ``^``), enough to decide whether a requirement may allow a version an
advisory marks as vulnerable. Nothing is downloaded.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import PurePath, PurePosixPath
from types import MappingProxyType
from typing import Any, ClassVar

from coretrace_python.analysis import Analysis, AnalysisContext
from coretrace_python.findings import Severity
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceFile, SourceId, SourceSpan

_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_CLAUSE = re.compile(r"^(===|==|!=|<=|>=|~=|<|>|\^)\s*([0-9][0-9A-Za-z.*+!-]*)$")


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True, order=True)
class Version:
    parts: tuple[int, ...]

    @classmethod
    def parse(cls, text: str) -> Version:
        parts: list[int] = []
        for piece in text.strip().split("."):
            digits = re.match(r"\d+", piece)
            if digits is None:
                break
            parts.append(int(digits.group()))
            if digits.end() != len(piece):
                break
        return cls(tuple(parts) or (0,))

    def padded(self, length: int) -> tuple[int, ...]:
        return self.parts + (0,) * (length - len(self.parts))

    def satisfies(self, specifier: str) -> bool:
        """Whether this version is in ``specifier``: comma-separated clauses all hold, and
        ``||`` separates alternatives, as an advisory over several release series needs
        (``>=4.2,<4.2.28 || >=5.2,<5.2.11``)."""

        return any(self._satisfies_all(alternative) for alternative in _alternatives(specifier))

    def _satisfies_all(self, specifier: str) -> bool:
        for clause in [c.strip() for c in specifier.split(",") if c.strip()]:
            match = _CLAUSE.match(clause)
            if match is None:
                continue
            operator, wanted = match.group(1), Version.parse(match.group(2))
            if not self._satisfies_clause(operator, wanted, match.group(2)):
                return False
        return True

    def _satisfies_clause(self, operator: str, wanted: Version, raw: str) -> bool:
        length = max(len(self.parts), len(wanted.parts))
        mine, theirs = self.padded(length), wanted.padded(length)
        if operator in ("==", "==="):
            if raw.endswith(".*"):
                prefix = wanted.parts
                return self.parts[: len(prefix)] == prefix
            return mine == theirs
        if operator == "!=":
            return mine != theirs
        if operator == "<":
            return mine < theirs
        if operator == "<=":
            return mine <= theirs
        if operator == ">":
            return mine > theirs
        if operator == ">=":
            return mine >= theirs
        if operator == "~=":
            ceiling = list(wanted.parts[:-1]) if len(wanted.parts) > 1 else [wanted.parts[0]]
            ceiling[-1] += 1
            return mine >= theirs and self.padded(len(ceiling)) < tuple(ceiling)
        if operator == "^":
            ceiling = [0] * len(wanted.parts)
            for index, part in enumerate(wanted.parts):
                if part != 0 or index == len(wanted.parts) - 1:
                    ceiling[index] = part + 1
                    break
            return mine >= theirs and self.padded(len(ceiling)) < tuple(ceiling)
        return True


def _alternatives(specifier: str) -> list[str]:
    return [a for a in specifier.split("||") if a.strip()] or [""]


def _lower_bounds(specifier: str) -> list[Version]:
    bounds: list[Version] = []
    for alternative in _alternatives(specifier):
        for clause in [c.strip() for c in alternative.split(",") if c.strip()]:
            match = _CLAUSE.match(clause)
            if match is not None and match.group(1) in (">=", ">", "~=", "^", "==", "==="):
                bounds.append(Version.parse(match.group(2)))
    return bounds


@dataclass(frozen=True)
class Requirement:
    name: str
    specifier: str
    span: SourceSpan
    pinned: Version | None = None
    optional: bool = False

    @classmethod
    def parse(cls, text: str, source_id: SourceId, line: int, optional: bool = False) -> Requirement | None:
        cleaned = text.split("#", 1)[0].split(";", 1)[0].strip()
        match = _REQUIREMENT.match(cleaned)
        if match is None or not match.group(1):
            return None
        specifier = ",".join(part.strip() for part in match.group(3).split(",") if part.strip())
        pinned = None
        clauses = [c for c in specifier.split(",") if c]
        if len(clauses) == 1 and clauses[0].startswith("==") and not clauses[0].endswith(".*"):
            pinned = Version.parse(clauses[0].lstrip("="))
        return cls(normalize(match.group(1)), specifier, SourceSpan(source_id, line, 1), pinned, optional)

    def may_match(self, vulnerable: str) -> bool:
        """Whether some version this requirement allows is in the ``vulnerable`` range."""

        if self.pinned is not None:
            return self.pinned.satisfies(vulnerable)
        candidates = [Version((0,)), *_lower_bounds(self.specifier), *_lower_bounds(vulnerable)]
        return any(v.satisfies(self.specifier) and v.satisfies(vulnerable) for v in candidates)


@dataclass(frozen=True)
class Condition:
    """What must hold for an entry point to reach, or exploit, the affected code: the
    value of an argument, the loader or algorithm used, the format decoded, the kind of
    input, a configuration. ``kind`` says whether the engine can check it: an
    ``argument`` condition names the argument by keyword, and by ``position`` when it may
    be passed positionally, and lists the ``values`` that satisfy it — symbols
    (``python.yaml.FullLoader``) or constants as Python writes them (``True``);
    ``default`` says an absent argument means a vulnerable value. A ``semantic``
    condition cannot be checked and is reported as pending review."""

    kind: str
    text: str
    argument: str | None = None
    values: tuple[str, ...] = ()
    position: int | None = None
    default: bool = False

    @property
    def checkable(self) -> bool:
        return self.kind == "argument"


@dataclass(frozen=True)
class AdvisoryEntryPoint:
    """A public API through which a project reaches an affected symbol, justified by the
    fixing commit or by a call path, with the conditions under which it is affected."""

    symbol: SymbolId
    justification: str
    conditions: tuple[Condition, ...] = ()


DIRECT = "affected symbol, changed by the fix"


@dataclass(frozen=True)
class Advisory:
    id: str
    package: str
    vulnerable: str
    summary: str
    severity: Severity
    affected_symbols: tuple[SymbolId, ...] = ()
    aliases: tuple[str, ...] = ()
    entry_points: tuple[AdvisoryEntryPoint, ...] = ()
    # Top-level modules the package installs, to tell an imported package from a merely
    # required one; defaults to the package name (``pyyaml`` installs ``yaml``: say so).
    modules: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.modules:
            object.__setattr__(self, "modules", (normalize(self.package).replace("-", "_"),))

    def affects(self, requirement: Requirement) -> bool:
        return requirement.name == normalize(self.package) and requirement.may_match(self.vulnerable)

    @property
    def reachable_symbols(self) -> tuple[SymbolId, ...]:
        """Every symbol a call to which reaches the vulnerability: the entry points and
        the affected symbols themselves."""

        return (*(e.symbol for e in self.entry_points), *self.affected_symbols)

    def entry_point(self, symbol: SymbolId) -> AdvisoryEntryPoint | None:
        return next((e for e in self.entry_points if e.symbol == symbol), None)

    def imported_by(self, symbols: Iterable[SymbolId]) -> bool:
        """Whether any of the ``symbols`` a project imports belongs to this package."""

        prefixes = tuple(f"python.{m}" for m in self.modules)
        return any(
            s.canonical_name == p or s.canonical_name.startswith(p + ".") for s in symbols for p in prefixes
        )


class DependencyGraph:
    def __init__(
        self,
        requirements: Mapping[str, Requirement] | None = None,
        errors: tuple[str, ...] = (),
        dependents: Mapping[str, frozenset[str]] | None = None,
    ) -> None:
        self._requirements = MappingProxyType(dict(sorted((requirements or {}).items())))
        self.errors = errors
        self._dependents = MappingProxyType(dict(dependents or {}))

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self._requirements)

    @property
    def requirements(self) -> tuple[Requirement, ...]:
        return tuple(self._requirements.values())

    def requirement(self, name: str) -> Requirement | None:
        return self._requirements.get(normalize(name))

    def required_by(self, name: str) -> frozenset[str] | None:
        """The other packages a lock file shows requiring ``name`` — an empty set when
        only the project does — or None when no lock file mentions it."""

        return self._dependents.get(normalize(name))

    def merge(self, other: DependencyGraph) -> DependencyGraph:
        merged = dict(self._requirements)
        for name, requirement in other._requirements.items():
            current = merged.get(name)
            if current is None:
                merged[name] = requirement
                continue
            merged[name] = Requirement(
                name,
                current.specifier or requirement.specifier,
                current.span if current.specifier else requirement.span,
                requirement.pinned or current.pinned,
                current.optional and requirement.optional,
            )
        dependents = dict(self._dependents)
        for name, found in other._dependents.items():
            dependents[name] = dependents.get(name, frozenset()) | found
        return DependencyGraph(merged, self.errors + other.errors, dependents)


def parse_dependencies(source: SourceFile) -> DependencyGraph:
    """The requirements declared or pinned by one dependency file; other files are empty."""

    name = source.path.name if source.path is not None else PurePath(str(source.source_id)).name
    if name.startswith("requirements") and name.endswith(".txt"):
        return _parse_requirements_txt(source)
    if name == "pyproject.toml":
        return _parse_toml(source, _pyproject_requirements)
    if name in ("poetry.lock", "uv.lock"):
        return _parse_toml(source, _lock_requirements, _lock_dependents)
    return DependencyGraph()


def _parse_requirements_txt(source: SourceFile) -> DependencyGraph:
    found: dict[str, Requirement] = {}
    for number, line in enumerate(source.text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        requirement = Requirement.parse(stripped, source.source_id, number)
        if requirement is not None:
            found[requirement.name] = requirement
    return DependencyGraph(found)


def _parse_toml(source: SourceFile, extract: Any, dependents: Any = None) -> DependencyGraph:
    try:
        data = tomllib.loads(source.text)
    except tomllib.TOMLDecodeError as error:
        return DependencyGraph(errors=(f"{source.source_id}: {error}",))
    found: dict[str, Requirement] = {}
    for requirement in extract(data, source):
        found[requirement.name] = requirement
    return DependencyGraph(found, dependents=None if dependents is None else dependents(data))


def _line_of(source: SourceFile, key: str, default: int = 1) -> int:
    for number, line in enumerate(source.text.splitlines(), start=1):
        if key in line:
            return number
    return default


def _pyproject_requirements(data: Mapping[str, Any], source: SourceFile) -> list[Requirement]:
    found: list[Requirement] = []
    project = data.get("project", {})
    for text in project.get("dependencies", []) or []:
        requirement = Requirement.parse(text, source.source_id, _line_of(source, text))
        if requirement is not None:
            found.append(requirement)
    for group in (project.get("optional-dependencies", {}) or {}).values():
        for text in group or []:
            requirement = Requirement.parse(text, source.source_id, _line_of(source, text), True)
            if requirement is not None:
                found.append(requirement)
    poetry = data.get("tool", {}).get("poetry", {})
    for section, optional in (("dependencies", False), ("dev-dependencies", True)):
        for name, spec in (poetry.get(section, {}) or {}).items():
            if normalize(name) == "python":
                continue
            specifier = spec.get("version", "") if isinstance(spec, dict) else str(spec)
            if specifier == "*":
                specifier = ""
            requirement = Requirement.parse(
                f"{name}{specifier}", source.source_id, _line_of(source, name), optional
            )
            if requirement is not None:
                found.append(requirement)
    return found


def _lock_requirements(data: Mapping[str, Any], source: SourceFile) -> list[Requirement]:
    found: list[Requirement] = []
    for package in data.get("package", []) or []:
        name, version = package.get("name"), package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        line = _line_of(source, f'name = "{name}"')
        found.append(
            Requirement(normalize(name), "", SourceSpan(source.source_id, line, 1), Version.parse(version))
        )
    return found


def _lock_dependents(data: Mapping[str, Any]) -> dict[str, frozenset[str]]:
    """For every package a lock file lists or requires, the other locked packages that
    require it, optional extras and development groups included. The project's own
    packages — uv's editable or virtual sources inside the project — are not others."""

    dependents: dict[str, set[str]] = {}
    for package in data.get("package", []) or []:
        name = package.get("name")
        if not isinstance(name, str):
            continue
        dependents.setdefault(normalize(name), set())
        own = _is_project_package(package)
        for dependency in _locked_dependencies(package):
            found = dependents.setdefault(dependency, set())
            if not own:
                found.add(normalize(name))
    return {name: frozenset(found) for name, found in dependents.items()}


def _locked_dependencies(package: Mapping[str, Any]) -> Iterator[str]:
    declared = package.get("dependencies") or []
    if isinstance(declared, Mapping):  # poetry.lock: ``name = specifier``, optional ones too
        yield from (normalize(str(name)) for name in declared)
        return
    groups = (
        declared,
        *(package.get("optional-dependencies") or {}).values(),
        *(package.get("dev-dependencies") or {}).values(),
    )
    for group in groups:
        for entry in group or []:
            if isinstance(entry, Mapping) and isinstance(entry.get("name"), str):
                yield normalize(entry["name"])


def _is_project_package(package: Mapping[str, Any]) -> bool:
    source = package.get("source")
    if not isinstance(source, Mapping):
        return False
    path = source.get("editable", source.get("virtual"))
    if not isinstance(path, str):
        return False
    location = PurePosixPath(path)
    return not location.is_absolute() and ".." not in location.parts


class DependencyAnalysis(Analysis[DependencyGraph]):
    """The project's dependency graph, provided by the engine; empty for a lone file."""

    name: ClassVar[str] = "dependency.graph"

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> DependencyGraph:
        return DependencyGraph()


DEPENDENCY_FILES = ("pyproject.toml", "poetry.lock", "uv.lock")
