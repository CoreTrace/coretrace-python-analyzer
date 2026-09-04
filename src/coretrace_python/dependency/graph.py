"""Dependency resolution (architecture §26).

Requirements declared in ``requirements.txt``, ``pyproject.toml`` (PEP 621 and Poetry)
and pinned in ``poetry.lock`` or ``uv.lock`` become a ``DependencyGraph``. Versions are
compared with a small PEP 440 subset (``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``,
``~=`` and Poetry's ``^``), enough to decide whether a requirement may allow a version an
advisory marks as vulnerable. Nothing is downloaded.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
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


def _lower_bounds(specifier: str) -> list[Version]:
    bounds: list[Version] = []
    for clause in [c.strip() for c in specifier.split(",") if c.strip()]:
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
class Advisory:
    id: str
    package: str
    vulnerable: str
    summary: str
    severity: Severity
    affected_symbols: tuple[SymbolId, ...] = ()

    def affects(self, requirement: Requirement) -> bool:
        return requirement.name == normalize(self.package) and requirement.may_match(self.vulnerable)


class DependencyGraph:
    def __init__(self, requirements: Mapping[str, Requirement] | None = None, errors: tuple[str, ...] = ()) -> None:
        self._requirements = MappingProxyType(dict(sorted((requirements or {}).items())))
        self.errors = errors

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self._requirements)

    @property
    def requirements(self) -> tuple[Requirement, ...]:
        return tuple(self._requirements.values())

    def requirement(self, name: str) -> Requirement | None:
        return self._requirements.get(normalize(name))

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
        return DependencyGraph(merged, self.errors + other.errors)


def parse_dependencies(source: SourceFile) -> DependencyGraph:
    """The requirements declared or pinned by one dependency file; other files are empty."""

    name = source.path.name if source.path is not None else str(source.source_id)
    if name.startswith("requirements") and name.endswith(".txt"):
        return _parse_requirements_txt(source)
    if name == "pyproject.toml":
        return _parse_toml(source, _pyproject_requirements)
    if name in ("poetry.lock", "uv.lock"):
        return _parse_toml(source, _lock_requirements)
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


def _parse_toml(source: SourceFile, extract: Any) -> DependencyGraph:
    try:
        data = tomllib.loads(source.text)
    except tomllib.TOMLDecodeError as error:
        return DependencyGraph(errors=(f"{source.source_id}: {error}",))
    found: dict[str, Requirement] = {}
    for requirement in extract(data, source):
        found[requirement.name] = requirement
    return DependencyGraph(found)


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


class DependencyAnalysis(Analysis[DependencyGraph]):
    """The project's dependency graph, provided by the engine; empty for a lone file."""

    name: ClassVar[str] = "dependency.graph"

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> DependencyGraph:
        return DependencyGraph()


DEPENDENCY_FILES = ("pyproject.toml", "poetry.lock", "uv.lock")
