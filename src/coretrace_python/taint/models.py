"""Security model registry (architecture §16, §17).

Taint kinds form a bitset joined with ``|``. Plugins register sources, sinks and
sanitizers keyed by canonical symbol; the engine freezes them into an immutable
``ModelTable`` and provides it to the Analysis Manager as the ``taint.models`` input,
so every detector consumes the same models and the same taint result.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Flag, auto
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.analysis import Analysis, AnalysisContext, MissingInputError
from coretrace_python.semantic.symbols import SymbolId


class TaintKind(Flag):
    NONE = 0
    SQL = auto()
    COMMAND = auto()
    HTML = auto()
    PATH = auto()
    SSRF = auto()
    CODE = auto()
    ADVISORY = auto()
    DESERIALIZATION = auto()
    REDIRECT = auto()
    ALL = SQL | COMMAND | HTML | PATH | SSRF | CODE | ADVISORY | DESERIALIZATION | REDIRECT
    # Outside ALL on purpose: only credential-named parameters carry it, so a database
    # write reached by ordinary input is not a plaintext credential.
    CREDENTIAL = auto()


class ModelError(Exception):
    """Two models of the same kind claim the same symbol."""


@dataclass(frozen=True)
class Source:
    """A symbol whose value, or call result, is attacker-controlled."""

    symbol: SymbolId
    label: str
    kinds: TaintKind = TaintKind.ALL


@dataclass(frozen=True)
class Sink:
    """A callable whose arguments must not carry the given taint kinds. ``positions``
    restricts some kinds to argument positions: a SQL statement is the first argument
    of ``execute``, its parameter tuple is not a statement."""

    symbol: SymbolId
    kinds: TaintKind
    positions: tuple[tuple[TaintKind, tuple[int, ...]], ...] = ()

    def kinds_at(self, position: int | None) -> TaintKind:
        """The kinds that must not reach the argument at ``position`` (``None`` for a
        keyword or starred argument)."""

        kinds = self.kinds
        for restricted, allowed in self.positions:
            if position is None or position not in allowed:
                kinds &= ~restricted
        return kinds


@dataclass(frozen=True)
class Sanitizer:
    """A callable whose result no longer carries the given taint kinds."""

    symbol: SymbolId
    kinds: TaintKind


@dataclass(frozen=True)
class EntryPoint:
    """Functions decorated by ``symbol``, and methods of classes deriving from it,
    receive attacker-controlled parameters."""

    symbol: SymbolId
    label: str
    kinds: TaintKind = TaintKind.ALL


@dataclass(frozen=True)
class TypedParameter:
    """A parameter annotated with ``symbol`` is attacker-controlled."""

    symbol: SymbolId
    label: str
    kinds: TaintKind = TaintKind.ALL


@dataclass(frozen=True)
class NamedParameter:
    """Parameters whose name matches ``pattern`` carry ``kinds`` (``password`` is a
    credential wherever it is a parameter)."""

    pattern: str
    label: str
    kinds: TaintKind

    @property
    def symbol(self) -> SymbolId:
        digest = hashlib.sha1(self.pattern.encode("utf-8")).hexdigest()[:12]
        return SymbolId(f"python.parameter.p{digest}")

    def matches(self, name: str) -> bool:
        return re.search(self.pattern, name) is not None


@dataclass(frozen=True)
class RouteRegistrar:
    """A call registering a handler elsewhere (``path('login/', views.log_in)``): the
    function or class referenced by ``argument`` (or ``keyword``) is an entry point."""

    symbol: SymbolId
    argument: int
    label: str
    kinds: TaintKind = TaintKind.ALL
    keyword: str | None = None


@dataclass(frozen=True)
class SuffixSink:
    """A sink matched by the tail of a call's symbol (``objects.raw`` for any model)."""

    suffix: str
    kinds: TaintKind
    positions: tuple[tuple[TaintKind, tuple[int, ...]], ...] = ()

    @property
    def symbol(self) -> SymbolId:
        return SymbolId(f"python.suffix.{self.suffix.replace('.', '_')}")


@dataclass(frozen=True)
class Validator:
    """A callable whose truth proves its ``argument`` safe (refutation evidence, §24)."""

    symbol: SymbolId
    kinds: TaintKind = TaintKind.ALL
    argument: int = 0


@dataclass(frozen=True)
class AuthorizationGuard:
    """A decorator, or a condition, that restricts who reaches the code behind it; a
    flow behind one is a hotspot rather than a vulnerability (§24)."""

    symbol: SymbolId
    label: str


Model = (
    Source
    | Sink
    | Sanitizer
    | EntryPoint
    | TypedParameter
    | Validator
    | AuthorizationGuard
    | NamedParameter
    | RouteRegistrar
    | SuffixSink
)


@dataclass(frozen=True)
class ModelTable:
    sources: tuple[Source, ...]
    sinks: tuple[Sink, ...]
    sanitizers: tuple[Sanitizer, ...]
    entry_points: tuple[EntryPoint, ...] = ()
    typed_parameters: tuple[TypedParameter, ...] = ()
    validators: tuple[Validator, ...] = ()
    authorizations: tuple[AuthorizationGuard, ...] = ()
    named_parameters: tuple[NamedParameter, ...] = ()
    route_registrars: tuple[RouteRegistrar, ...] = ()
    suffix_sinks: tuple[SuffixSink, ...] = ()
    _by_symbol: dict[type[Model], dict[SymbolId, Model]] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        index: dict[type[Model], dict[SymbolId, Model]] = {
            Source: {m.symbol: m for m in self.sources},
            Sink: {m.symbol: m for m in self.sinks},
            Sanitizer: {m.symbol: m for m in self.sanitizers},
            EntryPoint: {m.symbol: m for m in self.entry_points},
            TypedParameter: {m.symbol: m for m in self.typed_parameters},
            Validator: {m.symbol: m for m in self.validators},
            AuthorizationGuard: {m.symbol: m for m in self.authorizations},
            RouteRegistrar: {m.symbol: m for m in self.route_registrars},
        }
        object.__setattr__(self, "_by_symbol", MappingProxyType(index))

    def entry_point(self, symbol: SymbolId) -> EntryPoint | None:
        found = self._by_symbol[EntryPoint].get(symbol)
        return found if isinstance(found, EntryPoint) else None

    def typed_parameter(self, symbol: SymbolId) -> TypedParameter | None:
        found = self._by_symbol[TypedParameter].get(symbol)
        return found if isinstance(found, TypedParameter) else None

    def validator(self, symbol: SymbolId) -> Validator | None:
        found = self._by_symbol[Validator].get(symbol)
        return found if isinstance(found, Validator) else None

    def authorization(self, symbol: SymbolId) -> AuthorizationGuard | None:
        found = self._by_symbol[AuthorizationGuard].get(symbol)
        return found if isinstance(found, AuthorizationGuard) else None

    def source(self, symbol: SymbolId) -> Source | None:
        found = self._by_symbol[Source].get(symbol)
        return found if isinstance(found, Source) else None

    def source_covering(self, symbol: SymbolId) -> Source | None:
        """The source registered for ``symbol`` or for the closest symbol above it, so a
        source on ``flask.request.args`` also covers ``flask.request.args.get``."""

        parts = symbol.canonical_name.split(".")
        for length in range(len(parts), 1, -1):
            found = self.source(SymbolId(".".join(parts[:length])))
            if found is not None:
                return found
        return None

    def sink(self, symbol: SymbolId) -> Sink | None:
        found = self._by_symbol[Sink].get(symbol)
        if isinstance(found, Sink):
            return found
        for suffix in self.suffix_sinks:
            if symbol.canonical_name.endswith(f".{suffix.suffix}"):
                return Sink(symbol, suffix.kinds, suffix.positions)
        return None

    def route_registrar(self, symbol: SymbolId) -> RouteRegistrar | None:
        found = self._by_symbol[RouteRegistrar].get(symbol)
        return found if isinstance(found, RouteRegistrar) else None

    def extended(self, *sinks: Sink) -> ModelTable:
        """A table with extra sinks; a sink already present gains the new kinds."""

        merged = {sink.symbol: sink for sink in self.sinks}
        for sink in sinks:
            current = merged.get(sink.symbol)
            merged[sink.symbol] = (
                Sink(sink.symbol, current.kinds | sink.kinds, current.positions + sink.positions)
                if current is not None
                else sink
            )
        return ModelTable(
            self.sources,
            tuple(merged.values()),
            self.sanitizers,
            self.entry_points,
            self.typed_parameters,
            self.validators,
            self.authorizations,
            self.named_parameters,
            self.route_registrars,
            self.suffix_sinks,
        )

    def sanitizer(self, symbol: SymbolId) -> Sanitizer | None:
        found = self._by_symbol[Sanitizer].get(symbol)
        return found if isinstance(found, Sanitizer) else None


class SecurityModelRegistry:
    """Mutable collection point for the models plugins register."""

    def __init__(self) -> None:
        self._models: dict[tuple[type[Model], SymbolId], Model] = {}

    def register(self, *models: Model) -> None:
        for model in models:
            key = (type(model), model.symbol)
            if key in self._models:
                raise ModelError(
                    f"{type(model).__name__.lower()} model for {model.symbol} is already registered"
                )
            self._models[key] = model

    def freeze(self) -> ModelTable:
        models = list(self._models.values())
        return ModelTable(
            sources=tuple(m for m in models if isinstance(m, Source)),
            sinks=tuple(m for m in models if isinstance(m, Sink)),
            sanitizers=tuple(m for m in models if isinstance(m, Sanitizer)),
            entry_points=tuple(m for m in models if isinstance(m, EntryPoint)),
            typed_parameters=tuple(m for m in models if isinstance(m, TypedParameter)),
            validators=tuple(m for m in models if isinstance(m, Validator)),
            authorizations=tuple(m for m in models if isinstance(m, AuthorizationGuard)),
            named_parameters=tuple(m for m in models if isinstance(m, NamedParameter)),
            route_registrars=tuple(m for m in models if isinstance(m, RouteRegistrar)),
            suffix_sinks=tuple(m for m in models if isinstance(m, SuffixSink)),
        )


class SecurityModelAnalysis(Analysis[ModelTable]):
    """The frozen model table, provided by the engine rather than computed."""

    name: ClassVar[str] = "taint.models"

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> ModelTable:
        raise MissingInputError(
            f"{cls.name} must be provided to the analysis manager before it is requested"
        )
