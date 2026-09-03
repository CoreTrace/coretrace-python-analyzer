"""Security model registry (architecture §16, §17).

Taint kinds form a bitset joined with ``|``. Plugins register sources, sinks and
sanitizers keyed by canonical symbol; the engine freezes them into an immutable
``ModelTable`` and provides it to the Analysis Manager as the ``taint.models`` input,
so every detector consumes the same models and the same taint result.
"""

from __future__ import annotations

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
    ALL = SQL | COMMAND | HTML | PATH | SSRF | CODE


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
    """A callable whose arguments must not carry the given taint kinds."""

    symbol: SymbolId
    kinds: TaintKind


@dataclass(frozen=True)
class Sanitizer:
    """A callable whose result no longer carries the given taint kinds."""

    symbol: SymbolId
    kinds: TaintKind


@dataclass(frozen=True)
class EntryPoint:
    """Functions decorated by ``symbol`` receive attacker-controlled parameters."""

    symbol: SymbolId
    label: str
    kinds: TaintKind = TaintKind.ALL


Model = Source | Sink | Sanitizer | EntryPoint


@dataclass(frozen=True)
class ModelTable:
    sources: tuple[Source, ...]
    sinks: tuple[Sink, ...]
    sanitizers: tuple[Sanitizer, ...]
    entry_points: tuple[EntryPoint, ...] = ()
    _by_symbol: dict[type[Model], dict[SymbolId, Model]] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        index: dict[type[Model], dict[SymbolId, Model]] = {
            Source: {m.symbol: m for m in self.sources},
            Sink: {m.symbol: m for m in self.sinks},
            Sanitizer: {m.symbol: m for m in self.sanitizers},
            EntryPoint: {m.symbol: m for m in self.entry_points},
        }
        object.__setattr__(self, "_by_symbol", MappingProxyType(index))

    def entry_point(self, symbol: SymbolId) -> EntryPoint | None:
        found = self._by_symbol[EntryPoint].get(symbol)
        return found if isinstance(found, EntryPoint) else None

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
        return found if isinstance(found, Sink) else None

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
        )


class SecurityModelAnalysis(Analysis[ModelTable]):
    """The frozen model table, provided by the engine rather than computed."""

    name: ClassVar[str] = "taint.models"

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> ModelTable:
        raise MissingInputError(
            f"{cls.name} must be provided to the analysis manager before it is requested"
        )
