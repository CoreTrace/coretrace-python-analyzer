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
from coretrace_python.interprocedural import Clearing
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
    NOSQL = auto()
    ALL = SQL | COMMAND | HTML | PATH | SSRF | CODE | ADVISORY | DESERIALIZATION | REDIRECT | NOSQL
    # Outside ALL on purpose: only the values a model marks carry them, so a database
    # write reached by ordinary input is not a plaintext credential, and ordinary input
    # reaching a logger is neither log forging nor a personal-data leak.
    CREDENTIAL = auto()
    LOG = auto()
    PII = auto()


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
    """A callable whose arguments must not carry the given taint kinds. ``positions`` and
    ``keywords`` restrict some kinds to the arguments they list: a SQL statement is the
    first argument of ``execute``, its parameter tuple is not a statement; the target of
    ``requests.get`` is its first argument or ``url=``, its body is no destination."""

    symbol: SymbolId
    kinds: TaintKind
    positions: tuple[tuple[TaintKind, tuple[int, ...]], ...] = ()
    keywords: tuple[tuple[TaintKind, tuple[str, ...]], ...] = ()

    def kinds_at(self, position: int | None, keyword: str | None = None) -> TaintKind:
        """The kinds that must not reach the argument at ``position`` or passed as
        ``keyword``; both are ``None`` for a starred argument or ``**kwargs``, which
        reach no restricted kind. A restricted kind reaches any argument one of its
        restrictions lists."""

        restricted = allowed = TaintKind(0)
        for kinds, positions in self.positions:
            restricted |= kinds
            if position in positions:
                allowed |= kinds
        for kinds, names in self.keywords:
            restricted |= kinds
            if keyword in names:
                allowed |= kinds
        return self.kinds & ~(restricted & ~allowed)

    def merged(self, other: Sink) -> Sink:
        """This sink with ``other``'s kinds, positions and keywords added."""

        return Sink(
            self.symbol,
            self.kinds | other.kinds,
            self.positions + other.positions,
            self.keywords + other.keywords,
        )


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
class SafeArgument:
    """A call to the sink ``symbol`` whose ``argument`` (by keyword, or at ``position``)
    denotes one of ``values`` is not a sink for ``kinds``: ``yaml.load`` with
    ``Loader=SafeLoader``. Values are written as call sites record them: a symbol by its
    canonical name, a constant as Python writes it. Only a value given explicitly makes
    the call safe; an absent argument, a variable or unpacked arguments leave the sink."""

    symbol: SymbolId
    argument: str
    values: tuple[str, ...]
    position: int | None = None
    kinds: TaintKind = TaintKind.ALL


@dataclass(frozen=True)
class Validator:
    """A callable whose truth proves its ``argument`` safe (refutation evidence, §24)."""

    symbol: SymbolId
    kinds: TaintKind = TaintKind.ALL
    argument: int = 0


@dataclass(frozen=True)
class TemplateRender:
    """A call rendering the template it names (argument ``position``, or ``keyword``)
    with autoescaping on, such as ``render_to_string``: what it returns carries no
    ``HTML`` when the project shows that template escaping everything it renders."""

    symbol: SymbolId
    position: int = 0
    keyword: str = "template_name"


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
    | SafeArgument
    | TemplateRender
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
    safe_arguments: tuple[SafeArgument, ...] = ()
    template_renders: tuple[TemplateRender, ...] = ()
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
            SafeArgument: {m.symbol: m for m in self.safe_arguments},
            TemplateRender: {m.symbol: m for m in self.template_renders},
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
            merged[sink.symbol] = sink if current is None else current.merged(sink)
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
            self.safe_arguments,
            self.template_renders,
        )

    def sanitizer(self, symbol: SymbolId) -> Sanitizer | None:
        found = self._by_symbol[Sanitizer].get(symbol)
        return found if isinstance(found, Sanitizer) else None

    def safe_argument(self, symbol: SymbolId) -> SafeArgument | None:
        found = self._by_symbol[SafeArgument].get(symbol)
        return found if isinstance(found, SafeArgument) else None

    def template_render(self, symbol: SymbolId) -> TemplateRender | None:
        found = self._by_symbol[TemplateRender].get(symbol)
        return found if isinstance(found, TemplateRender) else None

    def clearing(self, escaped: frozenset[str] = frozenset()) -> Clearing:
        """What calls clear from the data they return: every sanitizer its kinds, every
        template render ``HTML`` when it names one of the ``escaped`` templates."""

        return Clearing(
            MappingProxyType({s.symbol: s.kinds.value for s in self.sanitizers}),
            MappingProxyType({r.symbol: (r.position, r.keyword, TaintKind.HTML.value) for r in self.template_renders}),
            # As call sites record a constant argument: the way Python writes it.
            frozenset(repr(name) for name in escaped),
        )


class SecurityModelRegistry:
    """Mutable collection point for the models plugins register."""

    def __init__(self) -> None:
        self._models: dict[tuple[type[Model], SymbolId], Model] = {}
        self._origins: dict[tuple[type[Model], SymbolId], str | None] = {}

    def register(self, *models: Model, origin: str | None = None) -> None:
        """Add models; ``origin`` names the plugin so a conflict can name both sides.

        Two plugins may describe the same symbol: an identical model is ignored, sinks
        merge their kinds and positions, any other difference is a conflict."""

        for model in models:
            key = (type(model), model.symbol)
            current = self._models.get(key)
            if current is None:
                self._models[key] = model
                self._origins[key] = origin
            elif current == model:
                continue
            elif isinstance(model, Sink) and isinstance(current, Sink):
                self._models[key] = current.merged(model)
            else:
                registered = self._origins[key]
                sides = f" by {registered!r} and {origin!r}" if registered and origin else ""
                raise ModelError(
                    f"{type(model).__name__.lower()} model for {model.symbol}"
                    f" is registered twice{sides} with different values"
                )

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
            safe_arguments=tuple(m for m in models if isinstance(m, SafeArgument)),
            template_renders=tuple(m for m in models if isinstance(m, TemplateRender)),
        )


class SecurityModelAnalysis(Analysis[ModelTable]):
    """The frozen model table, provided by the engine rather than computed."""

    name: ClassVar[str] = "taint.models"

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> ModelTable:
        raise MissingInputError(
            f"{cls.name} must be provided to the analysis manager before it is requested"
        )
