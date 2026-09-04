"""Immutable nodes for the Python high-level intermediate representation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias

from coretrace_python.source import SourceSpan

HIR_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class Name:
    identifier: str
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Constant:
    value: object
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class BinaryOp:
    operator: str
    left: Expression
    right: Expression
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class UnaryOp:
    operator: str
    operand: Expression
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class BoolOp:
    """``and`` / ``or`` over two or more values; chained comparisons lower to ``and``."""

    operator: str
    values: tuple[Expression, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Compare:
    operator: str
    left: Expression
    right: Expression
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Attribute:
    value: Expression
    name: str
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Subscript:
    value: Expression
    key: Expression
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Keyword:
    """A keyword argument; ``name`` is ``None`` for ``**mapping`` unpacking."""

    name: str | None
    value: Expression
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Call:
    callee: Expression
    arguments: tuple[Expression, ...]
    keywords: tuple[Keyword, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Tuple:
    elements: tuple[Expression, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class List:
    elements: tuple[Expression, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Dict:
    """Items are ``(key, value)``; a ``None`` key is a ``**mapping`` unpacking."""

    items: tuple[tuple[Expression | None, Expression], ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class FormattedString:
    """An f-string: constant text and formatted expressions, in order. Conversions and
    format specifications are dropped; expressions nested in a specification are parts."""

    parts: tuple[Expression, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Slice:
    lower: Expression | None
    upper: Expression | None
    step: Expression | None
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Starred:
    """``*iterable`` in a call argument list or a list or tuple display."""

    value: Expression
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Set:
    elements: tuple[Expression, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Conditional:
    """``body if test else orelse``; the CFG builder lays it out as a branch."""

    test: Expression
    body: Expression
    orelse: Expression
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Lambda:
    """An anonymous function; its body is a scope of its own and is not lowered."""

    parameters: tuple[Parameter, ...]
    body: Expression
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Await:
    value: Expression
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Yield:
    value: Expression | None
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class ComprehensionGenerator:
    """One ``for target in iterable if condition...`` clause of a comprehension."""

    target: Target
    iterable: Expression
    conditions: tuple[Expression, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Comprehension:
    """A list, set, dict or generator comprehension; ``kind`` names which one. A dict
    comprehension's ``element`` is the value and ``key`` its key."""

    kind: str
    element: Expression
    generators: tuple[ComprehensionGenerator, ...]
    span: SourceSpan
    key: Expression | None = None


Expression: TypeAlias = (
    Name
    | Constant
    | BinaryOp
    | UnaryOp
    | BoolOp
    | Compare
    | Attribute
    | Subscript
    | Call
    | Tuple
    | List
    | Dict
    | FormattedString
    | Slice
    | Starred
    | Set
    | Conditional
    | Lambda
    | Await
    | Yield
    | Comprehension
)

Target: TypeAlias = Name | Attribute | Subscript | Tuple


@dataclass(frozen=True, slots=True)
class Parameter:
    """``kind`` is ``positional``, ``keyword``, ``var_positional`` or ``var_keyword``.
    ``annotation`` is kept when it is an expression the HIR can represent."""

    name: str
    span: SourceSpan
    default: Expression | None = None
    kind: str = "positional"
    annotation: Expression | None = None


@dataclass(frozen=True, slots=True)
class Assign:
    target: Target
    value: Expression
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class AugAssign:
    target: Name | Attribute | Subscript
    operator: str
    value: Expression
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Return:
    value: Expression | None
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class ExpressionStatement:
    expression: Expression
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Pass:
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Delete:
    targets: tuple[Target, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class ValuePattern:
    """``case <expression>``: equality with a value."""

    value: Expression
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class SingletonPattern:
    """``case None`` / ``True`` / ``False``: identity with a singleton."""

    value: object
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class WildcardPattern:
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class CapturePattern:
    """``case name`` or ``case <pattern> as name``: binds the subject."""

    name: str
    pattern: Pattern | None
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class OrPattern:
    alternatives: tuple[Pattern, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class StarPattern:
    """``*rest`` inside a sequence pattern; ``name`` is ``None`` for ``*_``."""

    name: str | None
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class SequencePattern:
    patterns: tuple[Pattern, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class MappingPattern:
    """``{key: pattern, ..., **rest}``; keys are expressions, ``rest`` a name or ``None``."""

    keys: tuple[Expression, ...]
    patterns: tuple[Pattern, ...]
    rest: str | None
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class ClassPattern:
    """``Cls(p, ..., name=pattern, ...)``: positional sub-patterns need the class's
    ``__match_args__``; keyword ones match attributes."""

    cls: Expression
    patterns: tuple[Pattern, ...]
    keyword_names: tuple[str, ...]
    keyword_patterns: tuple[Pattern, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class UnsupportedPattern:
    """A pattern the HIR does not represent; the CFG builder reports it."""

    kind: str
    span: SourceSpan


Pattern: TypeAlias = (
    ValuePattern
    | SingletonPattern
    | WildcardPattern
    | CapturePattern
    | OrPattern
    | StarPattern
    | SequencePattern
    | MappingPattern
    | ClassPattern
    | UnsupportedPattern
)


@dataclass(frozen=True, slots=True)
class MatchCase:
    pattern: Pattern
    guard: Expression | None
    body: tuple[Statement, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Match:
    """``match subject:``; the CFG builder lays it out as an ``if`` chain."""

    subject: Expression
    cases: tuple[MatchCase, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Assert:
    test: Expression
    message: Expression | None
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class If:
    condition: Expression
    body: tuple[Statement, ...]
    orelse: tuple[Statement, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class While:
    condition: Expression
    body: tuple[Statement, ...]
    span: SourceSpan
    orelse: tuple[Statement, ...] = ()


@dataclass(frozen=True, slots=True)
class For:
    target: Name
    iterable: Expression
    body: tuple[Statement, ...]
    is_async: bool
    span: SourceSpan
    orelse: tuple[Statement, ...] = ()


@dataclass(frozen=True, slots=True)
class Break:
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Continue:
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Raise:
    exception: Expression | None
    span: SourceSpan
    cause: Expression | None = None


@dataclass(frozen=True, slots=True)
class WithItem:
    context: Expression
    target: Name | None
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class With:
    items: tuple[WithItem, ...]
    body: tuple[Statement, ...]
    is_async: bool
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class EnterWith:
    """Synthetic statement the CFG builder emits when a ``with`` body starts."""

    item: WithItem
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class ExitWith:
    """Synthetic statement the CFG builder emits when a ``with`` body falls through."""

    item: WithItem
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class ExceptHandler:
    """``except type as name:``; ``type`` is ``None`` for a bare ``except``."""

    type: Expression | None
    name: str | None
    body: tuple[Statement, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Try:
    body: tuple[Statement, ...]
    handlers: tuple[ExceptHandler, ...]
    orelse: tuple[Statement, ...]
    finalbody: tuple[Statement, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class EnterHandler:
    """Synthetic statement the CFG builder emits at the start of a handler block."""

    handler: ExceptHandler
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class ImportAlias:
    name: str
    as_name: str | None
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Import:
    names: tuple[ImportAlias, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class ImportFrom:
    module: str | None
    names: tuple[ImportAlias, ...]
    level: int
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Global:
    names: tuple[str, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Nonlocal:
    names: tuple[str, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Function:
    name: str
    parameters: tuple[Parameter, ...]
    body: tuple[Statement, ...]
    is_async: bool
    span: SourceSpan
    decorators: tuple[Expression, ...] = ()


@dataclass(frozen=True, slots=True)
class Class:
    name: str
    bases: tuple[Expression, ...]
    body: tuple[Statement, ...]
    span: SourceSpan
    decorators: tuple[Expression, ...] = ()


Statement: TypeAlias = (
    Assign
    | AugAssign
    | Return
    | ExpressionStatement
    | Pass
    | Delete
    | Match
    | Assert
    | If
    | While
    | For
    | Break
    | Continue
    | Raise
    | With
    | EnterWith
    | ExitWith
    | Try
    | EnterHandler
    | Import
    | ImportFrom
    | Global
    | Nonlocal
    | Function
    | Class
)


@dataclass(frozen=True, slots=True)
class Module:
    name: str
    body: tuple[Statement, ...]
    span: SourceSpan
    is_package: bool = False
