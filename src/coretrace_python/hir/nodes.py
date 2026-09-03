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
    items: tuple[tuple[Expression, Expression], ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class ComprehensionGenerator:
    """One ``for target in iterable if condition...`` clause of a comprehension."""

    target: Name
    iterable: Expression
    conditions: tuple[Expression, ...]
    span: SourceSpan


@dataclass(frozen=True, slots=True)
class Comprehension:
    """A list, set or generator comprehension; ``kind`` names which one."""

    kind: str
    element: Expression
    generators: tuple[ComprehensionGenerator, ...]
    span: SourceSpan


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
    | Comprehension
)

Target: TypeAlias = Name | Attribute | Subscript | Tuple


@dataclass(frozen=True, slots=True)
class Parameter:
    """``kind`` is ``positional``, ``keyword``, ``var_positional`` or ``var_keyword``."""

    name: str
    span: SourceSpan
    default: Expression | None = None
    kind: str = "positional"


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


@dataclass(frozen=True, slots=True)
class For:
    target: Name
    iterable: Expression
    body: tuple[Statement, ...]
    is_async: bool
    span: SourceSpan


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
