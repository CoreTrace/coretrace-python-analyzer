"""Immutable nodes for the Python high-level intermediate representation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias

from coretrace_python.source import SourceSpan


@dataclass(frozen=True, slots=True)
class Parameter:
    name: str
    span: SourceSpan


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
    | Compare
    | Attribute
    | Subscript
    | Call
    | Comprehension
)


@dataclass(frozen=True, slots=True)
class Assign:
    target: Name
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


@dataclass(frozen=True, slots=True)
class Class:
    name: str
    bases: tuple[Expression, ...]
    body: tuple[Statement, ...]
    span: SourceSpan


Statement: TypeAlias = (
    Assign
    | Return
    | ExpressionStatement
    | Pass
    | If
    | While
    | For
    | Break
    | Continue
    | Raise
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

