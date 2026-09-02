from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import TypeAlias


@dataclass(frozen=True)
class SourceLocation:
    filename: str
    line: int
    column: int
    end_line: int | None = None
    end_column: int | None = None

    @classmethod
    def from_ast(cls, filename: str, node: ast.AST) -> SourceLocation:
        return cls(filename, getattr(node, "lineno", 1), getattr(node, "col_offset", 0) + 1)


@dataclass(frozen=True)
class Value:
    id: int


@dataclass(frozen=True)
class Constant:
    result: Value
    location: SourceLocation
    value: object


@dataclass(frozen=True)
class Global:
    result: Value
    location: SourceLocation
    name: str


@dataclass(frozen=True)
class BinaryOp:
    result: Value
    location: SourceLocation
    operator: str
    left: Value
    right: Value


@dataclass(frozen=True)
class UnaryOp:
    result: Value
    location: SourceLocation
    operator: str
    operand: Value


@dataclass(frozen=True)
class Compare:
    result: Value
    location: SourceLocation
    operator: str
    left: Value
    right: Value


@dataclass(frozen=True)
class Call:
    result: Value
    location: SourceLocation
    callee: Value
    arguments: tuple[Value, ...]


@dataclass(frozen=True)
class GetAttr:
    result: Value
    location: SourceLocation
    object: Value
    attribute: str


@dataclass(frozen=True)
class GetItem:
    result: Value
    location: SourceLocation
    object: Value
    key: Value


@dataclass(frozen=True)
class Return:
    result: None
    location: SourceLocation
    value: Value | None


Instruction: TypeAlias = (
    Constant | Global | BinaryOp | UnaryOp | Compare | Call | GetAttr | GetItem | Return
)


@dataclass(frozen=True)
class BasicBlock:
    name: str
    instructions: list[Instruction]

    def __init__(self, name: str, instructions: list[Instruction] | None = None) -> None:
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "instructions", instructions or [])


@dataclass(frozen=True)
class FunctionIR:
    name: str
    parameters: tuple[Value, ...]
    blocks: tuple[BasicBlock, ...]
    location: SourceLocation


@dataclass(frozen=True)
class ModuleIR:
    functions: tuple[FunctionIR, ...]
