"""Lower parser-independent PyHIR into analysis-oriented PyIR."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NoReturn

from coretrace_python.hir import nodes
from coretrace_python.ir.model import (
    BasicBlock,
    BinaryOp,
    Call,
    Compare,
    Constant,
    FunctionIR,
    GetAttr,
    GetItem,
    Global,
    LoadLocal,
    ModuleIR,
    Return,
    StoreLocal,
    Symbol,
    UnaryOp,
    Value,
    ValueInstruction,
)
from coretrace_python.semantic.imports import ImportBindings, collect_imports
from coretrace_python.semantic.symbols import SymbolId


class LoweringError(Exception):
    """Raised when PyHIR uses constructs outside the current PyIR subset."""


@dataclass
class _FunctionLowerer:
    imports: ImportBindings
    next_value_id: int = 0
    locals: set[str] = field(default_factory=set)
    parameters: dict[str, Value] = field(default_factory=dict)
    block: BasicBlock = field(default_factory=lambda: BasicBlock("entry"))

    def fail(
        self,
        node: nodes.Statement | nodes.Expression,
        message: str | None = None,
    ) -> NoReturn:
        detail = message or f"unsupported syntax: {type(node).__name__}"
        raise LoweringError(f"{node.span.display()}: {detail}")

    def new_value(self) -> Value:
        value = Value(self.next_value_id)
        self.next_value_id += 1
        return value

    def emit(self, instruction: ValueInstruction) -> Value:
        self.block.instructions.append(instruction)
        return instruction.result

    def emit_effect(self, instruction: StoreLocal | Return) -> None:
        self.block.instructions.append(instruction)

    def imported_symbol(self, node: nodes.Expression) -> SymbolId | None:
        if isinstance(node, nodes.Name):
            if node.identifier in self.locals or node.identifier in self.parameters:
                return None
            return self.imports.resolve(node.identifier)
        if isinstance(node, nodes.Attribute):
            parent = self.imported_symbol(node.value)
            return parent.attribute(node.name) if parent is not None else None
        return None

    def expression(self, node: nodes.Expression) -> Value:
        imported_symbol = self.imported_symbol(node)
        if imported_symbol is not None:
            return self.emit(Symbol(self.new_value(), node.span, imported_symbol))
        if isinstance(node, nodes.Name):
            if node.identifier in self.locals:
                return self.emit(LoadLocal(self.new_value(), node.span, node.identifier))
            if node.identifier in self.parameters:
                return self.parameters[node.identifier]
            return self.emit(Global(self.new_value(), node.span, node.identifier))
        if isinstance(node, nodes.Constant):
            return self.emit(Constant(self.new_value(), node.span, node.value))
        if isinstance(node, nodes.BinaryOp):
            left = self.expression(node.left)
            right = self.expression(node.right)
            return self.emit(BinaryOp(self.new_value(), node.span, node.operator, left, right))
        if isinstance(node, nodes.UnaryOp):
            operand = self.expression(node.operand)
            return self.emit(UnaryOp(self.new_value(), node.span, node.operator, operand))
        if isinstance(node, nodes.Compare):
            left = self.expression(node.left)
            right = self.expression(node.right)
            return self.emit(Compare(self.new_value(), node.span, node.operator, left, right))
        if isinstance(node, nodes.Call):
            if node.keywords:
                self.fail(node, "keyword arguments are not supported yet")
            callee = self.expression(node.callee)
            arguments = tuple(self.expression(argument) for argument in node.arguments)
            return self.emit(Call(self.new_value(), node.span, callee, arguments))
        if isinstance(node, nodes.Attribute):
            object_value = self.expression(node.value)
            return self.emit(GetAttr(self.new_value(), node.span, object_value, node.name))
        if isinstance(node, nodes.Subscript):
            object_value = self.expression(node.value)
            key = self.expression(node.key)
            return self.emit(GetItem(self.new_value(), node.span, object_value, key))
        self.fail(node)

    def statement(self, node: nodes.Statement) -> None:
        if isinstance(node, nodes.Assign):
            value = self.expression(node.value)
            self.emit_effect(StoreLocal(None, node.span, node.target.identifier, value))
            self.locals.add(node.target.identifier)
            return
        if isinstance(node, nodes.Return):
            return_value = self.expression(node.value) if node.value is not None else None
            self.emit_effect(Return(None, node.span, return_value))
            return
        if isinstance(node, nodes.ExpressionStatement):
            self.expression(node.expression)
            return
        if isinstance(node, nodes.Pass):
            return
        self.fail(node)

    def function(self, node: nodes.Function) -> FunctionIR:
        parameters = tuple(self.new_value() for _ in node.parameters)
        parameter_names = (parameter.name for parameter in node.parameters)
        self.parameters.update(zip(parameter_names, parameters, strict=True))
        for statement in node.body:
            self.statement(statement)
        return FunctionIR(node.name, parameters, (self.block,), node.span)


def lower_module(module: nodes.Module) -> ModuleIR:
    imports = collect_imports(module)
    functions: list[FunctionIR] = []
    for statement in module.body:
        if isinstance(statement, nodes.Function):
            functions.append(_FunctionLowerer(imports).function(statement))
        elif isinstance(statement, (nodes.Import, nodes.ImportFrom)):
            continue
        elif (
            isinstance(statement, nodes.ExpressionStatement)
            and isinstance(statement.expression, nodes.Constant)
            and isinstance(statement.expression.value, str)
        ):
            # Permit module docstrings.
            continue
        else:
            raise LoweringError(
                f"{statement.span.display()}: "
                f"unsupported module syntax: {type(statement).__name__}"
            )
    return ModuleIR(tuple(functions))
