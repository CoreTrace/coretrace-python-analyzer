from __future__ import annotations

import ast
from dataclasses import dataclass, field

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
    ModuleIR,
    Return,
    SourceLocation,
    UnaryOp,
    Value,
)


class LoweringError(Exception):
    """Raised when source uses syntax outside the current PyIR subset."""


_BINARY_OPERATORS = {
    ast.Add: "add",
    ast.Sub: "sub",
    ast.Mult: "mul",
    ast.Div: "div",
    ast.FloorDiv: "floor_div",
    ast.Mod: "mod",
    ast.Pow: "pow",
    ast.LShift: "lshift",
    ast.RShift: "rshift",
    ast.BitOr: "bit_or",
    ast.BitXor: "bit_xor",
    ast.BitAnd: "bit_and",
    ast.MatMult: "matmul",
}
_UNARY_OPERATORS = {ast.Invert: "invert", ast.Not: "not", ast.UAdd: "pos", ast.USub: "neg"}
_COMPARE_OPERATORS = {
    ast.Eq: "eq",
    ast.NotEq: "not_eq",
    ast.Lt: "lt",
    ast.LtE: "lt_eq",
    ast.Gt: "gt",
    ast.GtE: "gt_eq",
    ast.Is: "is",
    ast.IsNot: "is_not",
    ast.In: "in",
    ast.NotIn: "not_in",
}


@dataclass
class _FunctionLowerer:
    filename: str
    next_value_id: int = 0
    locals: dict[str, Value] = field(default_factory=dict)
    block: BasicBlock = field(default_factory=lambda: BasicBlock("entry"))

    def location(self, node: ast.AST) -> SourceLocation:
        return SourceLocation(
            filename=self.filename,
            line=getattr(node, "lineno", 1),
            column=getattr(node, "col_offset", 0) + 1,
            end_line=getattr(node, "end_lineno", None),
            end_column=(getattr(node, "end_col_offset", 0) + 1)
            if getattr(node, "end_col_offset", None) is not None
            else None,
        )

    def fail(self, node: ast.AST, message: str | None = None) -> None:
        location = self.location(node)
        detail = message or f"unsupported syntax: {type(node).__name__}"
        raise LoweringError(f"{location.filename}:{location.line}:{location.column}: {detail}")

    def new_value(self) -> Value:
        value = Value(self.next_value_id)
        self.next_value_id += 1
        return value

    def emit(self, instruction):
        self.block.instructions.append(instruction)
        return instruction.result

    def expression(self, node: ast.expr) -> Value:
        location = self.location(node)
        if isinstance(node, ast.Name):
            if node.id in self.locals:
                return self.locals[node.id]
            return self.emit(Global(self.new_value(), location, node.id))
        if isinstance(node, ast.Constant):
            return self.emit(Constant(self.new_value(), location, node.value))
        if isinstance(node, ast.BinOp):
            operator = _BINARY_OPERATORS.get(type(node.op))
            if operator is None:
                self.fail(node.op)
            left = self.expression(node.left)
            right = self.expression(node.right)
            return self.emit(
                BinaryOp(
                    self.new_value(),
                    location,
                    operator,
                    left,
                    right,
                )
            )
        if isinstance(node, ast.UnaryOp):
            operator = _UNARY_OPERATORS.get(type(node.op))
            if operator is None:
                self.fail(node.op)
            operand = self.expression(node.operand)
            return self.emit(UnaryOp(self.new_value(), location, operator, operand))
        if isinstance(node, ast.Compare):
            if len(node.ops) != 1 or len(node.comparators) != 1:
                self.fail(node, "chained comparisons are not supported yet")
            operator = _COMPARE_OPERATORS.get(type(node.ops[0]))
            if operator is None:
                self.fail(node.ops[0])
            left = self.expression(node.left)
            right = self.expression(node.comparators[0])
            return self.emit(
                Compare(
                    self.new_value(),
                    location,
                    operator,
                    left,
                    right,
                )
            )
        if isinstance(node, ast.Call):
            if node.keywords:
                self.fail(node, "keyword arguments are not supported yet")
            callee = self.expression(node.func)
            arguments = tuple(self.expression(argument) for argument in node.args)
            return self.emit(Call(self.new_value(), location, callee, arguments))
        if isinstance(node, ast.Attribute):
            object_value = self.expression(node.value)
            return self.emit(GetAttr(self.new_value(), location, object_value, node.attr))
        if isinstance(node, ast.Subscript):
            object_value = self.expression(node.value)
            key = self.expression(node.slice)
            return self.emit(GetItem(self.new_value(), location, object_value, key))
        self.fail(node)

    def statement(self, node: ast.stmt) -> None:
        if isinstance(node, ast.Assign):
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                self.fail(node, "only assignment to one local name is supported")
            self.locals[node.targets[0].id] = self.expression(node.value)
            return
        if isinstance(node, ast.Return):
            value = self.expression(node.value) if node.value is not None else None
            self.emit(Return(None, self.location(node), value))
            return
        if isinstance(node, ast.Expr):
            self.expression(node.value)
            return
        if isinstance(node, ast.Pass):
            return
        self.fail(node)

    def function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> FunctionIR:
        if node.decorator_list:
            self.fail(node, "decorated functions are not supported yet")
        has_advanced_arguments = (
            node.args.posonlyargs or node.args.kwonlyargs or node.args.vararg or node.args.kwarg
        )
        if has_advanced_arguments:
            self.fail(node.args, "only positional arguments are supported")
        parameters = tuple(self.new_value() for _ in node.args.args)
        argument_names = (argument.arg for argument in node.args.args)
        self.locals.update(zip(argument_names, parameters, strict=True))
        for statement in node.body:
            self.statement(statement)
        return FunctionIR(node.name, parameters, (self.block,), self.location(node))


def lower_module(tree: ast.Module, filename: str = "<unknown>") -> ModuleIR:
    functions: list[FunctionIR] = []
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(_FunctionLowerer(filename).function(statement))
        elif isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
            # Permit module docstrings.
            continue
        else:
            location = SourceLocation.from_ast(filename, statement)
            raise LoweringError(
                f"{filename}:{location.line}:{location.column}: "
                f"unsupported module syntax: {type(statement).__name__}"
            )
    return ModuleIR(tuple(functions))
