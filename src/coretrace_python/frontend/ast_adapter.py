"""Adapter from Python's standard-library AST to parser-independent PyHIR."""

from __future__ import annotations

import ast
from typing import NoReturn

from coretrace_python.hir import nodes
from coretrace_python.source import SourceFile, SourceSpan


class HIRBuildError(Exception):
    """A source-located failure to represent parsed syntax as PyHIR."""


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
_COMPREHENSIONS = {ast.ListComp: "list", ast.SetComp: "set", ast.GeneratorExp: "generator"}
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


class AstHIRBuilder:
    """Build PyHIR while containing every dependency on ``ast`` in this adapter."""

    def __init__(self, source: SourceFile) -> None:
        self._source = source

    def span(self, node: ast.AST) -> SourceSpan:
        end_line = getattr(node, "end_lineno", None)
        end_offset = getattr(node, "end_col_offset", None)
        return SourceSpan(
            source_id=self._source.source_id,
            start_line=getattr(node, "lineno", 1),
            start_column=getattr(node, "col_offset", 0) + 1,
            end_line=end_line,
            end_column=end_offset + 1 if end_offset is not None else None,
        )

    def fail(self, node: ast.AST, message: str | None = None) -> NoReturn:
        span = self.span(node)
        detail = message or f"unsupported syntax: {type(node).__name__}"
        raise HIRBuildError(f"{span.display()}: {detail}")

    def expression(self, node: ast.expr) -> nodes.Expression:
        span = self.span(node)
        if isinstance(node, ast.Name):
            return nodes.Name(node.id, span)
        if isinstance(node, ast.Constant):
            return nodes.Constant(node.value, span)
        if isinstance(node, ast.BinOp):
            operator = _BINARY_OPERATORS.get(type(node.op))
            if operator is None:
                self.fail(node.op)
            return nodes.BinaryOp(operator, self.expression(node.left), self.expression(node.right), span)
        if isinstance(node, ast.UnaryOp):
            operator = _UNARY_OPERATORS.get(type(node.op))
            if operator is None:
                self.fail(node.op)
            return nodes.UnaryOp(operator, self.expression(node.operand), span)
        if isinstance(node, ast.Compare):
            if len(node.ops) != 1 or len(node.comparators) != 1:
                self.fail(node, "chained comparisons are not supported yet")
            operator = _COMPARE_OPERATORS.get(type(node.ops[0]))
            if operator is None:
                self.fail(node.ops[0])
            return nodes.Compare(
                operator,
                self.expression(node.left),
                self.expression(node.comparators[0]),
                span,
            )
        if isinstance(node, ast.Attribute):
            return nodes.Attribute(self.expression(node.value), node.attr, span)
        if isinstance(node, ast.Subscript):
            return nodes.Subscript(self.expression(node.value), self.expression(node.slice), span)
        if isinstance(node, ast.Call):
            arguments = tuple(self.expression(argument) for argument in node.args)
            keywords = tuple(
                nodes.Keyword(keyword.arg, self.expression(keyword.value), self.span(keyword))
                for keyword in node.keywords
            )
            return nodes.Call(self.expression(node.func), arguments, keywords, span)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            generators = tuple(self.generator(generator) for generator in node.generators)
            return nodes.Comprehension(
                _COMPREHENSIONS[type(node)], self.expression(node.elt), generators, span
            )
        self.fail(node)

    def generator(self, node: ast.comprehension) -> nodes.ComprehensionGenerator:
        if node.is_async:
            self.fail(node.target, "async comprehensions are not supported yet")
        if not isinstance(node.target, ast.Name):
            self.fail(node.target, "only a single name is supported as a comprehension target")
        target = nodes.Name(node.target.id, self.span(node.target))
        conditions = tuple(self.expression(condition) for condition in node.ifs)
        # ``ast.comprehension`` carries no location; span it from the target to the last clause.
        last = self.span(node.ifs[-1] if node.ifs else node.iter)
        span = SourceSpan(
            self._source.source_id,
            target.span.start_line,
            target.span.start_column,
            last.end_line,
            last.end_column,
        )
        return nodes.ComprehensionGenerator(target, self.expression(node.iter), conditions, span)

    def statement(self, node: ast.stmt) -> nodes.Statement:
        span = self.span(node)
        if isinstance(node, ast.Assign):
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                self.fail(node, "only assignment to one local name is supported")
            target = nodes.Name(node.targets[0].id, self.span(node.targets[0]))
            return nodes.Assign(target, self.expression(node.value), span)
        if isinstance(node, ast.Return):
            value = self.expression(node.value) if node.value is not None else None
            return nodes.Return(value, span)
        if isinstance(node, ast.Expr):
            return nodes.ExpressionStatement(self.expression(node.value), span)
        if isinstance(node, ast.Pass):
            return nodes.Pass(span)
        if isinstance(node, ast.Import):
            aliases = tuple(
                nodes.ImportAlias(alias.name, alias.asname, self.span(alias)) for alias in node.names
            )
            return nodes.Import(aliases, span)
        if isinstance(node, ast.ImportFrom):
            aliases = tuple(
                nodes.ImportAlias(alias.name, alias.asname, self.span(alias)) for alias in node.names
            )
            return nodes.ImportFrom(node.module, aliases, node.level, span)
        if isinstance(node, ast.Global):
            return nodes.Global(tuple(node.names), span)
        if isinstance(node, ast.Nonlocal):
            return nodes.Nonlocal(tuple(node.names), span)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return self.function(node)
        if isinstance(node, ast.ClassDef):
            return self.class_definition(node)
        self.fail(node)

    def class_definition(self, node: ast.ClassDef) -> nodes.Class:
        if node.decorator_list:
            self.fail(node, "decorated classes are not supported yet")
        if node.keywords:
            self.fail(node, "class keyword arguments are not supported yet")
        bases = tuple(self.expression(base) for base in node.bases)
        body = tuple(self.statement(statement) for statement in node.body)
        return nodes.Class(node.name, bases, body, self.span(node))

    def function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> nodes.Function:
        if node.decorator_list:
            self.fail(node, "decorated functions are not supported yet")
        arguments = node.args
        has_advanced_arguments = (
            arguments.posonlyargs or arguments.kwonlyargs or arguments.vararg or arguments.kwarg
        )
        if has_advanced_arguments or arguments.defaults or arguments.kw_defaults:
            self.fail(arguments, "only required positional arguments are supported")
        parameters = tuple(
            nodes.Parameter(argument.arg, self.span(argument)) for argument in arguments.args
        )
        body = tuple(self.statement(statement) for statement in node.body)
        return nodes.Function(
            name=node.name,
            parameters=parameters,
            body=body,
            is_async=isinstance(node, ast.AsyncFunctionDef),
            span=self.span(node),
        )

    def module(self, tree: ast.Module) -> nodes.Module:
        body = tuple(self.statement(statement) for statement in tree.body)
        if tree.body:
            first_span = self.span(tree.body[0])
            last_span = self.span(tree.body[-1])
            span = SourceSpan(
                self._source.source_id,
                first_span.start_line,
                first_span.start_column,
                last_span.end_line,
                last_span.end_column,
            )
        else:
            span = SourceSpan(self._source.source_id, 1, 1, 1, 1)
        return nodes.Module(body, span)


def build_module(source: SourceFile, tree: ast.Module) -> nodes.Module:
    return AstHIRBuilder(source).module(tree)
