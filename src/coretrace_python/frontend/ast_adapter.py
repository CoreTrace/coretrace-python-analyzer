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
_COMPREHENSIONS = {ast.ListComp: "list", ast.SetComp: "set", ast.GeneratorExp: "generator", ast.DictComp: "dict"}
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
            comparisons: list[nodes.Expression] = []
            left = self.expression(node.left)
            for op, comparator in zip(node.ops, node.comparators, strict=True):
                operator = _COMPARE_OPERATORS.get(type(op))
                if operator is None:
                    self.fail(op)
                right = self.expression(comparator)
                comparisons.append(nodes.Compare(operator, left, right, span))
                left = right
            if len(comparisons) == 1:
                return comparisons[0]
            return nodes.BoolOp("and", tuple(comparisons), span)
        if isinstance(node, ast.BoolOp):
            operator = "and" if isinstance(node.op, ast.And) else "or"
            return nodes.BoolOp(operator, tuple(self.expression(v) for v in node.values), span)
        if isinstance(node, ast.Tuple):
            return nodes.Tuple(self.elements(node.elts), span)
        if isinstance(node, ast.List):
            return nodes.List(self.elements(node.elts), span)
        if isinstance(node, ast.Dict):
            items: list[tuple[nodes.Expression | None, nodes.Expression]] = []
            for key, value in zip(node.keys, node.values, strict=True):
                items.append((None if key is None else self.expression(key), self.expression(value)))
            return nodes.Dict(tuple(items), span)
        if isinstance(node, ast.JoinedStr):
            return nodes.FormattedString(tuple(self.formatted_parts(node)), span)
        if isinstance(node, ast.Slice):
            return nodes.Slice(
                self.expression(node.lower) if node.lower is not None else None,
                self.expression(node.upper) if node.upper is not None else None,
                self.expression(node.step) if node.step is not None else None,
                span,
            )
        if isinstance(node, ast.Starred):
            return nodes.Starred(self.expression(node.value), span)
        if isinstance(node, ast.Set):
            return nodes.Set(self.elements(node.elts), span)
        if isinstance(node, ast.IfExp):
            return nodes.Conditional(
                self.expression(node.test), self.expression(node.body), self.expression(node.orelse), span
            )
        if isinstance(node, ast.Lambda):
            return nodes.Lambda(self.parameters(node.args), self.expression(node.body), span)
        if isinstance(node, ast.DictComp):
            generators = tuple(self.generator(generator) for generator in node.generators)
            return nodes.Comprehension("dict", self.expression(node.value), generators, span, self.expression(node.key))
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
        if isinstance(node, ast.Await):
            return nodes.Await(self.expression(node.value), span)
        if isinstance(node, ast.Yield):
            yielded = self.expression(node.value) if node.value is not None else None
            return nodes.Yield(yielded, span)
        if isinstance(node, ast.YieldFrom):
            return nodes.Yield(self.expression(node.value), span, True)
        if isinstance(node, ast.NamedExpr):
            assert isinstance(node.target, ast.Name)
            target = nodes.Name(node.target.id, self.span(node.target))
            return nodes.NamedExpr(target, self.expression(node.value), span)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            generators = tuple(self.generator(generator) for generator in node.generators)
            return nodes.Comprehension(
                _COMPREHENSIONS[type(node)], self.expression(node.elt), generators, span
            )
        self.fail(node)

    def elements(self, elements: list[ast.expr]) -> tuple[nodes.Expression, ...]:
        return tuple(self.expression(element) for element in elements)

    def formatted_parts(self, node: ast.JoinedStr) -> list[nodes.Expression]:
        parts: list[nodes.Expression] = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(nodes.Constant(value.value, self.span(value)))
            elif isinstance(value, ast.FormattedValue):
                parts.append(self.expression(value.value))
                if isinstance(value.format_spec, ast.JoinedStr):
                    parts.extend(p for p in self.formatted_parts(value.format_spec) if not isinstance(p, nodes.Constant))
            else:  # pragma: no cover - the grammar allows nothing else
                self.fail(value)
        return parts

    def target(self, node: ast.expr) -> nodes.Target:
        if isinstance(node, ast.Name):
            return nodes.Name(node.id, self.span(node))
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            target = self.expression(node)
            assert isinstance(target, (nodes.Attribute, nodes.Subscript))
            return target
        if isinstance(node, (ast.Tuple, ast.List)):
            elements: list[nodes.Expression] = []
            for element in node.elts:
                if isinstance(element, ast.Starred):
                    elements.append(nodes.Starred(self.target(element.value), self.span(element)))
                else:
                    elements.append(self.target(element))
            return nodes.Tuple(tuple(elements), self.span(node))
        self.fail(node, f"unsupported assignment target: {type(node).__name__}")

    def generator(self, node: ast.comprehension) -> nodes.ComprehensionGenerator:
        if node.is_async:
            self.fail(node.target, "async comprehensions are not supported yet")
        target = self.target(node.target)
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

    def statements(self, node: ast.stmt) -> list[nodes.Statement]:
        """The HIR statements of one source statement: several for ``a = b = value``,
        which assigns a hidden local once and every target from it."""

        span = self.span(node)
        if isinstance(node, ast.Assign) and len(node.targets) > 1:
            hidden = nodes.Name(f"_coretrace_chain_{span.start_line}_{span.start_column}", span)
            found: list[nodes.Statement] = [nodes.Assign(hidden, self.expression(node.value), span)]
            found.extend(nodes.Assign(self.target(target), hidden, self.span(target)) for target in node.targets)
            return found
        return [self.statement(node)]

    def statement(self, node: ast.stmt) -> nodes.Statement:
        span = self.span(node)
        if isinstance(node, ast.Assign):
            return nodes.Assign(self.target(node.targets[0]), self.expression(node.value), span)
        if isinstance(node, ast.AnnAssign):
            # The annotation never affects behaviour; a bare declaration binds nothing
            # but names a dataclass field or an annotated local.
            if node.value is None:
                annotation: nodes.Expression | None = None
                try:
                    annotation = self.expression(node.annotation)
                except HIRBuildError:
                    annotation = None
                name = node.target.id if isinstance(node.target, ast.Name) else None
                return nodes.Declaration(name, annotation, span) if name is not None else nodes.Pass(span)
            return nodes.Assign(self.target(node.target), self.expression(node.value), span)
        if isinstance(node, ast.AugAssign):
            operator = _BINARY_OPERATORS.get(type(node.op))
            if operator is None:
                self.fail(node.op)
            target = self.target(node.target)
            if isinstance(target, nodes.Tuple):
                self.fail(node.target, "unsupported augmented assignment target")
            return nodes.AugAssign(target, operator, self.expression(node.value), span)
        if isinstance(node, ast.Assert):
            message = self.expression(node.msg) if node.msg is not None else None
            return nodes.Assert(self.expression(node.test), message, span)
        if isinstance(node, (ast.With, ast.AsyncWith)):
            items = []
            for item in node.items:
                bound: nodes.Target | None = None
                if item.optional_vars is not None:
                    bound = self.target(item.optional_vars)
                items.append(
                    nodes.WithItem(
                        self.expression(item.context_expr), bound, self.span(item.context_expr)
                    )
                )
            return nodes.With(tuple(items), self.block(node.body), isinstance(node, ast.AsyncWith), span)
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
        if isinstance(node, ast.If):
            return nodes.If(
                self.expression(node.test), self.block(node.body), self.block(node.orelse), span
            )
        if isinstance(node, ast.While):
            return nodes.While(self.expression(node.test), self.block(node.body), span, self.block(node.orelse))
        if isinstance(node, (ast.For, ast.AsyncFor)):
            body = self.block(node.body)
            if isinstance(node.target, ast.Name):
                target = nodes.Name(node.target.id, self.span(node.target))
            else:
                # ``for k, v in items`` binds a hidden local and destructures it first.
                target_span = self.span(node.target)
                target = nodes.Name(f"_coretrace_item_{target_span.start_line}_{target_span.start_column}", target_span)
                body = (nodes.Assign(self.target(node.target), target, target_span), *body)
            return nodes.For(
                target,
                self.expression(node.iter),
                body,
                isinstance(node, ast.AsyncFor),
                span,
                self.block(node.orelse),
            )
        if isinstance(node, ast.Break):
            return nodes.Break(span)
        if isinstance(node, ast.Delete):
            return nodes.Delete(tuple(self.target(target) for target in node.targets), span)
        if isinstance(node, ast.Match):
            cases = tuple(
                nodes.MatchCase(
                    self.pattern(case.pattern),
                    self.expression(case.guard) if case.guard is not None else None,
                    self.block(case.body),
                    self.span(case.pattern),
                )
                for case in node.cases
            )
            return nodes.Match(self.expression(node.subject), cases, span)
        if isinstance(node, ast.Continue):
            return nodes.Continue(span)
        if isinstance(node, ast.Raise):
            exception = self.expression(node.exc) if node.exc is not None else None
            cause = self.expression(node.cause) if node.cause is not None else None
            return nodes.Raise(exception, span, cause)
        if isinstance(node, ast.Try):
            handlers = []
            for handler in node.handlers:
                handler_type = self.expression(handler.type) if handler.type is not None else None
                handlers.append(
                    nodes.ExceptHandler(
                        handler_type, handler.name, self.block(handler.body), self.span(handler)
                    )
                )
            return nodes.Try(
                self.block(node.body),
                tuple(handlers),
                self.block(node.orelse),
                self.block(node.finalbody),
                span,
            )
        if isinstance(node, getattr(ast, "TryStar", ())):
            self.fail(node, "except* groups are not supported yet")
        if isinstance(node, ast.Global):
            return nodes.Global(tuple(node.names), span)
        if isinstance(node, ast.Nonlocal):
            return nodes.Nonlocal(tuple(node.names), span)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return self.function(node)
        if isinstance(node, ast.ClassDef):
            return self.class_definition(node)
        self.fail(node)

    def pattern(self, node: ast.pattern) -> nodes.Pattern:
        span = self.span(node)
        if isinstance(node, ast.MatchValue):
            return nodes.ValuePattern(self.expression(node.value), span)
        if isinstance(node, ast.MatchSingleton):
            return nodes.SingletonPattern(node.value, span)
        if isinstance(node, ast.MatchAs):
            if node.name is None:
                return nodes.WildcardPattern(span)
            inner = self.pattern(node.pattern) if node.pattern is not None else None
            return nodes.CapturePattern(node.name, inner, span)
        if isinstance(node, ast.MatchOr):
            return nodes.OrPattern(tuple(self.pattern(p) for p in node.patterns), span)
        if isinstance(node, ast.MatchStar):
            return nodes.StarPattern(node.name, span)
        if isinstance(node, ast.MatchSequence):
            return nodes.SequencePattern(tuple(self.pattern(p) for p in node.patterns), span)
        if isinstance(node, ast.MatchMapping):
            return nodes.MappingPattern(
                tuple(self.expression(k) for k in node.keys),
                tuple(self.pattern(p) for p in node.patterns),
                node.rest,
                span,
            )
        if isinstance(node, ast.MatchClass):
            return nodes.ClassPattern(
                self.expression(node.cls),
                tuple(self.pattern(p) for p in node.patterns),
                tuple(node.kwd_attrs),
                tuple(self.pattern(p) for p in node.kwd_patterns),
                span,
            )
        return nodes.UnsupportedPattern(type(node).__name__, span)

    def block(self, statements: list[ast.stmt]) -> tuple[nodes.Statement, ...]:
        return tuple(found for statement in statements for found in self.statements(statement))

    def class_definition(self, node: ast.ClassDef) -> nodes.Class:
        bases = tuple(self.expression(base) for base in node.bases)
        keywords = tuple(
            nodes.Keyword(keyword.arg, self.expression(keyword.value), self.span(keyword))
            for keyword in node.keywords
        )
        body = self.block(node.body)
        decorators = tuple(self.expression(d) for d in node.decorator_list)
        return nodes.Class(node.name, bases, body, self.span(node), decorators, keywords)

    def function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> nodes.Function:
        body = self.block(node.body)
        return nodes.Function(
            name=node.name,
            parameters=self.parameters(node.args),
            body=body,
            is_async=isinstance(node, ast.AsyncFunctionDef),
            span=self.span(node),
            decorators=tuple(self.expression(d) for d in node.decorator_list),
        )

    def parameters(self, arguments: ast.arguments) -> tuple[nodes.Parameter, ...]:
        positional = [*arguments.posonlyargs, *arguments.args]
        defaults: list[ast.expr | None] = [None] * (len(positional) - len(arguments.defaults))
        defaults.extend(arguments.defaults)
        parameters: list[nodes.Parameter] = []
        for argument, default in zip(positional, defaults, strict=True):
            parameters.append(self.parameter(argument, default, "positional"))
        if arguments.vararg is not None:
            parameters.append(self.parameter(arguments.vararg, None, "var_positional"))
        for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults, strict=True):
            parameters.append(self.parameter(argument, default, "keyword"))
        if arguments.kwarg is not None:
            parameters.append(self.parameter(arguments.kwarg, None, "var_keyword"))
        return tuple(parameters)

    def parameter(self, argument: ast.arg, default: ast.expr | None, kind: str) -> nodes.Parameter:
        value = self.expression(default) if default is not None else None
        annotation: nodes.Expression | None = None
        if argument.annotation is not None:
            # Annotations never affect behaviour; one the HIR cannot represent is dropped.
            try:
                annotation = self.expression(argument.annotation)
            except HIRBuildError:
                annotation = None
        return nodes.Parameter(argument.arg, self.span(argument), value, kind, annotation)

    def module(self, tree: ast.Module) -> nodes.Module:
        body = self.block(tree.body)
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
        return nodes.Module(self._source.module_name, body, span, self._source.is_package)


def build_module(source: SourceFile, tree: ast.Module) -> nodes.Module:
    return AstHIRBuilder(source).module(tree)
