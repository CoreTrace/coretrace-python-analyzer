"""Build a control-flow graph from a PyHIR function."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import fields, is_dataclass, replace
from typing import Any, ClassVar

from coretrace_python.analysis import AnalysisContext, FunctionAnalysis
from coretrace_python.cfg.model import (
    CFG,
    BasicBlock,
    BlockId,
    Branch,
    CFGError,
    ForEach,
    Jump,
    Raise,
    Return,
    Terminator,
)
from coretrace_python.hir import nodes
from coretrace_python.source import SourceSpan


class _Open:
    """A block that is still collecting statements and has no terminator yet."""

    def __init__(self, block_id: BlockId) -> None:
        self.id = block_id
        self.statements: list[nodes.Statement] = []


class _Builder:
    def __init__(
        self, function: nodes.Function, match_args: Mapping[str, tuple[str, ...]] | None = None
    ) -> None:
        self.match_args = dict(match_args or {})
        self.function = function
        self.blocks: dict[BlockId, BasicBlock] = {}
        self.counters: dict[str, int] = {}
        self.loops: list[tuple[BlockId, BlockId]] = []
        self.handlers: list[tuple[BlockId, ...]] = []
        self.synthetic: set[str] = set()

    def build(self) -> CFG:
        entry = BlockId("entry")
        end = self.sequence(self.function.body, _Open(entry), None, self.function.span)
        if end is not None:
            self.finish(end, Return(None, self.function.span))
        return CFG(entry, self.blocks, frozenset(self.synthetic))

    # ------------------------------------------------------------------ expression-level control flow

    def hidden(self, kind: str, span: SourceSpan) -> nodes.Name:
        name = f"_coretrace_{kind}_{span.start_line}_{span.start_column}_{len(self.synthetic)}"
        self.synthetic.add(name)
        return nodes.Name(name, span)

    def desugared(self, node: nodes.Statement, block: _Open) -> tuple[nodes.Statement, _Open]:
        """``node`` with its conditional expressions and comprehensions replaced by reads
        of synthetic locals, after laying out the statements that compute them."""

        pending: list[nodes.Statement] = []
        if isinstance(node, nodes.While):
            if not _has_control_flow(node.condition):
                return node, block
            # ``while <control flow>:`` recomputes its condition every iteration: it
            # becomes ``while True`` with the condition laid out at the top of the body
            # and a ``break``; the ``else`` clause runs before that ``break``.
            inner: list[nodes.Statement] = []
            condition = self.hoist(node.condition, inner)
            stop = nodes.If(
                nodes.UnaryOp("not", condition, node.span),
                (*node.orelse, nodes.Break(node.span)),
                (),
                node.span,
            )
            return (
                replace(
                    node,
                    condition=nodes.Constant(True, node.span),
                    body=(*inner, stop, *node.body),
                    orelse=(),
                ),
                block,
            )
        if isinstance(node, nodes.Assign | nodes.AugAssign):
            node = replace(node, target=self.hoist(node.target, pending), value=self.hoist(node.value, pending))
        elif isinstance(node, nodes.ExpressionStatement):
            node = replace(node, expression=self.hoist(node.expression, pending))
        elif isinstance(node, nodes.Return | nodes.Raise) and node.__class__ is nodes.Return:
            if node.value is not None:
                node = replace(node, value=self.hoist(node.value, pending))
        elif isinstance(node, nodes.Raise):
            exception = self.hoist(node.exception, pending) if node.exception is not None else None
            cause = self.hoist(node.cause, pending) if node.cause is not None else None
            node = replace(node, exception=exception, cause=cause)
        elif isinstance(node, nodes.Assert):
            message = self.hoist(node.message, pending) if node.message is not None else None
            node = replace(node, test=self.hoist(node.test, pending), message=message)
        elif isinstance(node, nodes.If):
            node = replace(node, condition=self.hoist(node.condition, pending))
        elif isinstance(node, nodes.For):
            node = replace(node, iterable=self.hoist(node.iterable, pending))
        elif isinstance(node, nodes.With):
            items = tuple(replace(item, context=self.hoist(item.context, pending)) for item in node.items)
            node = replace(node, items=items)
        if not pending:
            return node, block
        laid_out = self.sequence(tuple(pending), block, None, node.span)
        assert laid_out is not None, "hoisted statements always fall through"
        return node, laid_out

    def hoist(self, node: Any, pending: list[nodes.Statement]) -> Any:
        """Rewrite one expression tree, appending the statements it needs to ``pending``."""

        if isinstance(node, nodes.Conditional):
            test = self.hoist(node.test, pending)
            result = self.hidden("cond", node.span)
            pending.append(
                nodes.If(
                    test,
                    (nodes.Assign(result, node.body, node.span),),
                    (nodes.Assign(result, node.orelse, node.span),),
                    node.span,
                )
            )
            return result
        if isinstance(node, nodes.Comprehension):
            return self.comprehension(node, pending)
        if isinstance(node, nodes.NamedExpr):
            pending.append(nodes.Assign(node.target, self.hoist(node.value, pending), node.span))
            return node.target
        if isinstance(node, nodes.Lambda):
            defaults = tuple(
                replace(p, default=self.hoist(p.default, pending)) if p.default is not None else p
                for p in node.parameters
            )
            return replace(node, parameters=defaults)
        if isinstance(node, tuple):
            return tuple(self.hoist(item, pending) for item in node)
        if is_dataclass(node) and not isinstance(node, type):
            changes = {
                f.name: self.hoist(getattr(node, f.name), pending)
                for f in fields(node)
                if f.name != "span" and _may_hold_expressions(getattr(node, f.name))
            }
            return replace(node, **changes) if changes else node
        return node

    def comprehension(self, node: nodes.Comprehension, pending: list[nodes.Statement]) -> nodes.Name:
        """Lay a comprehension out as loops filling a synthetic collection."""

        span = node.span
        result = self.hidden("comp", span)
        renames: dict[str, str] = {}
        for generator in node.generators:
            for name in _bound_names(generator.target):
                renames[name] = self.hidden(f"var_{name}", generator.target.span).identifier
        if node.kind == "set":
            initial: nodes.Expression = nodes.Call(nodes.Name("set", span), (), (), span)
        elif node.kind == "dict":
            initial = nodes.Dict((), span)
        else:
            initial = nodes.List((), span)
        pending.append(nodes.Assign(result, initial, span))

        element = _rename(node.element, renames)
        if node.kind == "dict":
            assert node.key is not None
            innermost: nodes.Statement = nodes.Assign(
                nodes.Subscript(result, _rename(node.key, renames), span), element, span
            )
        else:
            method = "add" if node.kind == "set" else "append"
            call = nodes.Call(nodes.Attribute(result, method, span), (element,), (), span)
            innermost = nodes.ExpressionStatement(call, span)

        body: tuple[nodes.Statement, ...] = (innermost,)
        for index in range(len(node.generators) - 1, -1, -1):
            generator = node.generators[index]
            for condition in reversed(generator.conditions):
                body = (nodes.If(_rename(condition, renames), body, (), condition.span),)
            iterable = _rename(generator.iterable, renames) if index else self.hoist(generator.iterable, pending)
            if isinstance(generator.target, nodes.Name):
                target = nodes.Name(renames[generator.target.identifier], generator.target.span)
            else:
                target = self.hidden("item", generator.target.span)
                body = (nodes.Assign(_rename_target(generator.target, renames), target, generator.target.span), *body)
            body = (nodes.For(target, iterable, body, False, generator.span),)
        pending.extend(body)
        return result

    # ------------------------------------------------------------------ blocks

    def new_id(self, kind: str) -> BlockId:
        self.counters[kind] = self.counters.get(kind, 0) + 1
        return BlockId(f"{kind}_{self.counters[kind]}")

    def finish(self, block: _Open, terminator: Terminator) -> None:
        self.blocks[block.id] = BasicBlock(
            block.id, tuple(block.statements), terminator, self.exception_targets()
        )

    def header(self, block_id: BlockId, terminator: Terminator) -> None:
        self.blocks[block_id] = BasicBlock(block_id, (), terminator, self.exception_targets())

    def exception_targets(self) -> tuple[BlockId, ...]:
        return self.handlers[-1] if self.handlers else ()

    # ------------------------------------------------------------------ statements

    def sequence(
        self,
        statements: tuple[nodes.Statement, ...],
        block: _Open,
        continuation: BlockId | None,
        join_span: SourceSpan,
    ) -> _Open | None:
        """Lay ``statements`` out from ``block``.

        Returns the block left open at the end, or ``None`` when control left the
        sequence. With a ``continuation``, an open end jumps there instead.
        """

        current: _Open | None = block
        last_index = len(statements) - 1
        for index, statement in enumerate(statements):
            assert current is not None
            is_last = index == last_index
            current = self.statement(statement, current, continuation if is_last else None)
            if current is None and not is_last:
                current = _Open(self.new_id("dead"))
        if current is not None and continuation is not None:
            self.finish(current, Jump(continuation, join_span))
            return None
        return current

    def statement(
        self, node: nodes.Statement, block: _Open, continuation: BlockId | None
    ) -> _Open | None:
        node, block = self.desugared(node, block)
        if isinstance(node, nodes.Return):
            self.finish(block, Return(node.value, node.span))
            return None
        if isinstance(node, nodes.Raise):
            self.finish(block, Raise(node.exception, node.span, node.cause))
            return None
        if isinstance(node, nodes.Break):
            self.finish(block, Jump(self.loop("break", node.span)[1], node.span))
            return None
        if isinstance(node, nodes.Continue):
            self.finish(block, Jump(self.loop("continue", node.span)[0], node.span))
            return None
        if isinstance(node, nodes.If):
            return self.conditional(node, block, continuation)
        if isinstance(node, nodes.While | nodes.For):
            return self.loop_statement(node, block, continuation)
        if isinstance(node, nodes.Match):
            return self.match_statement(node, block, continuation)
        if isinstance(node, nodes.With):
            return self.with_statement(node, block)
        if isinstance(node, nodes.Try):
            return self.try_statement(node, block, continuation)
        block.statements.append(node)
        return block

    def try_statement(
        self, node: nodes.Try, block: _Open, continuation: BlockId | None
    ) -> _Open | None:
        """Body blocks carry exception edges to every handler; handlers, ``else`` and
        ``finally`` join on the normal path (exceptional exits are approximated)."""

        body_id = self.new_id("try")
        handler_ids = tuple(self.new_id("handler") for _ in node.handlers)
        else_id = self.new_id("else") if node.orelse else None
        final_id = self.new_id("finally") if node.finalbody else None
        after_id = continuation if continuation is not None and final_id is None else None
        if after_id is None:
            after_id = self.new_id("after") if final_id is None or continuation is None else None
        join = final_id if final_id is not None else after_id
        assert join is not None

        self.finish(block, Jump(body_id, node.span))
        self.handlers.append(handler_ids)
        try:
            # The whole body, including the block that leaves it, may raise into a handler.
            end = self.sequence(node.body, _Open(body_id), None, node.span)
            if end is not None:
                self.finish(end, Jump(else_id if else_id is not None else join, node.span))
        finally:
            self.handlers.pop()
        if end is not None and else_id is not None:
            self.sequence(node.orelse, _Open(else_id), join, node.span)
        for handler, handler_id in zip(node.handlers, handler_ids, strict=True):
            opened = _Open(handler_id)
            opened.statements.append(nodes.EnterHandler(handler, handler.span))
            self.sequence(handler.body, opened, join, node.span)
        if final_id is not None:
            target = continuation if continuation is not None else after_id
            assert target is not None
            self.sequence(node.finalbody, _Open(final_id), target, node.span)
            return None if continuation is not None else _Open(target)
        return None if continuation is not None else _Open(after_id)  # type: ignore[arg-type]

    def with_statement(self, node: nodes.With, block: _Open) -> _Open | None:
        """Lay the body out inline; an early exit skips the ``ExitWith`` statements."""

        for item in node.items:
            block.statements.append(nodes.EnterWith(item, node.span))
        current = self.sequence(node.body, block, None, node.span)
        if current is None:
            return None
        for item in reversed(node.items):
            current.statements.append(nodes.ExitWith(item, node.span))
        return current

    def conditional(
        self, node: nodes.If, block: _Open, continuation: BlockId | None
    ) -> _Open | None:
        merge = continuation if continuation is not None else self.new_id("merge")
        then_id = self.new_id("then")
        else_id = self.new_id("else") if node.orelse else merge
        self.finish(block, Branch(node.condition, then_id, else_id, node.span))
        self.sequence(node.body, _Open(then_id), merge, node.span)
        if node.orelse:
            self.sequence(node.orelse, _Open(else_id), merge, node.span)
        return None if continuation is not None else _Open(merge)

    def loop_statement(
        self, node: nodes.While | nodes.For, block: _Open, continuation: BlockId | None
    ) -> _Open | None:
        header_id = self.new_id("loop")
        body_id = self.new_id("body")
        after_id = continuation if continuation is not None else self.new_id("exit")
        # An ``else`` clause runs when the loop is exhausted; ``break`` skips it.
        exit_id = self.new_id("else") if node.orelse else after_id
        self.finish(block, Jump(header_id, node.span))
        if isinstance(node, nodes.While):
            self.header(header_id, Branch(node.condition, body_id, exit_id, node.span))
        else:
            self.header(header_id, ForEach(node.target, node.iterable, body_id, exit_id, node.span))
        self.loops.append((header_id, after_id))
        try:
            self.sequence(node.body, _Open(body_id), header_id, node.span)
        finally:
            self.loops.pop()
        if node.orelse:
            self.sequence(node.orelse, _Open(exit_id), after_id, node.span)
        return None if continuation is not None else _Open(after_id)

    def match_statement(
        self, node: nodes.Match, block: _Open, continuation: BlockId | None
    ) -> _Open | None:
        """``match`` as an ``if`` chain over a hidden subject: literal, singleton, capture,
        wildcard and or-patterns, with guards; other patterns are reported."""

        subject = self.hidden("match", node.span)
        statements: tuple[nodes.Statement, ...] = ()
        for case in reversed(node.cases):
            condition, bindings = self.pattern(case.pattern, subject)
            if case.guard is not None:
                condition = nodes.BoolOp("and", (condition, case.guard), case.span)
            statements = (*bindings, nodes.If(condition, case.body, statements, case.span))
        chain = (nodes.Assign(subject, node.subject, node.span), *statements)
        return self.sequence(chain, block, continuation, node.span)

    def pattern(
        self, node: nodes.Pattern, subject: nodes.Expression
    ) -> tuple[nodes.Expression, tuple[nodes.Statement, ...]]:
        """The condition a pattern tests on ``subject`` and the names it binds."""

        if isinstance(node, nodes.ValuePattern):
            return nodes.Compare("eq", subject, node.value, node.span), ()
        if isinstance(node, nodes.SingletonPattern):
            return nodes.Compare("is", subject, nodes.Constant(node.value, node.span), node.span), ()
        if isinstance(node, nodes.WildcardPattern):
            return nodes.Constant(True, node.span), ()
        if isinstance(node, nodes.CapturePattern):
            binding = nodes.Assign(nodes.Name(node.name, node.span), subject, node.span)
            if node.pattern is None:
                return nodes.Constant(True, node.span), (binding,)
            condition, inner = self.pattern(node.pattern, subject)
            return condition, (*inner, binding)
        if isinstance(node, nodes.OrPattern):
            conditions: list[nodes.Expression] = []
            bindings: list[nodes.Statement] = []
            for alternative in node.alternatives:
                condition, inner = self.pattern(alternative, subject)
                conditions.append(condition)
                bindings.extend(inner)
            return nodes.BoolOp("or", tuple(conditions), node.span), tuple(bindings)
        if isinstance(node, nodes.SequencePattern):
            return self.sequence_pattern(node, subject)
        if isinstance(node, nodes.MappingPattern):
            return self.mapping_pattern(node, subject)
        if isinstance(node, nodes.ClassPattern):
            return self.class_pattern(node, subject)
        if isinstance(node, nodes.StarPattern):
            raise CFGError(f"{node.span.display()}: a star pattern only belongs in a sequence pattern")
        raise CFGError(f"{node.span.display()}: match pattern {node.kind} is not supported yet")

    def sequence_pattern(
        self, node: nodes.SequencePattern, subject: nodes.Expression
    ) -> tuple[nodes.Expression, tuple[nodes.Statement, ...]]:
        """``[a, 0, *rest, b]``: the length fits, each item matches its sub-pattern and
        the star captures the middle slice."""

        span = node.span
        count = len(node.patterns)
        star = next((i for i, p in enumerate(node.patterns) if isinstance(p, nodes.StarPattern)), None)
        length = nodes.Call(nodes.Name("len", span), (subject,), (), span)
        if star is None:
            conditions: list[nodes.Expression] = [nodes.Compare("eq", length, nodes.Constant(count, span), span)]
        else:
            conditions = [nodes.Compare("gt_eq", length, nodes.Constant(count - 1, span), span)]
        bindings: list[nodes.Statement] = []
        for index, sub in enumerate(node.patterns):
            if isinstance(sub, nodes.StarPattern):
                if sub.name is not None:
                    upper = None if index == count - 1 else nodes.Constant(index - count + 1, span)
                    piece = nodes.Subscript(subject, nodes.Slice(nodes.Constant(index, span), upper, None, span), span)
                    bindings.append(nodes.Assign(nodes.Name(sub.name, sub.span), piece, sub.span))
                continue
            position = index if star is None or index < star else index - count
            item = nodes.Subscript(subject, nodes.Constant(position, span), span)
            condition, inner = self.pattern(sub, item)
            conditions.append(condition)
            bindings.extend(inner)
        return _conjunction(conditions, span), tuple(bindings)

    def mapping_pattern(
        self, node: nodes.MappingPattern, subject: nodes.Expression
    ) -> tuple[nodes.Expression, tuple[nodes.Statement, ...]]:
        """``{key: pattern, **rest}``: every key is present and its value matches."""

        span = node.span
        conditions: list[nodes.Expression] = []
        bindings: list[nodes.Statement] = []
        for key, sub in zip(node.keys, node.patterns, strict=True):
            conditions.append(nodes.Compare("in", key, subject, span))
            condition, inner = self.pattern(sub, nodes.Subscript(subject, key, span))
            conditions.append(condition)
            bindings.extend(inner)
        if node.rest is not None:
            bindings.append(nodes.Assign(nodes.Name(node.rest, span), subject, span))
        return _conjunction(conditions, span), tuple(bindings)

    def class_pattern(
        self, node: nodes.ClassPattern, subject: nodes.Expression
    ) -> tuple[nodes.Expression, tuple[nodes.Statement, ...]]:
        """``Cls(name=pattern)``: an instance of the class whose attributes match."""

        span = node.span
        conditions: list[nodes.Expression] = [
            nodes.Call(nodes.Name("isinstance", span), (subject, node.cls), (), span)
        ]
        bindings: list[nodes.Statement] = []
        # Positional sub-patterns match the attributes ``__match_args__`` names, known
        # for the module's classes; an unknown class gets a conservative position.
        known = self.match_args.get(node.cls.identifier, ()) if isinstance(node.cls, nodes.Name) else ()
        positional = [
            (known[i] if i < len(known) else f"_match_arg_{i}", sub) for i, sub in enumerate(node.patterns)
        ]
        for name, sub in (*positional, *zip(node.keyword_names, node.keyword_patterns, strict=True)):
            condition, inner = self.pattern(sub, nodes.Attribute(subject, name, span))
            conditions.append(condition)
            bindings.extend(inner)
        return _conjunction(conditions, span), tuple(bindings)

    def loop(self, keyword: str, span: SourceSpan) -> tuple[BlockId, BlockId]:
        if not self.loops:
            raise CFGError(f"{span.display()}: '{keyword}' outside loop")
        return self.loops[-1]


def _conjunction(conditions: list[nodes.Expression], span: SourceSpan) -> nodes.Expression:
    return conditions[0] if len(conditions) == 1 else nodes.BoolOp("and", tuple(conditions), span)


def _may_hold_expressions(value: object) -> bool:
    return isinstance(value, tuple) or (is_dataclass(value) and not isinstance(value, type))


def _has_control_flow(node: object) -> bool:
    if isinstance(node, nodes.Conditional | nodes.Comprehension | nodes.NamedExpr):
        return True
    if isinstance(node, nodes.Lambda):
        return False
    if isinstance(node, tuple):
        return any(_has_control_flow(item) for item in node)
    if is_dataclass(node) and not isinstance(node, type):
        return any(_has_control_flow(getattr(node, f.name)) for f in fields(node) if f.name != "span")
    return False


def _bound_names(target: nodes.Target | nodes.Starred) -> list[str]:
    if isinstance(target, nodes.Name):
        return [target.identifier]
    if isinstance(target, nodes.Starred):
        return _bound_names(target.value)  # type: ignore[arg-type]
    if isinstance(target, nodes.Tuple):
        return [name for element in target.elements for name in _bound_names(element)]  # type: ignore[arg-type]
    return []


def _rename(node: Any, renames: dict[str, str]) -> Any:
    """``node`` with comprehension variables replaced by their synthetic locals, without
    entering scopes that rebind them."""

    if not renames:
        return node
    if isinstance(node, nodes.Name):
        return nodes.Name(renames[node.identifier], node.span) if node.identifier in renames else node
    if isinstance(node, nodes.Lambda):
        inner = {k: v for k, v in renames.items() if k not in {p.name for p in node.parameters}}
        return replace(node, body=_rename(node.body, inner))
    if isinstance(node, nodes.Comprehension):
        shadowed = {name for g in node.generators for name in _bound_names(g.target)}
        inner = {k: v for k, v in renames.items() if k not in shadowed}
        generators = tuple(
            replace(
                g,
                iterable=_rename(g.iterable, renames if index == 0 else inner),
                conditions=_rename(g.conditions, inner),
            )
            for index, g in enumerate(node.generators)
        )
        key = _rename(node.key, inner) if node.key is not None else None
        return replace(node, element=_rename(node.element, inner), generators=generators, key=key)
    if isinstance(node, tuple):
        return tuple(_rename(item, renames) for item in node)
    if is_dataclass(node) and not isinstance(node, type):
        changes = {
            f.name: _rename(getattr(node, f.name), renames)
            for f in fields(node)
            if f.name != "span" and _may_hold_expressions(getattr(node, f.name))
        }
        return replace(node, **changes) if changes else node
    return node


def _rename_target(target: nodes.Target, renames: dict[str, str]) -> nodes.Target:
    renamed = _rename(target, renames)
    assert isinstance(renamed, nodes.Name | nodes.Tuple | nodes.Attribute | nodes.Subscript)
    return renamed


def build_cfg(function: nodes.Function, match_args: Mapping[str, tuple[str, ...]] | None = None) -> CFG:
    return _Builder(function, match_args).build()


def match_args_of(module: nodes.Module) -> dict[str, tuple[str, ...]]:
    """``__match_args__`` of the module's classes: explicit, or the field order of a
    dataclass (bare annotated declarations and assignments, in order)."""

    found: dict[str, tuple[str, ...]] = {}
    for statement in module.body:
        if not isinstance(statement, nodes.Class):
            continue
        explicit = None
        fields: list[str] = []
        for member in statement.body:
            if isinstance(member, nodes.Assign) and isinstance(member.target, nodes.Name):
                if member.target.identifier == "__match_args__" and isinstance(member.value, nodes.Tuple | nodes.List):
                    explicit = tuple(
                        e.value for e in member.value.elements if isinstance(e, nodes.Constant) and isinstance(e.value, str)
                    )
                elif not member.target.identifier.startswith("_"):
                    fields.append(member.target.identifier)
            elif isinstance(member, nodes.Declaration):
                fields.append(member.name)
        if explicit is not None:
            found[statement.name] = explicit
        elif any(_is_dataclass(d) for d in statement.decorators):
            found[statement.name] = tuple(fields)
    return found


def _is_dataclass(decorator: nodes.Expression) -> bool:
    if isinstance(decorator, nodes.Call):
        decorator = decorator.callee
    if isinstance(decorator, nodes.Name):
        return decorator.identifier == "dataclass"
    return isinstance(decorator, nodes.Attribute) and decorator.name == "dataclass"


class CFGAnalysis(FunctionAnalysis[CFG]):
    name: ClassVar[str] = "cfg.function"

    @classmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> CFG:
        return build_cfg(function, match_args_of(ctx.module))
