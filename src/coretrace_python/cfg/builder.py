"""Build a control-flow graph from a PyHIR function."""

from __future__ import annotations

from typing import ClassVar

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
    def __init__(self, function: nodes.Function) -> None:
        self.function = function
        self.blocks: dict[BlockId, BasicBlock] = {}
        self.counters: dict[str, int] = {}
        self.loops: list[tuple[BlockId, BlockId]] = []
        self.handlers: list[tuple[BlockId, ...]] = []

    def build(self) -> CFG:
        entry = BlockId("entry")
        end = self.sequence(self.function.body, _Open(entry), None, self.function.span)
        if end is not None:
            self.finish(end, Return(None, self.function.span))
        return CFG(entry, self.blocks)

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
        exit_id = continuation if continuation is not None else self.new_id("exit")
        self.finish(block, Jump(header_id, node.span))
        if isinstance(node, nodes.While):
            self.header(header_id, Branch(node.condition, body_id, exit_id, node.span))
        else:
            self.header(header_id, ForEach(node.target, node.iterable, body_id, exit_id, node.span))
        self.loops.append((header_id, exit_id))
        try:
            self.sequence(node.body, _Open(body_id), header_id, node.span)
        finally:
            self.loops.pop()
        return None if continuation is not None else _Open(exit_id)

    def loop(self, keyword: str, span: SourceSpan) -> tuple[BlockId, BlockId]:
        if not self.loops:
            raise CFGError(f"{span.display()}: '{keyword}' outside loop")
        return self.loops[-1]


def build_cfg(function: nodes.Function) -> CFG:
    return _Builder(function).build()


class CFGAnalysis(FunctionAnalysis[CFG]):
    name: ClassVar[str] = "cfg.function"

    @classmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> CFG:
        return build_cfg(function)
