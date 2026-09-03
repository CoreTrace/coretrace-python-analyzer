"""Lower parser-independent PyHIR into analysis-oriented PyIR, one CFG block at a time."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar, NoReturn

from coretrace_python import cfg as control_flow
from coretrace_python.analysis import (
    Analysis,
    AnalysisContext,
    AnalysisManager,
    AnyAnalysis,
    FunctionAnalysis,
)
from coretrace_python.cfg import CFG, BlockId, CFGAnalysis
from coretrace_python.hir import nodes
from coretrace_python.hir.visitors import Node, children
from coretrace_python.ir.model import (
    BasicBlock,
    BinaryOp,
    Branch,
    Call,
    Compare,
    Constant,
    ForNext,
    FunctionIR,
    GetAttr,
    GetItem,
    GetIter,
    Global,
    Instruction,
    Jump,
    LoadLocal,
    ModuleIR,
    Raise,
    Return,
    StoreLocal,
    Symbol,
    Terminator,
    UnaryOp,
    Value,
    ValueInstruction,
)
from coretrace_python.semantic import SEMANTIC_ANALYSES
from coretrace_python.semantic.scopes import (
    Resolution,
    ResolutionKind,
    Scope,
    ScopeAnalysis,
    ScopeTable,
)
from coretrace_python.semantic.symbols import SymbolAnalysis, SymbolId, SymbolTable


class LoweringError(Exception):
    """Raised when PyHIR uses constructs outside the current PyIR subset."""


@dataclass
class _FunctionLowerer:
    symbols: SymbolTable
    scopes: ScopeTable
    scope: Scope
    cfg: CFG
    next_value_id: int = 0
    parameters: dict[str, Value] = field(default_factory=dict)
    instructions: list[Instruction] = field(default_factory=list)
    iterators: dict[BlockId, Value] = field(default_factory=dict)

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
        self.instructions.append(instruction)
        return instruction.result

    def emit_effect(self, instruction: StoreLocal) -> None:
        self.instructions.append(instruction)

    def resolve(self, name: str) -> Resolution:
        return self.scopes.resolve(self.scope.id, name)

    # ------------------------------------------------------------------ expressions

    def imported_symbol(self, node: nodes.Expression) -> SymbolId | None:
        if isinstance(node, nodes.Name):
            return self.symbols.resolve(self.scope.id, node.identifier)
        if isinstance(node, nodes.Attribute):
            parent = self.imported_symbol(node.value)
            return parent.attribute(node.name) if parent is not None else None
        return None

    def expression(self, node: nodes.Expression) -> Value:
        imported_symbol = self.imported_symbol(node)
        if imported_symbol is not None:
            return self.emit(Symbol(self.new_value(), node.span, imported_symbol))
        if isinstance(node, nodes.Name):
            resolution = self.resolve(node.identifier)
            if resolution.kind is ResolutionKind.FREE:
                self.fail(node, "closures are not supported yet")
            if resolution.kind is not ResolutionKind.LOCAL:
                return self.emit(Global(self.new_value(), node.span, node.identifier))
            if node.identifier in self.parameters:
                return self.parameters[node.identifier]
            return self.emit(LoadLocal(self.new_value(), node.span, node.identifier))
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

    # ------------------------------------------------------------------ statements

    def store(self, target: nodes.Name, value: Value) -> None:
        if self.resolve(target.identifier).kind is not ResolutionKind.LOCAL:
            self.fail(target, "assignment to a global or nonlocal name is not supported yet")
        self.emit_effect(StoreLocal(None, target.span, target.identifier, value))

    def statement(self, node: nodes.Statement) -> None:
        if isinstance(node, nodes.Assign):
            self.store(node.target, self.expression(node.value))
            return
        if isinstance(node, nodes.ExpressionStatement):
            self.expression(node.expression)
            return
        if isinstance(node, nodes.Pass | nodes.Global | nodes.Import | nodes.ImportFrom):
            # Declarations and imports are already applied by the semantic analyses.
            return
        self.fail(node)

    # ------------------------------------------------------------------ blocks

    def terminator(self, block: control_flow.BasicBlock) -> Terminator:
        terminator = block.terminator
        if isinstance(terminator, control_flow.Return):
            value = self.expression(terminator.value) if terminator.value is not None else None
            return Return(terminator.span, value)
        if isinstance(terminator, control_flow.Branch):
            condition = self.expression(terminator.condition)
            return Branch(terminator.span, condition, terminator.then_block, terminator.else_block)
        if isinstance(terminator, control_flow.Raise):
            exception = (
                self.expression(terminator.exception) if terminator.exception is not None else None
            )
            return Raise(terminator.span, exception)
        if isinstance(terminator, control_flow.Jump):
            self.enter_loop(block.id, terminator.target)
            return Jump(terminator.span, terminator.target)
        target = terminator.target
        if self.resolve(target.identifier).kind is not ResolutionKind.LOCAL:
            self.fail(target, "assignment to a global or nonlocal name is not supported yet")
        return ForNext(
            terminator.span,
            self.iterators[block.id],
            target.identifier,
            terminator.body,
            terminator.exit,
        )

    def enter_loop(self, source: BlockId, target: BlockId) -> None:
        """Take the iterator of a ``for`` loop in the block that enters its header."""

        header = self.cfg.block(target).terminator
        if isinstance(header, control_flow.ForEach) and (source, target) not in self.cfg.back_edges():
            iterable = self.expression(header.iterable)
            self.iterators[target] = self.emit(GetIter(self.new_value(), header.span, iterable))

    def function(self, node: nodes.Function) -> FunctionIR:
        parameter_values = tuple(self.new_value() for _ in node.parameters)
        reassigned = _reassigned_parameters(node)
        self.parameters = {
            parameter.name: value
            for parameter, value in zip(node.parameters, parameter_values, strict=True)
            if parameter.name not in reassigned
        }
        blocks: list[BasicBlock] = []
        for cfg_block in self.cfg.blocks.values():
            self.instructions = []
            if cfg_block.id == self.cfg.entry:
                # Reassigned parameters live in locals so every block reads the same slot.
                for parameter, value in zip(node.parameters, parameter_values, strict=True):
                    if parameter.name in reassigned:
                        self.emit_effect(StoreLocal(None, parameter.span, parameter.name, value))
            for statement in cfg_block.statements:
                self.statement(statement)
            terminator = self.terminator(cfg_block)
            blocks.append(BasicBlock(cfg_block.id, tuple(self.instructions), terminator))
        return FunctionIR(node.name, parameter_values, self.cfg.entry, tuple(blocks), node.span)


def _reassigned_parameters(function: nodes.Function) -> frozenset[str]:
    """Parameters that the function body assigns to, outside nested scopes."""

    assigned: set[str] = set()

    def walk(node: Node) -> None:
        if isinstance(node, nodes.Assign | nodes.For):
            assigned.add(node.target.identifier)
        if isinstance(node, nodes.Function | nodes.Class | nodes.Comprehension):
            return
        for child in children(node):
            walk(child)

    for statement in function.body:
        walk(statement)
    return frozenset(assigned & {parameter.name for parameter in function.parameters})


class PyIRAnalysis(FunctionAnalysis[FunctionIR]):
    """Lower one function to PyIR on demand, following its control-flow graph."""

    name: ClassVar[str] = "ir.pyir"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset(
        {ScopeAnalysis, SymbolAnalysis, CFGAnalysis}
    )

    @classmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> FunctionIR:
        scopes = ctx.get(ScopeAnalysis)
        lowerer = _FunctionLowerer(
            ctx.get(SymbolAnalysis),
            scopes,
            scopes.scope_for(function),
            ctx.get(CFGAnalysis, function),
        )
        return lowerer.function(function)


class ModuleIRAnalysis(Analysis[ModuleIR]):
    """Assemble the PyIR of every top-level function of the module."""

    name: ClassVar[str] = "ir.module"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({PyIRAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> ModuleIR:
        functions: list[FunctionIR] = []
        for statement in ctx.module.body:
            if isinstance(statement, nodes.Function):
                functions.append(ctx.get(PyIRAnalysis, statement))
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


def lower_module(module: nodes.Module) -> ModuleIR:
    """Lower a whole module through a fresh analysis manager."""

    manager = AnalysisManager(module)
    manager.register(*SEMANTIC_ANALYSES, CFGAnalysis, PyIRAnalysis, ModuleIRAnalysis)
    return manager.get(ModuleIRAnalysis)
