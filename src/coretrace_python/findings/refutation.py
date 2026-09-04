"""Proof / refutation engine (architecture §24).

Every taint flow gets a verdict. Walking the dominators of the sink block, each branch
whose one side alone reaches the sink fixes the truth of its condition there; the
condition is then interpreted: string validators (``isdigit()`` and friends), membership
in a constant allowlist and equality with a constant prove a value safe, ``and`` / ``or``
and ``not`` combine as expected, a ``Validator`` model names a callable whose truth proves
one of its arguments, a numeric value (``abstract.ranges``) cannot inject, and anything
else that mentions the value is a guard that does not prove it. A proof counts for an
origin when every dependence path from that origin to the sink argument goes through a
proven value. A flow is refuted when every tainted origin is proven safe or the sink is
unreachable, a hotspot when it sits behind an ``AuthorizationGuard`` (a decorator or a
dominating condition) or when an unproven guard mentions it, and a vulnerability
otherwise.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.abstract import ConstantPropagation, RangeAnalysis, RangeFacts
from coretrace_python.analysis import AnalysisContext, AnyAnalysis, FunctionAnalysis
from coretrace_python.cfg import CFG, BlockId, CFGAnalysis, DominanceAnalysis, DominatorTree
from coretrace_python.hir import nodes
from coretrace_python.interprocedural import CallGraphAnalysis
from coretrace_python.ir.model import (
    BoolOp,
    Branch,
    BuildList,
    BuildTuple,
    Call,
    Compare,
    Constant,
    FunctionIR,
    GetAttr,
    Instruction,
    UnaryOp,
    Value,
)
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.semantic.scopes import ScopeAnalysis, ScopeTable
from coretrace_python.semantic.symbols import SymbolAnalysis, SymbolId, SymbolTable
from coretrace_python.taint import (
    AuthorizationGuard,
    ModelTable,
    SecurityModelAnalysis,
    TaintAnalysis,
    TaintFacts,
    TaintFlow,
)

VALIDATORS = frozenset(
    {"isdigit", "isnumeric", "isdecimal", "isalnum", "isalpha", "isidentifier", "isascii"}
)


class Status(Enum):
    VULNERABILITY = "vulnerability"
    HOTSPOT = "hotspot"
    REFUTED = "refuted"


@dataclass(frozen=True)
class Verdict:
    flow: TaintFlow
    status: Status
    evidence: str


class Verdicts:
    def __init__(self, verdicts: tuple[Verdict, ...]) -> None:
        self._all = verdicts
        self._by_flow: Mapping[TaintFlow, Verdict] = MappingProxyType(
            {verdict.flow: verdict for verdict in verdicts}
        )

    def all(self) -> tuple[Verdict, ...]:
        return self._all

    def verdict(self, flow: TaintFlow) -> Verdict:
        return self._by_flow[flow]


@dataclass(frozen=True)
class _Guard:
    """A dominating branch condition with its truth at the sink."""

    condition: Value
    truth: bool
    line: int


class _Judge:
    def __init__(
        self,
        function: FunctionIR,
        cfg: CFG,
        tree: DominatorTree,
        taint: TaintFacts,
        ranges: RangeFacts | None = None,
        models: ModelTable | None = None,
        symbols: Mapping[Value, SymbolId] | None = None,
        authorization: AuthorizationGuard | None = None,
    ) -> None:
        self.function = function
        self.cfg = cfg
        self.tree = tree
        self.taint = taint
        self.ranges = ranges or RangeFacts({})
        self.models = models or ModelTable((), (), ())
        self.symbols = symbols or {}
        self.authorization = authorization
        self.blocks = {block.id: block for block in function.blocks}
        self.defs: dict[Value, Instruction] = {
            i.result: i for block in function.blocks for i in block.instructions if i.result
        }
        self._closures: dict[Value, frozenset[Value]] = {}

    # ------------------------------------------------------------------ dependencies

    def closure(self, value: Value) -> frozenset[Value]:
        """Every value ``value`` transitively depends on, excluding itself."""

        if value in self._closures:
            return self._closures[value]
        found: set[Value] = set()
        pending = [value]
        while pending:
            definition = self.defs.get(pending.pop())
            if definition is None:
                continue
            for operand in definition.operands():
                if operand not in found:
                    found.add(operand)
                    pending.append(operand)
        self._closures[value] = frozenset(found)
        return self._closures[value]

    def origins(self, value: Value) -> frozenset[Value]:
        """Tainted values the argument depends on whose own operands are untainted."""

        candidates = self.closure(value) | {value}
        return frozenset(
            v
            for v in candidates
            if self.taint.taint(v)
            and not any(self.taint.taint(o) for o in self.closure(v))
        )

    def covered(self, origin: Value, argument: Value, proven: Mapping[Value, str]) -> bool:
        """Whether every dependence path from ``origin`` to ``argument`` goes through a
        proven value, so nothing of the origin reaches the sink unproven."""

        if origin in proven:
            return True
        seen: set[Value] = set()
        pending = [argument]
        while pending:
            value = pending.pop()
            if value in proven or value in seen:
                continue
            if value == origin:
                return False
            seen.add(value)
            definition = self.defs.get(value)
            if definition is not None:
                pending.extend(definition.operands())
        return True

    # ------------------------------------------------------------------ guards

    def sink_block(self, flow: TaintFlow) -> BlockId | None:
        for block in self.function.blocks:
            for instruction in block.instructions:
                if isinstance(instruction, Call) and instruction.location == flow.location:
                    return block.id
        return None

    def reaches(self, start: BlockId, target: BlockId, avoiding: BlockId) -> bool:
        seen: set[BlockId] = set()
        pending = [start]
        while pending:
            block = pending.pop()
            if block == target:
                return True
            if block in seen or block == avoiding:
                continue
            seen.add(block)
            pending.extend(self.cfg.successors(block))
        return False

    def guards(self, sink: BlockId) -> list[_Guard]:
        found: list[_Guard] = []
        dominator = self.tree.idom(sink)
        while dominator is not None:
            terminator = self.blocks[dominator].terminator
            if isinstance(terminator, Branch):
                then_reaches = self.reaches(terminator.then_block, sink, dominator)
                else_reaches = self.reaches(terminator.else_block, sink, dominator)
                if then_reaches != else_reaches:
                    found.append(
                        _Guard(terminator.condition, then_reaches, terminator.location.start_line)
                    )
            dominator = self.tree.idom(dominator)
        return found

    def interpret(
        self, condition: Value, truth: bool | None
    ) -> tuple[dict[Value, str], set[Value]]:
        """Values the condition proves safe (with the reason), and values it mentions
        without proving anything. ``truth`` is ``None`` when it is not fixed at the sink.

        A recognised check evaluated the wrong way (``isdigit()`` known false) yields
        nothing: it is neither a proof nor a reassuring guard."""

        definition = self.defs.get(condition)
        proven: dict[Value, str] = {}
        mentioned: set[Value] = set()
        if isinstance(definition, UnaryOp) and definition.operator == "not":
            return self.interpret(definition.operand, None if truth is None else not truth)
        if isinstance(definition, BoolOp):
            fixed = truth is not None and (definition.operator == "and") == truth
            for value in definition.values:
                found, seen = self.interpret(value, truth if fixed else None)
                proven.update(found)
                mentioned |= seen
            return proven, mentioned
        recognised = self.recognise(definition)
        if recognised is None:
            return proven, set(self.closure(condition)) | {condition}
        tested, reason, when_true = recognised
        if truth is None:
            mentioned = set(self.closure(condition)) | {condition}
        elif truth == when_true:
            # The check proves ``tested``; whatever else it reads is merely mentioned.
            proven[tested] = reason
            mentioned = set(self.closure(condition)) | {condition}
        return proven, mentioned

    def recognise(self, definition: Instruction | None) -> tuple[Value, str, bool] | None:
        """``(validated value, reason, truth that validates)`` for known check shapes."""

        if isinstance(definition, Call) and not definition.arguments:
            callee = self.defs.get(definition.callee)
            if isinstance(callee, GetAttr) and callee.attribute in VALIDATORS:
                return callee.object, f"guarded by {callee.attribute}()", True
        if isinstance(definition, Call):
            symbol = self.symbols.get(definition.callee)
            validator = self.models.validator(symbol) if symbol is not None else None
            if validator is not None and validator.argument < len(definition.arguments):
                return definition.arguments[validator.argument], f"validated by {symbol}", True
        if isinstance(definition, Compare):
            left, right = definition.left, definition.right
            if definition.operator in ("in", "not_in") and self.is_constant_collection(right):
                return (
                    left,
                    "allowlisted by a membership check on constants",
                    definition.operator == "in",
                )
            if definition.operator in ("eq", "not_eq"):
                for tested, other in ((left, right), (right, left)):
                    if isinstance(self.defs.get(other), Constant):
                        return tested, "equals a constant", definition.operator == "eq"
        return None

    def is_constant_collection(self, value: Value) -> bool:
        definition = self.defs.get(value)
        if isinstance(definition, Constant):
            return isinstance(definition.value, str | bytes)
        if isinstance(definition, BuildList | BuildTuple):
            return all(isinstance(self.defs.get(e), Constant) for e in definition.elements)
        return False

    # ------------------------------------------------------------------ authorization

    def authorized_by(self, condition: Value, truth: bool) -> AuthorizationGuard | None:
        """The authorization guard this condition enforces when it is ``truth``."""

        definition = self.defs.get(condition)
        if isinstance(definition, UnaryOp) and definition.operator == "not":
            return self.authorized_by(definition.operand, not truth)
        if isinstance(definition, BoolOp) and (definition.operator == "and") == truth:
            for value in definition.values:
                found = self.authorized_by(value, truth)
                if found is not None:
                    return found
            return None
        if not truth:
            return None
        symbol = self.symbols.get(condition)
        if symbol is None and isinstance(definition, Call):
            symbol = self.symbols.get(definition.callee)
        return self.models.authorization(symbol) if symbol is not None else None

    # ------------------------------------------------------------------ verdicts

    def judge(self, flow: TaintFlow, reachable: bool) -> Verdict:
        sink = self.sink_block(flow)
        if sink is None or not reachable:
            return Verdict(flow, Status.REFUTED, "sink unreachable by constant propagation")
        origins = self.origins(flow.argument)
        chain = self.closure(flow.argument) | {flow.argument}
        proven: dict[Value, str] = {
            value: f"numeric value within {interval}"
            for value, interval in self.ranges.at(sink).items()
            if value in chain
        }
        mentions: dict[Value, int] = {}
        authorization: str | None = (
            f"behind authorization ({self.authorization.label}) by decorator"
            if self.authorization is not None
            else None
        )
        for guard in self.guards(sink):
            found, mentioned = self.interpret(guard.condition, guard.truth)
            for value, reason in found.items():
                if value in chain:
                    proven.setdefault(value, reason)
            for origin in origins:
                if origin not in mentions and mentioned & (
                    {origin} | {w for w in chain if origin in self.closure(w)}
                ):
                    mentions[origin] = guard.line
            if authorization is None:
                guard_model = self.authorized_by(guard.condition, guard.truth)
                if guard_model is not None:
                    authorization = f"behind authorization ({guard_model.label}) at line {guard.line}"
        proofs = {
            origin: sorted(
                {reason for value, reason in proven.items() if value == origin or origin in self.closure(value)}
            )
            for origin in origins
            if self.covered(origin, flow.argument, proven)
        }
        if origins and all(origin in proofs for origin in origins):
            reasons = sorted({reason for found in proofs.values() for reason in found})
            return Verdict(flow, Status.REFUTED, "; ".join(reasons))
        if authorization is not None:
            return Verdict(flow, Status.HOTSPOT, authorization)
        unguarded = [origin for origin in origins if origin not in proofs and origin not in mentions]
        if not origins or unguarded:
            return Verdict(flow, Status.VULNERABILITY, "no guard on the path to the sink")
        line = min(mentions.values())
        return Verdict(
            flow, Status.HOTSPOT, f"guard at line {line} does not prove the value safe"
        )


def judge_flows(
    function: FunctionIR,
    cfg: CFG,
    tree: DominatorTree,
    taint: TaintFacts,
    reachable: frozenset[BlockId],
    ranges: RangeFacts | None = None,
    models: ModelTable | None = None,
    symbols: Mapping[Value, SymbolId] | None = None,
    authorization: AuthorizationGuard | None = None,
) -> Verdicts:
    judge = _Judge(function, cfg, tree, taint, ranges, models, symbols, authorization)
    verdicts = []
    for flow in taint.flows:
        sink = judge.sink_block(flow)
        verdicts.append(judge.judge(flow, sink is not None and sink in reachable))
    return Verdicts(tuple(verdicts))


def authorization_of(
    function: nodes.Function, models: ModelTable, scopes: ScopeTable, symbols: SymbolTable
) -> AuthorizationGuard | None:
    """The authorization guard among the function's decorators, if any."""

    scope = scopes.scope_for(function)
    enclosing = scope.parent if scope.parent is not None else scope.id
    for decorator in function.decorators:
        symbol = symbols.resolve_expression(enclosing, decorator)
        guard = models.authorization(symbol) if symbol is not None else None
        if guard is not None:
            return guard
    return None


class RefutationAnalysis(FunctionAnalysis[Verdicts]):
    name: ClassVar[str] = "findings.refutation"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset(
        {
            TaintAnalysis,
            DominanceAnalysis,
            ConstantPropagation,
            RangeAnalysis,
            SSAAnalysis,
            CFGAnalysis,
            SecurityModelAnalysis,
            CallGraphAnalysis,
            ScopeAnalysis,
            SymbolAnalysis,
        }
    )

    @classmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> Verdicts:
        ssa = ctx.get(SSAAnalysis, function)
        constants = ctx.get(ConstantPropagation, function)
        graph = ctx.get(CallGraphAnalysis)
        models = ctx.get(SecurityModelAnalysis)
        return judge_flows(
            ssa,
            ctx.get(CFGAnalysis, function),
            ctx.get(DominanceAnalysis, function),
            ctx.get(TaintAnalysis, function),
            frozenset(b.id for b in ssa.blocks if constants.reachable(b.id)),
            ctx.get(RangeAnalysis, function),
            models,
            graph.symbols(graph.name_of(function)),
            authorization_of(function, models, ctx.get(ScopeAnalysis), ctx.get(SymbolAnalysis)),
        )

