"""Proof / refutation engine (architecture §24).

Every taint flow gets a verdict. Walking the dominators of the sink block, each branch
whose one side alone reaches the sink fixes the truth of its condition there; the
condition is then interpreted: string validators (``isdigit()`` and friends), membership
in a constant allowlist and equality with a constant prove a value safe, ``and`` / ``or``
and ``not`` combine as expected, and anything else that mentions the value is a guard
that does not prove it. A flow is refuted when every tainted origin of the argument is
proven safe or the sink is unreachable, a hotspot when an unproven guard mentions it, and
a vulnerability otherwise.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.abstract import ConstantPropagation
from coretrace_python.analysis import AnalysisContext, AnyAnalysis, FunctionAnalysis
from coretrace_python.cfg import CFG, BlockId, CFGAnalysis, DominanceAnalysis, DominatorTree
from coretrace_python.hir import nodes
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
from coretrace_python.taint import TaintAnalysis, TaintFacts, TaintFlow

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
        self, function: FunctionIR, cfg: CFG, tree: DominatorTree, taint: TaintFacts
    ) -> None:
        self.function = function
        self.cfg = cfg
        self.tree = tree
        self.taint = taint
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
            proven[tested] = reason
        return proven, mentioned

    def recognise(self, definition: Instruction | None) -> tuple[Value, str, bool] | None:
        """``(validated value, reason, truth that validates)`` for known check shapes."""

        if isinstance(definition, Call) and not definition.arguments:
            callee = self.defs.get(definition.callee)
            if isinstance(callee, GetAttr) and callee.attribute in VALIDATORS:
                return callee.object, f"guarded by {callee.attribute}()", True
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

    # ------------------------------------------------------------------ verdicts

    def judge(self, flow: TaintFlow, reachable: bool) -> Verdict:
        sink = self.sink_block(flow)
        if sink is None or not reachable:
            return Verdict(flow, Status.REFUTED, "sink unreachable by constant propagation")
        origins = self.origins(flow.argument)
        chains = {
            origin: frozenset(
                w for w in self.closure(flow.argument) | {flow.argument}
                if w == origin or origin in self.closure(w)
            )
            for origin in origins
        }
        proofs: dict[Value, str] = {}
        mentions: dict[Value, int] = {}
        for guard in self.guards(sink):
            proven, mentioned = self.interpret(guard.condition, guard.truth)
            for origin, chain in chains.items():
                for value, reason in proven.items():
                    if value in chain:
                        proofs.setdefault(origin, reason)
                if origin not in mentions and mentioned & chain:
                    mentions[origin] = guard.line
        if origins and all(origin in proofs for origin in origins):
            return Verdict(flow, Status.REFUTED, "; ".join(sorted(set(proofs.values()))))
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
) -> Verdicts:
    judge = _Judge(function, cfg, tree, taint)
    verdicts = []
    for flow in taint.flows:
        sink = judge.sink_block(flow)
        verdicts.append(judge.judge(flow, sink is not None and sink in reachable))
    return Verdicts(tuple(verdicts))


class RefutationAnalysis(FunctionAnalysis[Verdicts]):
    name: ClassVar[str] = "findings.refutation"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset(
        {TaintAnalysis, DominanceAnalysis, ConstantPropagation, SSAAnalysis, CFGAnalysis}
    )

    @classmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> Verdicts:
        ssa = ctx.get(SSAAnalysis, function)
        constants = ctx.get(ConstantPropagation, function)
        return judge_flows(
            ssa,
            ctx.get(CFGAnalysis, function),
            ctx.get(DominanceAnalysis, function),
            ctx.get(TaintAnalysis, function),
            frozenset(b.id for b in ssa.blocks if constants.reachable(b.id)),
        )

