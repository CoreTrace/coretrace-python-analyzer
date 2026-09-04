"""Coarse heap and aliasing abstraction (architecture §22).

SSA names values, not objects. This domain gives every allocation site one
``AbstractObject``: containers and calls at their instruction, parameters, module
globals and imported symbols by name, and the fields loaded from an object by field.
Each value points to an ``AliasSet`` of objects, computed by a flow-insensitive
points-to fixpoint over the SSA form; each object has two ``HeapLocation`` fields,
``elements`` for its items and ``attributes`` for its attributes, field-insensitive
within each. Taint and dependence analyses key their states by these locations, so a
store, a mutating method call or a load on any alias reads and writes the same place.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.analysis import AnalysisContext, AnyAnalysis, FunctionAnalysis
from coretrace_python.hir import nodes
from coretrace_python.ir.model import (
    Await,
    BuildDict,
    BuildList,
    BuildTuple,
    Call,
    Catch,
    ForNext,
    FunctionIR,
    GetAttr,
    GetItem,
    GetIter,
    Global,
    Instruction,
    Phi,
    SetAttr,
    SetItem,
    Symbol,
    Value,
    WithEnter,
    Yield,
)
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.source import SourceSpan

ELEMENTS = "elements"
ATTRIBUTES = "attributes"

# Method names that store their arguments into the receiver's elements.
MUTATORS = frozenset(
    {"append", "appendleft", "extend", "extendleft", "insert", "add", "update", "setdefault", "put"}
)


@dataclass(frozen=True)
class AllocationSite:
    kind: str
    location: SourceSpan
    name: str = ""
    ordinal: int = 0

    def __str__(self) -> str:
        text = f"{self.kind}@{self.location.source_id}:{self.location.start_line}"
        if self.name:
            text += f":{self.name}"
        if self.ordinal:
            text += f"#{self.ordinal}"
        return text


@dataclass(frozen=True)
class AbstractObject:
    site: AllocationSite

    def __str__(self) -> str:
        return str(self.site)


@dataclass(frozen=True)
class HeapLocation:
    object: AbstractObject
    field: str

    def __str__(self) -> str:
        return f"{self.object}.{self.field}"


AliasSet = frozenset[AbstractObject]
NOTHING: AliasSet = frozenset()


class HeapFacts:
    def __init__(self, objects: Mapping[Value, AliasSet]) -> None:
        self._objects: Mapping[Value, AliasSet] = MappingProxyType(dict(objects))
        self.values = tuple(objects)

    def objects(self, value: Value) -> AliasSet:
        return self._objects.get(value, NOTHING)

    def locations(self, value: Value, field: str) -> tuple[HeapLocation, ...]:
        return tuple(HeapLocation(o, field) for o in sorted(self.objects(value), key=str))


def mutated_by(call: Call, defs: Mapping[Value, Instruction]) -> Value | None:
    """The receiver of a call to a mutating method (``xs.append(v)``), if any."""

    callee = defs.get(call.callee)
    if isinstance(callee, GetAttr) and callee.attribute in MUTATORS:
        return callee.object
    return None


class _PointsTo:
    def __init__(self, function: FunctionIR) -> None:
        self.function = function
        self.defs: dict[Value, Instruction] = {
            i.result: i for block in function.blocks for i in block.instructions if i.result
        }
        self.points: dict[Value, set[AbstractObject]] = {}
        self.heap: dict[HeapLocation, set[AbstractObject]] = {}
        self.named: dict[tuple[str, str], AbstractObject] = {}
        for index, parameter in enumerate(function.parameters):
            self.points[parameter] = {
                AbstractObject(AllocationSite("parameter", function.location, ordinal=index))
            }

    def named_object(self, kind: str, name: str) -> AbstractObject:
        key = (kind, name)
        if key not in self.named:
            self.named[key] = AbstractObject(AllocationSite(kind, self.function.location, name))
        return self.named[key]

    @staticmethod
    def field_object(owner: AbstractObject, field: str) -> AbstractObject:
        # A field of a field collapses onto itself, so chains such as ``node.next``
        # in a loop stay finite.
        if owner.site.kind == "field":
            return owner
        return AbstractObject(AllocationSite("field", owner.site.location, f"{owner.site}.{field}"))

    def of(self, value: Value) -> set[AbstractObject]:
        return self.points.setdefault(value, set())

    def at(self, objects: set[AbstractObject], field: str) -> set[AbstractObject]:
        found: set[AbstractObject] = set()
        for owner in objects:
            found |= self.heap.setdefault(HeapLocation(owner, field), set())
            found.add(self.field_object(owner, field))
        return found

    def store(self, objects: set[AbstractObject], field: str, value: Value) -> bool:
        changed = False
        for owner in objects:
            location = self.heap.setdefault(HeapLocation(owner, field), set())
            before = len(location)
            location |= self.of(value)
            changed |= len(location) != before
        return changed

    def solve(self) -> None:
        changed = True
        while changed:
            changed = False
            for block in self.function.blocks:
                for instruction in block.instructions:
                    changed |= self.instruction(instruction)
                terminator = block.terminator
                if isinstance(terminator, ForNext) and terminator.result is not None:
                    changed |= self.assign(terminator.result, self.at(self.of(terminator.iterator), ELEMENTS))

    def assign(self, value: Value, objects: set[AbstractObject]) -> bool:
        current = self.of(value)
        before = len(current)
        current |= objects
        return len(current) != before

    def instruction(self, instruction: Instruction) -> bool:
        if isinstance(instruction, SetAttr):
            return self.store(self.of(instruction.object), ATTRIBUTES, instruction.value)
        if isinstance(instruction, SetItem):
            return self.store(self.of(instruction.object), ELEMENTS, instruction.value)
        result = instruction.result
        if result is None:
            return False
        if isinstance(instruction, BuildList | BuildTuple | BuildDict | Call | WithEnter | Catch | Yield):
            kind = {
                BuildList: "list",
                BuildTuple: "tuple",
                BuildDict: "dict",
                Call: "call",
                WithEnter: "context",
                Catch: "exception",
                Yield: "sent",
            }[type(instruction)]
            site = AbstractObject(AllocationSite(kind, instruction.location))
            changed = self.assign(result, {site})
            if isinstance(instruction, BuildList | BuildTuple):
                for element in instruction.elements:
                    changed |= self.store({site}, ELEMENTS, element)
            elif isinstance(instruction, BuildDict):
                for _, value in instruction.items:
                    changed |= self.store({site}, ELEMENTS, value)
            elif isinstance(instruction, Call):
                receiver = mutated_by(instruction, self.defs)
                if receiver is not None:
                    for argument in instruction.argument_values():
                        changed |= self.store(self.of(receiver), ELEMENTS, argument)
            return changed
        if isinstance(instruction, Global):
            return self.assign(result, {self.named_object("global", instruction.name)})
        if isinstance(instruction, Symbol):
            return self.assign(result, {self.named_object("symbol", instruction.symbol_id.canonical_name)})
        if isinstance(instruction, Phi):
            objects: set[AbstractObject] = set()
            for value, _ in instruction.incoming:
                objects |= self.of(value)
            return self.assign(result, objects)
        if isinstance(instruction, GetAttr):
            return self.assign(result, self.at(self.of(instruction.object), ATTRIBUTES))
        if isinstance(instruction, GetItem):
            return self.assign(result, self.at(self.of(instruction.object), ELEMENTS))
        if isinstance(instruction, GetIter):
            return self.assign(result, self.of(instruction.iterable))
        if isinstance(instruction, Await):
            return self.assign(result, self.of(instruction.value))
        return False


def analyze_heap(function: FunctionIR) -> HeapFacts:
    solver = _PointsTo(function)
    solver.solve()
    return HeapFacts({value: frozenset(objects) for value, objects in solver.points.items() if objects})


class HeapAnalysis(FunctionAnalysis[HeapFacts]):
    name: ClassVar[str] = "abstract.heap"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({SSAAnalysis})

    @classmethod
    def compute(cls, ctx: AnalysisContext, function: nodes.Function) -> HeapFacts:
        return analyze_heap(ctx.get(SSAAnalysis, function))
