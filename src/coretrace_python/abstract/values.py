"""Abstract values (architecture §18).

An ``AbstractValue`` records what is known about one SSA value: its constant on a flat
lattice, the set of Python types it may have (``None`` when unknown) and the truthiness
that follows. Taints, ranges, string constraints and nullability join this record as
their analyses arrive.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from coretrace_python.dataflow import BOTTOM, TOP, Element, FlatLattice

_CONSTANTS: FlatLattice[object] = FlatLattice()


class Truth(Enum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AbstractValue:
    constant: Element[object]
    types: frozenset[str] | None

    @classmethod
    def of(cls, value: object) -> AbstractValue:
        return cls(value, frozenset({type(value).__name__}))

    @classmethod
    def unknown(cls, types: frozenset[str] | None = None) -> AbstractValue:
        return cls(TOP, types)

    @classmethod
    def bottom(cls) -> AbstractValue:
        return cls(BOTTOM, frozenset())

    @property
    def truthiness(self) -> Truth:
        if self.constant is TOP or self.constant is BOTTOM:
            if self.types == frozenset({"NoneType"}):
                return Truth.FALSE
            return Truth.UNKNOWN
        return Truth.TRUE if self.constant else Truth.FALSE

    def join(self, other: AbstractValue) -> AbstractValue:
        if self.constant is BOTTOM:
            return other
        if other.constant is BOTTOM:
            return self
        types = None if self.types is None or other.types is None else self.types | other.types
        return AbstractValue(_CONSTANTS.join(self.constant, other.constant), types)
