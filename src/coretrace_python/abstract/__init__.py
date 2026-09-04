"""Abstract values and the analyses that compute them (architecture §18)."""

from coretrace_python.abstract.constants import (
    ConstantFacts,
    ConstantPropagation,
    propagate_constants,
)
from coretrace_python.abstract.heap import (
    ATTRIBUTES,
    ELEMENTS,
    MUTATORS,
    AbstractObject,
    AliasSet,
    AllocationSite,
    HeapAnalysis,
    HeapFacts,
    HeapLocation,
    analyze_heap,
    mutated_by,
)
from coretrace_python.abstract.ranges import Interval, RangeAnalysis, RangeFacts, analyze_ranges
from coretrace_python.abstract.values import AbstractValue, Truth

__all__ = [
    "ATTRIBUTES",
    "ELEMENTS",
    "MUTATORS",
    "AbstractObject",
    "AbstractValue",
    "AliasSet",
    "AllocationSite",
    "ConstantFacts",
    "ConstantPropagation",
    "HeapAnalysis",
    "HeapFacts",
    "HeapLocation",
    "Interval",
    "RangeAnalysis",
    "RangeFacts",
    "Truth",
    "analyze_heap",
    "analyze_ranges",
    "mutated_by",
    "propagate_constants",
]
