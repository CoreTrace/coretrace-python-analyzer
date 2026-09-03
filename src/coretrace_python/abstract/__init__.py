"""Abstract values and the analyses that compute them (architecture §18)."""

from coretrace_python.abstract.constants import (
    ConstantFacts,
    ConstantPropagation,
    propagate_constants,
)
from coretrace_python.abstract.values import AbstractValue, Truth

__all__ = [
    "AbstractValue",
    "ConstantFacts",
    "ConstantPropagation",
    "Truth",
    "propagate_constants",
]
