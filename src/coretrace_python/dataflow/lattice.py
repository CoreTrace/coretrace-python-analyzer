"""Lattice vocabulary shared by data-flow problems (architecture §37 dataflow/lattice).

``BOTTOM`` means "no information yet" and ``TOP`` means "anything". A ``FlatLattice``
places every other element between the two: equal elements join to themselves, different
ones to ``TOP``. Elements are compared by type as well as value, so ``1`` and ``True``
are different constants.
"""

from __future__ import annotations

from typing import Final, Generic, Protocol, TypeAlias, TypeVar


class Bottom:
    __slots__ = ()

    def __repr__(self) -> str:
        return "BOTTOM"


class Top:
    __slots__ = ()

    def __repr__(self) -> str:
        return "TOP"


BOTTOM: Final = Bottom()
TOP: Final = Top()

T = TypeVar("T")
Element: TypeAlias = T | Bottom | Top


def same_element(a: object, b: object) -> bool:
    """Equality that also requires equal types, so ``1 == True`` does not conflate."""

    return type(a) is type(b) and bool(a == b)


class Lattice(Protocol[T]):
    @property
    def bottom(self) -> Element[T]: ...

    @property
    def top(self) -> Element[T]: ...

    def join(self, a: Element[T], b: Element[T]) -> Element[T]: ...

    def leq(self, a: Element[T], b: Element[T]) -> bool: ...


class FlatLattice(Generic[T]):
    """Bottom < every element < Top, with no order between elements."""

    @property
    def bottom(self) -> Element[T]:
        return BOTTOM

    @property
    def top(self) -> Element[T]:
        return TOP

    def join(self, a: Element[T], b: Element[T]) -> Element[T]:
        if a is BOTTOM:
            return b
        if b is BOTTOM:
            return a
        if a is TOP or b is TOP:
            return TOP
        return a if same_element(a, b) else TOP

    def leq(self, a: Element[T], b: Element[T]) -> bool:
        if a is BOTTOM or b is TOP:
            return True
        if a is TOP or b is BOTTOM:
            return False
        return same_element(a, b)
