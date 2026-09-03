"""Generic traversal helpers over PyHIR nodes."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import fields

from coretrace_python.hir import nodes

Node = (
    nodes.Statement
    | nodes.Expression
    | nodes.ComprehensionGenerator
    | nodes.Keyword
    | nodes.WithItem
    | nodes.Parameter
)


def children(node: Node) -> Iterator[Node]:
    """Yield the direct child nodes of ``node`` in source order."""

    for field in fields(node):
        yield from _nodes_in(getattr(node, field.name))


def _nodes_in(value: object) -> Iterator[Node]:
    if _is_node(value):
        yield value  # type: ignore[misc]
    elif isinstance(value, tuple):
        for item in value:
            yield from _nodes_in(item)


def _is_node(value: object) -> bool:
    return hasattr(value, "span") and not isinstance(value, nodes.ImportAlias)
