"""Generic traversal helpers over PyHIR nodes."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import fields

from coretrace_python.hir import nodes

Node = nodes.Statement | nodes.Expression | nodes.ComprehensionGenerator | nodes.Keyword


def children(node: Node) -> Iterator[Node]:
    """Yield the direct child nodes of ``node`` in source order."""

    for field in fields(node):
        value = getattr(node, field.name)
        if _is_node(value):
            yield value
        elif isinstance(value, tuple):
            for item in value:
                if _is_node(item):
                    yield item


def _is_node(value: object) -> bool:
    return hasattr(value, "span") and not isinstance(value, nodes.Parameter | nodes.ImportAlias)
