from __future__ import annotations

import ast

from coretrace_python.hir import build_module, nodes
from coretrace_python.source import SourceManager


def build(source_text: str) -> nodes.Module:
    source = SourceManager().add_source("example.py", source_text)
    return build_module(source, ast.parse(source.text, filename=str(source.source_id)))


def test_builds_parser_independent_function_and_expression_nodes() -> None:
    module = build("def add(a, b):\n    return a + b\n")

    function = module.body[0]
    assert isinstance(function, nodes.Function)
    assert tuple(parameter.name for parameter in function.parameters) == ("a", "b")
    returned = function.body[0]
    assert isinstance(returned, nodes.Return)
    assert isinstance(returned.value, nodes.BinaryOp)
    assert returned.value.operator == "add"


def test_preserves_source_spans() -> None:
    module = build("def answer():\n    return 42\n")
    function = module.body[0]
    assert isinstance(function, nodes.Function)
    returned = function.body[0]

    assert returned.span.source_id.value == "example.py"
    assert returned.span.start_line == 2
    assert returned.span.start_column == 5


def test_represents_imports_without_ast_nodes() -> None:
    module = build("from os import system as run\n")
    imported = module.body[0]

    assert isinstance(imported, nodes.ImportFrom)
    assert imported.module == "os"
    assert imported.names == (
        nodes.ImportAlias("system", "run", imported.names[0].span),
    )


def test_represents_calls_attributes_and_subscripts() -> None:
    module = build('def read(request):\n    return request.args["name"]\n')
    function = module.body[0]
    assert isinstance(function, nodes.Function)
    returned = function.body[0]
    assert isinstance(returned, nodes.Return)
    assert isinstance(returned.value, nodes.Subscript)
    assert isinstance(returned.value.value, nodes.Attribute)
