from __future__ import annotations

import ast

from coretrace_python.frontend.ast_adapter import build_module
from coretrace_python.hir import nodes
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


# --------------------------------------------------------------------------- next milestone
# The tests below describe the frontend entry point and the PyHIR nodes required by
# Phase 2 scope analysis (docs/architecture.md §3.2, §4.1). They are expected to
# remain red until ``coretrace_python.frontend.build_hir`` and the ``Global``,
# ``Nonlocal``, ``Class`` and ``Comprehension`` nodes exist.


def build_via_frontend(source_text: str) -> nodes.Module:
    from coretrace_python.frontend import build_hir

    source = SourceManager().add_source("example.py", source_text)
    return build_hir(source)


def test_frontend_exposes_one_entry_point_returning_pyhir() -> None:
    module = build_via_frontend("def answer():\n    return 42\n")

    assert isinstance(module, nodes.Module)
    assert isinstance(module.body[0], nodes.Function)


def test_frontend_entry_point_reports_syntax_errors_with_location() -> None:
    import pytest

    from coretrace_python.frontend import ParseError

    with pytest.raises(ParseError, match=r"example.py:1:12"):
        build_via_frontend("def broken(:\n")


def test_represents_global_and_nonlocal_declarations() -> None:
    module = build_via_frontend(
        "def outer():\n"
        "    global total\n"
        "    def inner():\n"
        "        nonlocal total, other\n"
    )
    outer = module.body[0]
    assert isinstance(outer, nodes.Function)
    declaration = outer.body[0]
    assert isinstance(declaration, nodes.Global)
    assert declaration.names == ("total",)
    inner = outer.body[1]
    assert isinstance(inner, nodes.Function)
    nested = inner.body[0]
    assert isinstance(nested, nodes.Nonlocal)
    assert nested.names == ("total", "other")
    assert nested.span.start_line == 4
    assert nested.span.start_column == 9


def test_represents_nested_functions() -> None:
    module = build_via_frontend("def outer():\n    def inner():\n        pass\n    return inner\n")
    outer = module.body[0]
    assert isinstance(outer, nodes.Function)
    inner = outer.body[0]
    assert isinstance(inner, nodes.Function)
    assert inner.name == "inner"


def test_represents_classes() -> None:
    module = build_via_frontend(
        "class Config(Base):\n"
        "    debug = True\n"
        "    def read(self):\n"
        "        return self.debug\n"
    )
    config = module.body[0]
    assert isinstance(config, nodes.Class)
    assert config.name == "Config"
    assert len(config.bases) == 1
    assert isinstance(config.bases[0], nodes.Name)
    assert config.bases[0].identifier == "Base"
    assert isinstance(config.body[0], nodes.Assign)
    assert isinstance(config.body[1], nodes.Function)


def test_represents_list_comprehensions() -> None:
    module = build_via_frontend("def squares(items):\n    return [y * y for y in items if y > 0]\n")
    function = module.body[0]
    assert isinstance(function, nodes.Function)
    returned = function.body[0]
    assert isinstance(returned, nodes.Return)
    comprehension = returned.value
    assert isinstance(comprehension, nodes.Comprehension)
    assert comprehension.kind == "list"
    assert isinstance(comprehension.element, nodes.BinaryOp)
    assert len(comprehension.generators) == 1
    generator = comprehension.generators[0]
    assert isinstance(generator.target, nodes.Name)
    assert generator.target.identifier == "y"
    assert isinstance(generator.iterable, nodes.Name)
    assert len(generator.conditions) == 1
    assert isinstance(generator.conditions[0], nodes.Compare)
