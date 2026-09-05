from __future__ import annotations

import pytest

from coretrace_python.frontend import ParseError, build_hir
from coretrace_python.hir import nodes
from coretrace_python.source import SourceManager


def build(source_text: str) -> nodes.Module:
    source = SourceManager().add_source("example.py", source_text)
    return build_hir(source)


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


def test_frontend_exposes_one_entry_point_returning_pyhir() -> None:
    module = build("def answer():\n    return 42\n")

    assert isinstance(module, nodes.Module)
    assert isinstance(module.body[0], nodes.Function)


def test_frontend_entry_point_reports_syntax_errors_with_location() -> None:
    with pytest.raises(ParseError, match=r"example.py:1:12"):
        build("def broken(:\n")


def test_represents_global_and_nonlocal_declarations() -> None:
    module = build(
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
    module = build("def outer():\n    def inner():\n        pass\n    return inner\n")
    outer = module.body[0]
    assert isinstance(outer, nodes.Function)
    inner = outer.body[0]
    assert isinstance(inner, nodes.Function)
    assert inner.name == "inner"


def test_represents_classes() -> None:
    module = build(
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
    module = build("def squares(items):\n    return [y * y for y in items if y > 0]\n")
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


def test_module_carries_its_dotted_name() -> None:
    source = SourceManager().add_source("db.py", "value = 1\n", module_name="app.services.db")
    assert build_hir(source).name == "app.services.db"


# --------------------------------------------------------------------------- control flow
# PyHIR nodes required by the Phase 3 CFG builder (docs/architecture.md §3.2, §5).
# Expected to remain red until ``If``, ``While``, ``For``, ``Break``, ``Continue`` and
# ``Raise`` exist.


def test_represents_if_with_else_and_elif() -> None:
    module = build("def f(a):\n    if a == 1:\n        return 1\n    elif a == 2:\n        return 2\n    else:\n        return 0\n")
    function = module.body[0]
    assert isinstance(function, nodes.Function)
    outer = function.body[0]
    assert isinstance(outer, nodes.If)
    assert isinstance(outer.condition, nodes.Compare)
    assert isinstance(outer.body[0], nodes.Return)
    inner = outer.orelse[0]
    assert isinstance(inner, nodes.If)
    assert isinstance(inner.orelse[0], nodes.Return)
    assert outer.span.start_line == 2
    assert inner.span.start_line == 4


def test_represents_while_loops_with_break_and_continue() -> None:
    module = build("def f(n):\n    while n:\n        if n:\n            break\n        continue\n")
    function = module.body[0]
    assert isinstance(function, nodes.Function)
    loop = function.body[0]
    assert isinstance(loop, nodes.While)
    assert isinstance(loop.condition, nodes.Name)
    conditional = loop.body[0]
    assert isinstance(conditional, nodes.If)
    assert isinstance(conditional.body[0], nodes.Break)
    assert isinstance(loop.body[1], nodes.Continue)
    assert loop.body[1].span.start_line == 5


def test_represents_for_loops_over_a_name_target() -> None:
    module = build("def f(items):\n    for item in items:\n        pass\n")
    function = module.body[0]
    assert isinstance(function, nodes.Function)
    loop = function.body[0]
    assert isinstance(loop, nodes.For)
    assert isinstance(loop.target, nodes.Name)
    assert loop.target.identifier == "item"
    assert isinstance(loop.iterable, nodes.Name)
    assert isinstance(loop.body[0], nodes.Pass)
    assert loop.is_async is False


def test_represents_raise_with_and_without_exception() -> None:
    module = build("def f(a):\n    raise ValueError(a)\n\ndef g():\n    raise\n")
    first, second = module.body
    assert isinstance(first, nodes.Function) and isinstance(second, nodes.Function)
    raising = first.body[0]
    assert isinstance(raising, nodes.Raise)
    assert isinstance(raising.exception, nodes.Call)
    bare = second.body[0]
    assert isinstance(bare, nodes.Raise)
    assert bare.exception is None


@pytest.mark.parametrize(
    "source_text, message",
    [
        ("async def f(x):\n    return [a async for a in x]\n", "async comprehensions"),
        ("try:\n    pass\nexcept* ValueError:\n    pass\n", "except\\*"),
    ],
    ids=["async-comprehension", "exception-group"],
)
def test_unsupported_control_flow_forms_are_reported(source_text: str, message: str) -> None:
    from coretrace_python.frontend import HIRBuildError

    with pytest.raises(HIRBuildError, match=message):
        build(source_text)
