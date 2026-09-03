"""Acceptance tests widening the PyHIR node set and the PyIR instruction set.

``docs/architecture.md`` §3.2 PyHIR, §6 PyIR. Everyday syntax must reach the IR: keyword
arguments, parameter defaults and kinds, decorators, augmented assignment, attribute and
item stores, tuple unpacking, list/tuple/dict literals, ``and``/``or``, chained
comparisons, ``with``, ``assert``, module-level statements and methods of module-level
classes. A function that still uses unsupported syntax must not abort ``--check``: it is
reported as an ``unsupported-syntax`` note and the other functions are analysed.

Expected to remain red until the nodes, instructions and tolerant check exist.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.cli import main
from coretrace_python.findings import Severity
from coretrace_python.frontend import HIRBuildError, build_hir
from coretrace_python.hir import nodes
from coretrace_python.semantic.scopes import ResolutionKind, analyze_scopes
from coretrace_python.source import SourceManager

REPO = Path(__file__).resolve().parent.parent
PLUGINS = REPO / "plugins"


def build(source_text: str) -> nodes.Module:
    return build_hir(SourceManager().add_source("cover.py", source_text))


def emit(source_text: str, tmp_path: Path, capsys, *flags: str) -> str:  # type: ignore[no-untyped-def]
    path = tmp_path / "cover.py"
    path.write_text(source_text, encoding="utf-8")
    assert main(["--emit-ir", *flags, str(path)]) == 0, capsys.readouterr().err
    return str(capsys.readouterr().out)


# --------------------------------------------------------------------------- PyHIR nodes


def test_parameters_carry_defaults_and_kinds() -> None:
    module = build("def f(a, b=1, *args, c, d=2, **kwargs):\n    pass\n")
    function = module.body[0]
    assert isinstance(function, nodes.Function)

    assert [(p.name, p.kind) for p in function.parameters] == [
        ("a", "positional"),
        ("b", "positional"),
        ("args", "var_positional"),
        ("c", "keyword"),
        ("d", "keyword"),
        ("kwargs", "var_keyword"),
    ]
    assert function.parameters[0].default is None
    assert isinstance(function.parameters[1].default, nodes.Constant)
    assert isinstance(function.parameters[4].default, nodes.Constant)


def test_decorators_are_kept_on_functions_and_classes() -> None:
    module = build("@app.route('/')\ndef index():\n    pass\n\n@dataclass\nclass C:\n    pass\n")
    function, klass = module.body
    assert isinstance(function, nodes.Function) and isinstance(klass, nodes.Class)
    assert len(function.decorators) == 1
    assert isinstance(function.decorators[0], nodes.Call)
    assert isinstance(klass.decorators[0], nodes.Name)


def test_augmented_assignment_and_store_targets() -> None:
    module = build("def f(o, d, k):\n    o.n += 1\n    d[k] = o\n    a, (b, c) = o\n")
    function = module.body[0]
    assert isinstance(function, nodes.Function)
    aug, item, unpack = function.body
    assert isinstance(aug, nodes.AugAssign)
    assert aug.operator == "add"
    assert isinstance(aug.target, nodes.Attribute)
    assert isinstance(item, nodes.Assign) and isinstance(item.target, nodes.Subscript)
    assert isinstance(unpack, nodes.Assign) and isinstance(unpack.target, nodes.Tuple)
    assert isinstance(unpack.target.elements[1], nodes.Tuple)


def test_literals_boolean_operators_and_chained_comparisons() -> None:
    module = build("def f(a, b, c):\n    return [a], (a, b), {a: b}, a and b or c, a < b <= c\n")
    function = module.body[0]
    assert isinstance(function, nodes.Function)
    returned = function.body[0]
    assert isinstance(returned, nodes.Return) and isinstance(returned.value, nodes.Tuple)
    lst, tup, dct, boolean, chain = returned.value.elements
    assert isinstance(lst, nodes.List) and isinstance(tup, nodes.Tuple) and isinstance(dct, nodes.Dict)
    assert dct.items[0][1].identifier == "b"  # type: ignore[union-attr]
    assert isinstance(boolean, nodes.BoolOp) and boolean.operator == "or"
    assert isinstance(boolean.values[0], nodes.BoolOp) and boolean.values[0].operator == "and"
    assert isinstance(chain, nodes.BoolOp) and chain.operator == "and"
    assert [c.operator for c in chain.values] == ["lt", "lt_eq"]  # type: ignore[union-attr]


def test_with_and_assert_statements() -> None:
    module = build("def f(p):\n    with open(p) as fh, lock:\n        assert fh, 'open'\n")
    function = module.body[0]
    assert isinstance(function, nodes.Function)
    with_statement = function.body[0]
    assert isinstance(with_statement, nodes.With)
    first, second = with_statement.items
    assert isinstance(first.context, nodes.Call) and first.target is not None
    assert first.target.identifier == "fh"
    assert second.target is None
    assertion = with_statement.body[0]
    assert isinstance(assertion, nodes.Assert)
    assert isinstance(assertion.message, nodes.Constant)


def test_keyword_arguments_including_unpacking() -> None:
    module = build("def f(g, k):\n    g(1, key=2, **k)\n")
    function = module.body[0]
    assert isinstance(function, nodes.Function)
    call = function.body[0]
    assert isinstance(call, nodes.ExpressionStatement) and isinstance(call.expression, nodes.Call)
    assert [k.name for k in call.expression.keywords] == ["key", None]


def test_star_arguments_are_still_rejected_explicitly() -> None:
    with pytest.raises(HIRBuildError, match="star arguments"):
        build("def f(g, a):\n    g(*a)\n")


def test_pyhir_declares_a_schema_version() -> None:
    from coretrace_python.hir import HIR_SCHEMA_VERSION

    assert HIR_SCHEMA_VERSION >= 1


# --------------------------------------------------------------------------- scopes


def test_defaults_and_decorators_resolve_in_the_enclosing_scope() -> None:
    module = build("LIMIT = 1\n\n@register\ndef f(a, b=LIMIT):\n    return b\n")
    scopes = analyze_scopes(module)
    f = next(s for s in scopes.children(scopes.module_scope.id) if s.name == "f")

    assert "LIMIT" not in f.bindings
    assert f.bindings["b"].kind.name == "PARAMETER"
    assert scopes.resolve(scopes.module_scope.id, "LIMIT").kind is ResolutionKind.GLOBAL


def test_with_targets_and_unpacked_names_are_locals() -> None:
    module = build("def f(x):\n    with x as y:\n        a, b = y\n    return a\n")
    scopes = analyze_scopes(module)
    f = next(s for s in scopes.children(scopes.module_scope.id) if s.name == "f")

    assert {name for name in ("y", "a", "b")} <= set(f.bindings)


# --------------------------------------------------------------------------- PyIR


def test_emit_ir_keyword_arguments(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    output = emit("def f(g, a, k):\n    g(a, key=1, **k)\n", tmp_path, capsys)
    assert "    %3 = const 1\n    %4 = call %0(%1, key=%3, **%2)\n" in output


def test_emit_ir_augmented_and_indexed_stores(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    output = emit("def f(o, d, k):\n    o.n += 1\n    d[k] = o\n", tmp_path, capsys)
    assert output == (
        "func @f(%0, %1, %2) {\n"
        "entry:\n"
        "    %3 = get_attr %0, 'n'\n"
        "    %4 = const 1\n"
        "    %5 = binary.add %3, %4\n"
        "    set_attr %0, 'n', %5\n"
        "    set_item %1, %2, %0\n"
        "    return\n"
        "}\n"
    )


def test_emit_ir_unpacking_and_literals(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    output = emit("def f(x):\n    a, b = x\n    return [a, b], (a,), {a: b}\n", tmp_path, capsys)
    assert "    %1 = const 0\n    %2 = get_item %0, %1\n    store_local \"a\", %2\n" in output
    assert "    %3 = const 1\n    %4 = get_item %0, %3\n    store_local \"b\", %4\n" in output
    assert "build_list %5, %6\n" in output
    assert "build_tuple %8\n" in output
    assert "build_dict %10: %11\n" in output
    assert output.rstrip().endswith("    return %13\n}")


def test_emit_ir_boolean_operators_and_chains(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    output = emit("def f(a, b, c):\n    return a < b < c and a\n", tmp_path, capsys)
    assert output == (
        "func @f(%0, %1, %2) {\n"
        "entry:\n"
        "    %3 = compare.lt %0, %1\n"
        "    %4 = compare.lt %1, %2\n"
        "    %5 = bool_op.and %3, %4\n"
        "    %6 = bool_op.and %5, %0\n"
        "    return %6\n"
        "}\n"
    )


def test_emit_ir_with_statement(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    output = emit(
        "def f(p):\n    with open(p) as fh:\n        data = fh.read()\n    return data\n", tmp_path, capsys
    )
    assert output == (
        "func @f(%0) {\n"
        "entry:\n"
        "    %1 = symbol @python.builtins.open\n"
        "    %2 = call %1(%0)\n"
        "    %3 = with_enter %2\n"
        '    store_local "fh", %3\n'
        '    %4 = load_local "fh"\n'
        "    %5 = get_attr %4, 'read'\n"
        "    %6 = call %5()\n"
        '    store_local "data", %6\n'
        "    with_exit %2\n"
        '    %7 = load_local "data"\n'
        "    return %7\n"
        "}\n"
    )


def test_emit_ir_early_return_inside_with(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    output = emit("def f(x):\n    with x:\n        if x:\n            return 1\n    return 0\n", tmp_path, capsys)
    assert "with_enter %0" in output
    assert "then_1:\n    %2 = const 1\n    return %2\n" in output
    assert "merge_1:\n    with_exit %0\n" in output


def test_emit_ir_assert_evaluates_its_expressions(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    output = emit("def f(x):\n    assert x, 'm'\n    return x\n", tmp_path, capsys)
    assert output == "func @f(%0) {\nentry:\n    %1 = const 'm'\n    assert %0, %1\n    return %0\n}\n"


def test_emit_ir_defaults_and_decorators_do_not_change_the_function(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    output = emit("@deco\ndef f(a, b=1, *, c=2):\n    return c\n", tmp_path, capsys)
    assert output == "func @f(%0, %1, %2) {\nentry:\n    return %2\n}\n"


def test_emit_ir_module_level_code_and_methods(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    output = emit(
        "LIMIT = 3\n\nclass Store:\n    size = 0\n\n    def get(self, key):\n        return self.data[key]\n\n"
        "def top():\n    return LIMIT\n",
        tmp_path,
        capsys,
    )
    assert output.startswith("func @Store.get(%0, %1) {\n")
    assert "func @top() {\n" in output


def test_emit_ssa_handles_the_new_instructions(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    output = emit("def f(o, k):\n    o.n += k\n    xs = [o, k]\n    return xs\n", tmp_path, capsys, "--ssa")
    assert "set_attr %0, 'n', %3\n" in output
    assert "%4 = build_list %0, %1\n    return %4\n" in output


# --------------------------------------------------------------------------- tolerant check


def test_check_reports_unsupported_functions_and_keeps_going(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    source = tmp_path / "mixed.py"
    source.write_text(
        "CONFIG = {}\n\n"
        "def outer():\n"
        "    def inner():\n"
        "        return 1\n"
        "    return inner\n\n"
        "class Runner:\n"
        "    def go(self, code):\n"
        "        eval(code)\n",
        encoding="utf-8",
    )

    exit_code = main(["--check", str(source), "--plugins", str(PLUGINS)])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert f"{source}:3:1: info unsupported-syntax: " in output
    assert "Function" in output
    assert f"{source}:10:9: high dangerous-eval:" in output
    assert output.endswith("2 findings\n")


def test_unsupported_syntax_findings_are_notes() -> None:
    findings = engine.check(SourceManager().add_source("n.py", "def f():\n    def g():\n        pass\n"), [PLUGINS])

    assert [f.rule_id for f in findings] == ["unsupported-syntax"]
    assert findings[0].severity is Severity.INFO
    assert findings[0].function == "f"


def test_taint_flows_through_list_literals() -> None:
    findings = engine.check(
        SourceManager().add_source("cmd.py", "import subprocess\n\ndef run():\n    subprocess.run(['sh', '-c', input()], check=True)\n"),
        [PLUGINS],
    )
    assert [f.rule_id for f in findings] == ["command-injection"]


def test_taint_flows_through_keyword_arguments() -> None:
    findings = engine.check(
        SourceManager().add_source("cmd.py", "import subprocess\n\ndef run():\n    subprocess.run('ls', input=input())\n"),
        [PLUGINS],
    )
    assert [f.rule_id for f in findings] == ["command-injection"]
