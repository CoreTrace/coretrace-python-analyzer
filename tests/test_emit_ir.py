from coretrace_python.cli import main


def test_emit_ir_golden(tmp_path, capsys) -> None:
    source = tmp_path / "add.py"
    source.write_text("def add(a, b):\n    x = a + b\n    return x\n", encoding="utf-8")

    assert main(["--emit-ir", str(source)]) == 0
    assert capsys.readouterr().out == (
        "func @add(%0, %1) {\n"
        "entry:\n"
        "    %2 = binary.add %0, %1\n"
        '    store_local "x", %2\n'
        '    %3 = load_local "x"\n'
        "    return %3\n"
        "}\n"
    )


def test_emit_ir_for_python_specific_operations(tmp_path, capsys) -> None:
    source = tmp_path / "lookup.py"
    source.write_text(
        "def lookup(obj, key):\n    return obj.items[key]\n", encoding="utf-8"
    )

    assert main(["--emit-ir", str(source)]) == 0
    output = capsys.readouterr().out
    assert output == (
        "func @lookup(%0, %1) {\n"
        "entry:\n"
        "    %2 = get_attr %0, 'items'\n"
        "    %3 = get_item %2, %1\n"
        "    return %3\n"
        "}\n"
    )


def test_emit_ir_for_call(tmp_path, capsys) -> None:
    source = tmp_path / "call.py"
    source.write_text("def greet(name):\n    return print(name)\n", encoding="utf-8")

    assert main(["--emit-ir", str(source)]) == 0
    output = capsys.readouterr().out
    assert "%1 = symbol @python.builtins.print" in output
    assert "%2 = call %1(%0)" in output


def test_emit_ir_for_local_assignment(tmp_path, capsys) -> None:
    source = tmp_path / "locals.py"
    source.write_text(
        "def calculate(a, b):\n"
        "    result = a + b\n"
        "    return result\n",
        encoding="utf-8",
    )

    assert main(["--emit-ir", str(source)]) == 0
    assert capsys.readouterr().out == (
        "func @calculate(%0, %1) {\n"
        "entry:\n"
        "    %2 = binary.add %0, %1\n"
        '    store_local "result", %2\n'
        '    %3 = load_local "result"\n'
        "    return %3\n"
        "}\n"
    )


# --------------------------------------------------------------------------- control flow
# ``--emit-ir`` prints one block per CFG block with explicit terminators
# (docs/architecture.md §5 and §6). Expected to remain red until lowering runs over the CFG.


def test_emit_ir_for_if_without_else(tmp_path, capsys) -> None:
    # The example of §5: the sanitizer runs on one path only.
    source = tmp_path / "guard.py"
    source.write_text(
        "def f(safe, x):\n"
        "    if safe:\n"
        "        x = sanitize(x)\n"
        "    sink(x)\n",
        encoding="utf-8",
    )

    assert main(["--emit-ir", str(source)]) == 0
    assert capsys.readouterr().out == (
        "func @f(%0, %1) {\n"
        "entry:\n"
        '    store_local "x", %1\n'
        "    branch %0, then_1, merge_1\n"
        "then_1:\n"
        "    %2 = global 'sanitize'\n"
        '    %3 = load_local "x"\n'
        "    %4 = call %2(%3)\n"
        '    store_local "x", %4\n'
        "    jump merge_1\n"
        "merge_1:\n"
        "    %5 = global 'sink'\n"
        '    %6 = load_local "x"\n'
        "    %7 = call %5(%6)\n"
        "    return\n"
        "}\n"
    )


def test_emit_ir_for_while_loop(tmp_path, capsys) -> None:
    source = tmp_path / "loop.py"
    source.write_text(
        "def f(n):\n"
        "    while n > 0:\n"
        "        n = n - 1\n"
        "    return n\n",
        encoding="utf-8",
    )

    assert main(["--emit-ir", str(source)]) == 0
    assert capsys.readouterr().out == (
        "func @f(%0) {\n"
        "entry:\n"
        '    store_local "n", %0\n'
        "    jump loop_1\n"
        "loop_1:\n"
        '    %1 = load_local "n"\n'
        "    %2 = const 0\n"
        "    %3 = compare.gt %1, %2\n"
        "    branch %3, body_1, exit_1\n"
        "body_1:\n"
        '    %4 = load_local "n"\n'
        "    %5 = const 1\n"
        "    %6 = binary.sub %4, %5\n"
        '    store_local "n", %6\n'
        "    jump loop_1\n"
        "exit_1:\n"
        '    %7 = load_local "n"\n'
        "    return %7\n"
        "}\n"
    )


def test_emit_ir_for_for_loop(tmp_path, capsys) -> None:
    source = tmp_path / "sum.py"
    source.write_text(
        "def f(items):\n"
        "    total = 0\n"
        "    for item in items:\n"
        "        total = total + item\n"
        "    return total\n",
        encoding="utf-8",
    )

    assert main(["--emit-ir", str(source)]) == 0
    assert capsys.readouterr().out == (
        "func @f(%0) {\n"
        "entry:\n"
        "    %1 = const 0\n"
        '    store_local "total", %1\n'
        "    %2 = get_iter %0\n"
        "    jump loop_1\n"
        "loop_1:\n"
        '    for_next %2 -> "item", body_1, exit_1\n'
        "body_1:\n"
        '    %3 = load_local "total"\n'
        '    %4 = load_local "item"\n'
        "    %5 = binary.add %3, %4\n"
        '    store_local "total", %5\n'
        "    jump loop_1\n"
        "exit_1:\n"
        '    %6 = load_local "total"\n'
        "    return %6\n"
        "}\n"
    )


def test_emit_ir_for_raise(tmp_path, capsys) -> None:
    source = tmp_path / "raise.py"
    source.write_text(
        "def f(a):\n"
        "    if a:\n"
        "        raise ValueError(a)\n"
        "    return a\n\n"
        "def g():\n"
        "    raise\n",
        encoding="utf-8",
    )

    assert main(["--emit-ir", str(source)]) == 0
    output = capsys.readouterr().out
    assert (
        "then_1:\n"
        "    %1 = symbol @python.builtins.ValueError\n"
        "    %2 = call %1(%0)\n"
        "    raise %2\n"
        "merge_1:\n"
        "    return %0\n"
    ) in output
    assert "func @g() {\nentry:\n    raise\n}" in output


def test_emit_ir_for_break_and_continue(tmp_path, capsys) -> None:
    source = tmp_path / "control.py"
    source.write_text(
        "def f(items):\n"
        "    for item in items:\n"
        "        if item:\n"
        "            continue\n"
        "        if not item:\n"
        "            break\n"
        "    return 0\n",
        encoding="utf-8",
    )

    assert main(["--emit-ir", str(source)]) == 0
    output = capsys.readouterr().out
    assert "then_1:\n    jump loop_1\n" in output
    assert "then_2:\n    jump exit_1\n" in output


def test_emit_ir_keeps_unreachable_code(tmp_path, capsys) -> None:
    source = tmp_path / "dead.py"
    source.write_text("def f():\n    return 1\n    x = 2\n", encoding="utf-8")

    assert main(["--emit-ir", str(source)]) == 0
    output = capsys.readouterr().out
    assert "dead_1:\n    %1 = const 2\n" in output
