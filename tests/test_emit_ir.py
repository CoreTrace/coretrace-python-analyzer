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
    assert "%1 = global 'print'" in output
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
