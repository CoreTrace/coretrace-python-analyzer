from coretrace_python.frontend.lowering import lower_module
from coretrace_python.frontend.parser import parse_source
from coretrace_python.ir.model import BinaryOp, Return


def test_lowering_preserves_locations() -> None:
    tree = parse_source("def add(a, b):\n    return a + b\n", "add.py")
    module = lower_module(tree, "add.py")
    instructions = module.functions[0].blocks[0].instructions
    assert isinstance(instructions[0], BinaryOp)
    assert instructions[0].location.line == 2
    assert isinstance(instructions[1], Return)
    assert instructions[1].location.filename == "add.py"

