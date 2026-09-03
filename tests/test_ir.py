from coretrace_python.frontend import build_hir
from coretrace_python.ir.lowering import lower_module
from coretrace_python.ir.model import BinaryOp, Return
from coretrace_python.source import SourceManager


def test_lowering_preserves_locations() -> None:
    source = SourceManager().add_source("add.py", "def add(a, b):\n    return a + b\n")
    module = lower_module(build_hir(source))
    instructions = module.functions[0].blocks[0].instructions
    assert isinstance(instructions[0], BinaryOp)
    assert instructions[0].location.start_line == 2
    assert isinstance(instructions[1], Return)
    assert instructions[1].location.source_id.value == "add.py"
