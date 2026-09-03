import pytest

from coretrace_python.semantic.symbols import SymbolId


def test_symbol_id_adds_the_python_namespace() -> None:
    symbol = SymbolId.from_python_path("os.system")
    assert symbol.canonical_name == "python.os.system"


def test_symbol_id_does_not_duplicate_the_python_namespace() -> None:
    symbol = SymbolId.from_python_path("python.os.system")
    assert symbol.canonical_name == "python.os.system"


def test_symbol_attribute_creates_a_child_identity() -> None:
    module = SymbolId.from_python_path("os")
    assert module.attribute("system") == SymbolId("python.os.system")


@pytest.mark.parametrize("path", ["", ".os"])
def test_invalid_symbol_paths_are_rejected(path: str) -> None:
    with pytest.raises(ValueError):
        SymbolId.from_python_path(path)
