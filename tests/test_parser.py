import pytest

from coretrace_python.frontend.parser import ParseError, parse_source


def test_parse_source_returns_module() -> None:
    tree = parse_source("def example():\n    return 1\n", "example.py")
    assert len(tree.body) == 1


def test_parse_error_contains_location() -> None:
    with pytest.raises(ParseError, match=r"broken.py:1:12"):
        parse_source("def broken(:\n", "broken.py")

