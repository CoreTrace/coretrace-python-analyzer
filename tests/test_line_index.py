"""The line index of a text: the line and column of each offset, lines counted as
``lines_of`` counts them, and back."""

from __future__ import annotations

from coretrace_python.source import LineIndex

# Lines broken by a line feed, a carriage return and line feed, and a lone carriage
# return; a column counts characters, not bytes.
TEXT = "a\nbé\r\nc\rd"
POSITIONS = [(1, 1), (1, 2), (2, 1), (2, 2), (2, 3), (2, 4), (3, 1), (3, 2), (4, 1), (4, 2)]


def test_each_offset_has_the_line_and_column_lines_of_counts() -> None:
    index = LineIndex(TEXT)

    assert [index.position(offset) for offset in range(len(TEXT) + 1)] == POSITIONS


def test_each_position_has_its_offset_back() -> None:
    index = LineIndex(TEXT)

    assert [index.offset(line, column) for line, column in POSITIONS] == list(range(len(TEXT) + 1))
