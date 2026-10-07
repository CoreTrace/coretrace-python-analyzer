"""Acceptance tests for issues #207 and #210: where a value of a JSON or TOML file is written.

The detectors judge the values ``json`` and ``tomllib`` decode; where each value is
written is found by a separate component, from its structural path (the keys and indexes
leading to it) and checked against the value itself. JSON is read with the position of
every value, so repeated keys, nested arrays and escaped strings are told apart. In TOML,
the key and its value are checked in the section the path names, an array of tables
included: the element is the one its ``[[header]]`` opens, and its key must hold the
value. A value the component cannot place is not given a guessed line: it has no
position (None).
"""

from __future__ import annotations

import pytest

from coretrace_python.source.positions import JsonPositions, TomlPositions, pointer_text

HAR = """{
  "entries": [
    {"request": {"headers": [["Host", "example.org"], ["X-Amz-Cf-Id", "Kk1li6yk9u"]]}},
    {"request": {"headers": [["Host", "example.org"], ["X-Amz-Cf-Id", "PaWnQ2x7ab"]]}}
  ]
}
"""


def test_a_json_value_is_found_by_its_path_among_repeated_keys() -> None:
    text = '{\n  "first": {"api_token": "Zx81"},\n  "second": {"api_token": "Pq72"}\n}\n'
    positions = JsonPositions(text)

    assert positions.locate(("first", "api_token"), "Zx81") == (2, 26)
    assert positions.locate(("second", "api_token"), "Pq72") == (3, 27)


def test_json_values_in_nested_arrays_are_found_at_their_own_line() -> None:
    positions = JsonPositions(HAR)

    assert positions.locate(("entries", 0, "request", "headers", 1, 1), "Kk1li6yk9u") == (3, 71)
    assert positions.locate(("entries", 1, "request", "headers", 1, 1), "PaWnQ2x7ab") == (4, 71)


def test_escaped_json_strings_are_read_as_json_reads_them() -> None:
    text = '{"k\\"q": "\\u00e9t\\u00e9", "plain": "a\\nb"}'
    positions = JsonPositions(text)

    assert positions.locate(('k"q',), "été") == (1, 10)
    assert positions.locate(("plain",), "a\nb") == (1, 36)


def test_a_duplicate_json_key_is_the_last_one_as_json_decodes_it() -> None:
    positions = JsonPositions('{\n"k": "one",\n"k": "two"\n}')

    assert positions.locate(("k",), "two") == (3, 6)
    assert positions.locate(("k",), "one") is None


def test_a_json_value_that_does_not_match_has_no_position() -> None:
    positions = JsonPositions('{"a": {"b": "x"}}')

    assert positions.locate(("a", "b"), "y") is None
    assert positions.locate(("a", "c"), "x") is None
    assert JsonPositions("{not json").locate(("a",), "x") is None


LOCK = """version = 1

[[package]]
name = "flask"
version = "3.1.2"
dependencies = [
    { name = "werkzeug" },
]

[[package]]
name = "werkzeug"
version = "3.1.5"

[package.metadata]
token = "abc123"
"""


def test_a_toml_value_is_found_in_the_section_its_path_names() -> None:
    positions = TomlPositions(
        'title = "app"\n\n[db]\npassword = "s3cr3t"  # set by ops\nport = 5432\n'
    )

    assert positions.locate(("title",), "app") == (1, 9)
    assert positions.locate(("db", "password"), "s3cr3t") == (4, 12)
    assert positions.locate(("db", "port"), 5432) == (5, 8)


def test_an_element_of_an_array_of_tables_is_checked_by_its_key_and_value() -> None:
    positions = TomlPositions(LOCK)

    assert positions.locate(("package", 0, "name"), "flask") == (4, 8)
    assert positions.locate(("package", 1, "name"), "werkzeug") == (11, 8)
    assert positions.locate(("package", 1, "name"), "flask") is None
    assert positions.locate(("package", 2, "name"), "werkzeug") is None


def test_a_subtable_of_an_array_element_belongs_to_that_element() -> None:
    positions = TomlPositions(LOCK)

    assert positions.locate(("package", 1, "metadata", "token"), "abc123") == (15, 9)
    assert positions.locate(("package", 0, "metadata", "token"), "abc123") is None


def test_quoted_toml_keys_and_headers_are_read() -> None:
    positions = TomlPositions('[servers."alpha.example"]\n"api-key" = "k-1234"\n')

    assert positions.locate(("servers", "alpha.example", "api-key"), "k-1234") == (2, 13)


def test_toml_values_the_component_cannot_place_have_no_position() -> None:
    positions = TomlPositions('a.token = "x1"\ndep = { token = "x2" }\nnote = """\nx3\n"""\n')

    assert positions.locate(("a", "token"), "x1") is None
    assert positions.locate(("dep", "token"), "x2") is None
    assert positions.locate(("note",), "x3\n") is None
    assert TomlPositions("[unclosed").locate(("a",), "x") is None


def test_a_header_or_key_written_inside_a_toml_string_is_not_one() -> None:
    commented = 'note = "a" # use """ for docs\nexample = """\n[t]\nk = "S"\n"""\n[t]\nk = "S"\n'
    escaped = 'doc = """\nescaped \\"""\n[t]\nk = "S"\n"""\n[t]\nk = "S"\n'
    one_line = 's = \'"""\'\n[t]\nk = "S"\n'

    assert TomlPositions(commented).locate(("t", "k"), "S") == (7, 5)
    assert TomlPositions(escaped).locate(("t", "k"), "S") == (7, 5)
    assert TomlPositions(one_line).locate(("t", "k"), "S") == (3, 5)


@pytest.mark.parametrize("quote", ['"', "'"])
def test_quotes_before_a_closing_delimiter_belong_to_the_string(quote: str) -> None:
    triple = quote * 3
    text = (
        f"a = [{triple}x{triple}{quote}, {triple}y{triple}]\n"
        f'c = {triple}\n]\n[t]\nk = "v"\n{triple}\n[t]\nk = "v"\n'
    )

    assert TomlPositions(text).locate(("t", "k"), "v") == (8, 5)


def test_an_array_element_alone_on_its_line_is_not_a_toml_header() -> None:
    positions = TomlPositions('arr = [\n  ["b"]\n]\nk = "v"\n')

    assert positions.locate(("k",), "v") == (4, 5)


def test_toml_lines_are_counted_by_line_feeds_only() -> None:
    positions = TomlPositions('# caf\u2028e\napi_token = "S"\r\nport = 1\r\n')

    assert positions.locate(("api_token",), "S") == (2, 13)
    assert positions.locate(("port",), 1) == (3, 8)


def test_an_element_of_a_toml_array_is_found_and_checked() -> None:
    text = (
        '[project]\ndependencies = [\n    "a",  # first, ["x"]\n    { n = [1, 2] },\n'
        '    \'lit, "b"\', "c"\n]\noptional = ["d", "e"]\nname = "app"\n'
    )
    positions = TomlPositions(text)

    assert positions.locate(("project", "dependencies", 0), "a") == (3, 5)
    assert positions.locate(("project", "dependencies", 1), {"n": [1, 2]}) == (4, 5)
    assert positions.locate(("project", "dependencies", 2), 'lit, "b"') == (5, 5)
    assert positions.locate(("project", "dependencies", 3), "c") == (5, 17)
    assert positions.locate(("project", "optional", 1), "e") == (7, 18)
    assert positions.locate(("project", "dependencies", 0), "b") is None
    assert positions.locate(("project", "dependencies", 4), "c") is None
    assert positions.locate(("project", "name", 0), "app") is None


def test_an_array_element_written_over_several_lines_has_no_position() -> None:
    positions = TomlPositions('keys = ["""\nfirst\n""", "b"]\nother = [[1,\n  2]]\n')

    assert positions.locate(("keys", 0), "first\n") is None
    assert positions.locate(("keys", 1), "b") == (3, 6)
    assert positions.locate(("other", 0), [1, 2]) is None


def test_a_structural_path_is_written_as_a_json_pointer() -> None:
    assert pointer_text(("packages", "node_modules/a", "dependencies", "js-tokens")) == (
        "/packages/node_modules~1a/dependencies/js-tokens"
    )
    assert pointer_text(("entries", 0, "headers", 1, 1)) == "/entries/0/headers/1/1"
    assert pointer_text(("a~b",)) == "/a~0b"
