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


def test_a_structural_path_is_written_as_a_json_pointer() -> None:
    assert pointer_text(("packages", "node_modules/a", "dependencies", "js-tokens")) == (
        "/packages/node_modules~1a/dependencies/js-tokens"
    )
    assert pointer_text(("entries", 0, "headers", 1, 1)) == "/entries/0/headers/1/1"
    assert pointer_text(("a~b",)) == "/a~0b"
