"""Where a value of a JSON or TOML document is written, from its structural path.

Rules judge the values ``json`` and ``tomllib`` decode; this component, apart from them,
finds the line and column of a value from its path (the keys and indexes leading to it)
and checks that the text there holds that very value. JSON is read with the position of
every value. In TOML, the key and its value are checked in the section the path names:
the root, a ``[table]``, or the element of an array of tables that its ``[[header]]``
opens, with its ``[sub.tables]``. What the component cannot place (a dotted key, an
inline table, a multi-line value, a document it cannot read) has no position: the caller
gives the file, never a guessed line.
"""

from __future__ import annotations

import json
import re
import tomllib
from bisect import bisect_right

Pointer = tuple[str | int, ...]

_SPACE = re.compile(r"[ \t\n\r]*")
# A JSON string as RFC 8259 writes it; ``json`` decodes it.
_STRING = re.compile(r'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"')
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?")
_LITERALS = {"true": True, "false": False, "null": None}
_HEADER = re.compile(r"\s*(\[\[?)\s*(.+?)\s*(\]\]?)\s*(?:#.*)?$")
_KEY_LINE = re.compile(r"""\s*("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+)\s*=\s*(.*)$""")


def pointer_text(path: Pointer) -> str:
    """``path`` as a JSON pointer (RFC 6901): ``/entries/0/name``."""

    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in path)


class _Lines:
    def __init__(self, text: str) -> None:
        self._starts = [0, *(match.end() for match in re.finditer("\n", text))]

    def position(self, offset: int) -> tuple[int, int]:
        """The one-based line and column of ``offset``."""

        line = bisect_right(self._starts, offset)
        return line, offset - self._starts[line - 1] + 1


def _same(found: object, value: object) -> bool:
    return type(found) is type(value) and found == value


class JsonPositions:
    """The position of every value of a JSON document, by structural path. A key
    repeated in one object keeps its last value, as ``json`` decodes it."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._values: dict[Pointer, tuple[int, object]] = {}
        try:
            end = self._value(_SPACE.match(text, 0).end(), ())  # type: ignore[union-attr]
            if _SPACE.match(text, end).end() != len(text):  # type: ignore[union-attr]
                raise ValueError("trailing text")
        except (ValueError, IndexError, RecursionError):
            self._values = {}
        self._lines = _Lines(text)

    def locate(self, path: Pointer, value: object) -> tuple[int, int] | None:
        """The line and column ``value`` starts at under ``path``, or None when the text
        there does not hold it."""

        found = self._values.get(path)
        if found is None or not _same(found[1], value):
            return None
        return self._lines.position(found[0])

    def _value(self, start: int, path: Pointer) -> int:
        text = self._text
        first = text[start]
        if first == '"':
            decoded, end = self._string(start)
            self._values[path] = (start, decoded)
            return end
        if first == "{":
            return self._object(start, path)
        if first == "[":
            return self._array(start, path)
        for word, literal in _LITERALS.items():
            if text.startswith(word, start):
                self._values[path] = (start, literal)
                return start + len(word)
        number = _NUMBER.match(text, start)
        if number is None:
            raise ValueError(f"no JSON value at {start}")
        written = number.group(0)
        self._values[path] = (
            start,
            float(written) if any(c in written for c in ".eE") else int(written),
        )
        return number.end()

    def _object(self, start: int, path: Pointer) -> int:
        text = self._text
        position = self._space(start + 1)
        if text[position] == "}":
            return position + 1
        while True:
            if text[position] != '"':
                raise ValueError(f"no key at {position}")
            key, position = self._string(position)
            position = self._space(position)
            if text[position] != ":":
                raise ValueError(f"no colon at {position}")
            position = self._space(self._value(self._space(position + 1), (*path, key)))
            if text[position] == "}":
                return position + 1
            if text[position] != ",":
                raise ValueError(f"no comma at {position}")
            position = self._space(position + 1)

    def _array(self, start: int, path: Pointer) -> int:
        text = self._text
        position = self._space(start + 1)
        if text[position] == "]":
            return position + 1
        index = 0
        while True:
            position = self._space(self._value(position, (*path, index)))
            if text[position] == "]":
                return position + 1
            if text[position] != ",":
                raise ValueError(f"no comma at {position}")
            position = self._space(position + 1)
            index += 1

    def _string(self, start: int) -> tuple[str, int]:
        match = _STRING.match(self._text, start)
        if match is None:
            raise ValueError(f"no JSON string at {start}")
        decoded: str = json.loads(match.group(0))
        return decoded, match.end()

    def _space(self, position: int) -> int:
        return _SPACE.match(self._text, position).end()  # type: ignore[union-attr]


class TomlPositions:
    """The key lines of each section of a TOML document, by the structural path of its
    table: the root, ``[a.b]``, or the element ``[[a]]`` opens, numbered in order."""

    def __init__(self, text: str) -> None:
        self._lines = text.splitlines()
        self._sections: dict[Pointer, list[int]] = {(): []}
        arrays: dict[Pointer, int] = {}
        current: Pointer = ()
        quoted: str | None = None
        for number, line in enumerate(self._lines):
            if quoted is not None:
                if line.count(quoted) % 2:
                    quoted = None
                continue
            header = _HEADER.match(line)
            keys = _header_keys(header.group(2)) if header is not None else None
            if (
                header is not None
                and keys is not None
                and (header.group(1) == "[[") == (header.group(3) == "]]")
            ):
                table = _resolve(keys[:-1], arrays) + (keys[-1],)
                if header.group(1) == "[[":
                    arrays[table] = arrays.get(table, -1) + 1
                    table = (*table, arrays[table])
                else:
                    table = _resolve(keys, arrays)
                current = table
                self._sections.setdefault(current, [])
                continue
            self._sections[current].append(number)
            for delimiter in ('"""', "'''"):
                if line.count(delimiter) % 2:
                    quoted = delimiter

    def locate(self, path: Pointer, value: object) -> tuple[int, int] | None:
        """The line and column ``value`` starts at under ``path``, or None when the
        section its path names has no line setting that key to that value."""

        if not path or isinstance(path[-1], int):
            return None
        for number in self._sections.get(path[:-1], ()):
            line = self._lines[number]
            match = _KEY_LINE.match(line)
            if match is None or _key(match.group(1)) != path[-1]:
                continue
            try:
                found = tomllib.loads(f"v = {match.group(2)}")["v"]
            except tomllib.TOMLDecodeError:
                continue
            if _same(found, value):
                return number + 1, match.start(2) + 1
        return None


def _resolve(keys: tuple[str, ...], arrays: dict[Pointer, int]) -> Pointer:
    """The structural path of a table named by ``keys``: a key that names an array of
    tables stands for its last element."""

    path: Pointer = ()
    for key in keys:
        path = (*path, key)
        if path in arrays:
            path = (*path, arrays[path])
    return path


def _header_keys(written: str) -> tuple[str, ...] | None:
    """The keys of a table header, read as ``tomllib`` reads them; None when the text
    is not a header (an array literal on its own line)."""

    try:
        table: object = tomllib.loads(f"[{written}]")
    except tomllib.TOMLDecodeError:
        return None
    keys: list[str] = []
    while isinstance(table, dict) and len(table) == 1:
        key = next(iter(table))
        keys.append(key)
        table = table[key]
    return tuple(keys) if keys else None


def _key(written: str) -> str:
    return next(iter(tomllib.loads(f"{written} = 0")))
