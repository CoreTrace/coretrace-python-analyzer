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

import hashlib
import json
import re
import tomllib
from bisect import bisect_right

from coretrace_python.source.model import FileLocation, SourceId

Pointer = tuple[str | int, ...]

_SPACE = re.compile(r"[ \t\n\r]*")
# A JSON string as RFC 8259 writes it; ``json`` decodes it.
_STRING = re.compile(r'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"')
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?")
_LITERALS = {"true": True, "false": False, "null": None}
_HEADER = re.compile(r"\s*(\[\[?)\s*(.+?)\s*(\]\]?)\s*(?:#.*)?$")
_KEY_LINE = re.compile(r"""\s*("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+)\s*=\s*(.*)$""")


def file_location(source_id: SourceId, path: Pointer, value: str) -> FileLocation:
    """The location of a value whose line could not be established: its file, its JSON
    pointer, and a digest of the value, so that a baseline tells a changed value apart
    without recording it."""

    digest = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return FileLocation(source_id, pointer_text(path), f"sha256:{digest}")


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
    table: the root, ``[a.b]``, or the element ``[[a]]`` opens, numbered in order. Lines
    are counted by line feeds, as the rest of the engine counts them; a line that starts
    inside a multi-line string or an open array or inline table is a continuation, never
    a header or a key."""

    def __init__(self, text: str) -> None:
        # Section, key -> the line number, column and written text of each value.
        self._keys: dict[Pointer, dict[str, list[tuple[int, int, str]]]] = {(): {}}
        arrays: dict[Pointer, int] = {}
        current: Pointer = ()
        state = _LexState()
        for number, line in enumerate(text.split("\n"), start=1):
            line = line.removesuffix("\r")
            continued = state.inside()
            state.read(line)
            if continued:
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
                self._keys.setdefault(current, {})
                continue
            match = _KEY_LINE.match(line)
            if match is None:
                continue
            try:
                key = _key(match.group(1))
            except tomllib.TOMLDecodeError:
                continue
            self._keys[current].setdefault(key, []).append(
                (number, match.start(2) + 1, match.group(2))
            )

    def locate(self, path: Pointer, value: object) -> tuple[int, int] | None:
        """The line and column ``value`` starts at under ``path``, or None when the
        section its path names has no line setting that key to that value."""

        if not path or isinstance(path[-1], int):
            return None
        for number, column, written in self._keys.get(path[:-1], {}).get(path[-1], ()):
            try:
                found = tomllib.loads(f"v = {written}")["v"]
            except tomllib.TOMLDecodeError:
                continue
            if _same(found, value):
                return number, column
        return None


class _LexState:
    """Where a TOML line leaves the reader: inside a multi-line string (its delimiter),
    or inside arrays and inline tables opened by a value (their depth). Strings and
    comments are skipped, so a delimiter or a bracket written in them counts for
    nothing."""

    def __init__(self) -> None:
        self.string: str | None = None
        self.depth = 0

    def inside(self) -> bool:
        return self.string is not None or self.depth > 0

    def read(self, line: str) -> None:
        position, valued = 0, self.depth > 0
        while position < len(line):
            if self.string is not None:
                if self.string == '"""' and line[position] == "\\":
                    position += 2
                elif line.startswith(self.string, position):
                    # Up to two more quotes before the delimiter belong to the string.
                    run = len(line[position:]) - len(line[position:].lstrip(self.string[0]))
                    self.string, position = None, position + min(run, 5)
                else:
                    position += 1
                continue
            character = line[position]
            if character == "#":
                return
            if line.startswith(('"""', "'''"), position):
                self.string, position = line[position : position + 3], position + 3
            elif character == '"':
                position += 1
                while position < len(line) and line[position] != '"':
                    position += 2 if line[position] == "\\" else 1
                position += 1
            elif character == "'":
                closing = line.find("'", position + 1)
                position = len(line) if closing < 0 else closing + 1
            else:
                if character == "=" and self.depth == 0:
                    valued = True
                elif character in "[{" and valued:
                    self.depth += 1
                elif character in "]}" and self.depth > 0:
                    self.depth -= 1
                position += 1


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
