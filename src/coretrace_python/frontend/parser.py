from __future__ import annotations

import ast
import warnings

from coretrace_python.source import SourceFile


class ParseError(Exception):
    """A source-located Python parsing failure."""


def parse_source(source: str, filename: str = "<unknown>") -> ast.Module:
    try:
        with warnings.catch_warnings():
            # A warning raised while parsing (an invalid escape sequence: a SyntaxWarning
            # from 3.12, a DeprecationWarning on 3.11) is about the analysed source, not
            # the analyzer, and would reach its stderr once per process that parses (#241).
            warnings.simplefilter("ignore")
            return ast.parse(source, filename=filename)
    except SyntaxError as error:
        line = error.lineno or 0
        column = error.offset or 0
        message = error.msg or "invalid syntax"
        raise ParseError(f"{filename}:{line}:{column}: {message}") from error
    except RecursionError as error:
        # Python 3.11 builds the AST of a long left-nested chain recursively (#233).
        raise ParseError(f"{filename}:1:1: syntax nested too deeply for Python's parser") from error


def parse_source_file(source: SourceFile) -> ast.Module:
    return parse_source(source.text, filename=str(source.source_id))
