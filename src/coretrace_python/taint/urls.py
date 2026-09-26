"""What the constant text a URL starts with proves about its destination, and whether a
call follows redirects: one proof that the rules reading URLs share, each drawing its
own verdict from it. The text is what ``+`` and f-strings build before any other value
(``abstract.strings``); the proof says nothing about the rest of the URL."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from coretrace_python.abstract.strings import leading_text
from coretrace_python.interprocedural import Arguments
from coretrace_python.ir.model import Instruction, Value
from coretrace_python.taint.engine import TaintFlow

# ``scheme://`` and an authority ended by ``/``, ``?`` or ``#``. A backslash, which some
# URL parsers take for a slash, does not end it here.
_ORIGIN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/?#\\]+[/?#]")
# The same with the path fixed too: what follows is query or fragment.
_PATH = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/?#\\]+(?:/[^?#]*)?[?#]")
# A reference a browser resolves on the current site: ``/`` then a character that is not
# a slash, a backslash, a space or a control character (``//`` and ``/\`` name another
# host, and a browser drops tabs and newlines), a query or a fragment, or a relative path
# whose first segment ends in the text without a ``:`` that would make it a scheme.
_RELATIVE = re.compile(r"/[^/\\\x00-\x20\x7f]|[?#]|[^/\\?#:\x00-\x20\x7f][^/\\?#:]*[/?#]")
# A client honours the one of these keywords it knows and rejects the other with a
# ``TypeError``: either way, the call follows no redirect.
_NO_REDIRECTS = ("allow_redirects", "follow_redirects")


@dataclass(frozen=True)
class UrlProof:
    """What the constant ``text`` a URL starts with proves: the ``origin`` it fixes
    (``scheme://authority`` and the character ending it), whether it fixes the path
    too (``path_fixed``), and whether it starts a reference a browser resolves on the
    current site (``relative``)."""

    text: str
    origin: str | None = None
    path_fixed: bool = False
    relative: bool = False


def url_proof(text: str) -> UrlProof:
    origin = _ORIGIN.match(text)
    return UrlProof(
        text,
        origin.group(0) if origin is not None else None,
        _PATH.match(text) is not None,
        _RELATIVE.match(text) is not None,
    )


def flow_url(flow: TaintFlow, defs: Mapping[Value, Instruction], strings: Mapping[str, str]) -> UrlProof:
    """The proof for the value ``flow`` passes to its sink, ``defs`` defining the values
    of the function making the call. A flow reaching its sink in a callee proves nothing:
    the value is built there."""

    if flow.through is not None:
        return UrlProof("")
    text, _ = leading_text(flow.argument, defs, strings)
    return url_proof(text)


def redirects_disabled(arguments: Arguments | None) -> bool:
    """Whether the call disables redirects explicitly (``allow_redirects=False`` or
    ``follow_redirects=False``); absent, a variable or unpacked options do not."""

    return arguments is not None and any(arguments.given(name) == (True, "False") for name in _NO_REDIRECTS)
