"""What the constant text a URL starts with proves, and nothing more: one proof that the
rules reading URLs share, each drawing its own verdict from it.

- ``origin``: constant ``scheme://authority`` and the ``/``, ``?`` or ``#`` ending it, so
  the input cannot choose the host. A backslash, which some parsers take for a slash,
  does not end the authority.
- ``path_fixed``: the text fixes the path too; what follows is query or fragment.
- ``relative``: the text starts a reference a browser resolves on the current site:
  ``/`` then a character that is neither a slash, a backslash nor a space or control
  character (a browser takes ``//`` and ``/\\`` for another host, and drops tabs and
  newlines), ``?`` or ``#``, or a relative path whose first segment, ended in the text,
  holds no ``:`` that would make it a scheme.
"""

from __future__ import annotations

import pytest

from coretrace_python.interprocedural import Arguments
from coretrace_python.taint.urls import UrlProof, redirects_disabled, url_proof


@pytest.mark.parametrize(
    "text, proof",
    [
        ("https://api.example.com/users/", UrlProof("https://api.example.com/users/", "https://api.example.com/")),
        ("https://api.example.com/search?q=", UrlProof("https://api.example.com/search?q=", "https://api.example.com/", True)),
        ("https://api.example.com/#", UrlProof("https://api.example.com/#", "https://api.example.com/", True)),
        ("https://api.example.com?q=", UrlProof("https://api.example.com?q=", "https://api.example.com?", True)),
        ("https://api.example.com", UrlProof("https://api.example.com")),
        ("https://api.example.com:", UrlProof("https://api.example.com:")),
        ("https:/", UrlProof("https:/")),
        ("https://", UrlProof("https://")),
        ("https://api.example.com\\", UrlProof("https://api.example.com\\")),
        ("//api.example.com/", UrlProof("//api.example.com/")),
        ("", UrlProof("")),
    ],
)
def test_constant_text_fixes_an_origin_only_with_a_complete_authority(text: str, proof: UrlProof) -> None:
    assert url_proof(text) == proof


@pytest.mark.parametrize(
    "text, relative",
    [
        ("/profile/", True),
        ("/p", True),
        ("?page=", True),
        ("#top", True),
        ("profile/", True),
        ("search?q=", True),
        ("/", False),
        ("//evil.example/", False),
        ("/\\", False),
        ("/\t", False),
        ("/ ", False),
        ("profile", False),
        ("javascript:", False),
        ("a:b/", False),
        (" /profile/", False),
    ],
)
def test_constant_text_starts_a_reference_on_the_current_site_as_a_browser_resolves_it(text: str, relative: bool) -> None:
    assert url_proof(text).relative is relative


@pytest.mark.parametrize(
    "arguments, disabled",
    [
        (Arguments((), (("allow_redirects", "False"),)), True),
        (Arguments((), (("follow_redirects", "False"),)), True),
        (Arguments((), (("allow_redirects", "True"),)), False),
        (Arguments((), (("allow_redirects", None),)), False),
        (Arguments((), (), unpacked=True), False),
        (Arguments(), False),
        (None, False),
    ],
)
def test_only_an_explicit_keyword_disables_redirects(arguments: Arguments | None, disabled: bool) -> None:
    assert redirects_disabled(arguments) is disabled
