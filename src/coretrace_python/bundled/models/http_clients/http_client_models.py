"""Requests and httpx models: every request function is a SSRF sink for the argument that
chooses the destination, and what it returns is an ``http-response`` source, so data
fetched from a remote server is untrusted. The destination is the URL — first, or second
after the method, or ``url=`` — or the prepared request a ``send`` takes; the body, the
headers and the query parameters do not choose the host."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import Model, Sink, Source, TaintKind

_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "request")

_CALLERS = (
    "requests",
    "requests.Session",
    "requests.api",
    "httpx",
    "httpx.Client",
    "httpx.AsyncClient",
)

# Where each function takes its destination, by position (the receiver of a method
# excluded) and by keyword, as its signature declares it.
_DESTINATIONS = {
    **{f"{caller}.{method}": (0, "url") for caller in _CALLERS for method in _METHODS if method != "request"},
    **{f"{caller}.request": (1, "url") for caller in _CALLERS},
    "httpx.stream": (1, "url"),
    "httpx.Client.stream": (1, "url"),
    "httpx.AsyncClient.stream": (1, "url"),
    "requests.Session.send": (0, "request"),
    "httpx.Client.send": (0, "request"),
    "httpx.AsyncClient.send": (0, "request"),
}


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class HttpClientModels(ModelPlugin):
    name: ClassVar[str] = "http-client-models"
    models: ClassVar[tuple[Model, ...]] = (
        *(
            Sink(_sym(function), TaintKind.SSRF, ((TaintKind.SSRF, (position,)),), ((TaintKind.SSRF, (keyword,)),))
            for function, (position, keyword) in _DESTINATIONS.items()
        ),
        *(Source(_sym(function), "http-response") for function in _DESTINATIONS),
    )
