"""Requests and httpx models: every request function is a SSRF sink, and what it returns
is an ``http-response`` source, so data fetched from a remote server is untrusted."""

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

_REQUEST_FUNCTIONS = (
    *(f"{caller}.{method}" for caller in _CALLERS for method in _METHODS),
    "requests.Session.send",
    "httpx.stream",
    "httpx.Client.stream",
    "httpx.AsyncClient.stream",
    "httpx.Client.send",
    "httpx.AsyncClient.send",
)


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class HttpClientModels(ModelPlugin):
    name: ClassVar[str] = "http-client-models"
    models: ClassVar[tuple[Model, ...]] = (
        *(Sink(_sym(function), TaintKind.SSRF) for function in _REQUEST_FUNCTIONS),
        *(Source(_sym(function), "http-response") for function in _REQUEST_FUNCTIONS),
    )
