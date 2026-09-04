"""FastAPI security models: route handlers and response sinks."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import EntryPoint, Model, RouteRegistrar, Sink, TaintKind

_METHODS = ("get", "post", "put", "delete", "patch", "options", "head", "api_route", "websocket")


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class FastApiModels(ModelPlugin):
    name: ClassVar[str] = "fastapi-models"
    models: ClassVar[tuple[Model, ...]] = (
        *(EntryPoint(_sym(f"fastapi.FastAPI.{method}"), "http") for method in _METHODS),
        *(EntryPoint(_sym(f"fastapi.APIRouter.{method}"), "http") for method in _METHODS),
        RouteRegistrar(_sym("fastapi.FastAPI.add_api_route"), 1, "http"),
        RouteRegistrar(_sym("fastapi.APIRouter.add_api_route"), 1, "http"),
        Sink(_sym("fastapi.responses.HTMLResponse"), TaintKind.HTML),
        Sink(_sym("fastapi.responses.FileResponse"), TaintKind.PATH),
        Sink(_sym("fastapi.responses.RedirectResponse"), TaintKind.REDIRECT),
        Sink(_sym("starlette.responses.RedirectResponse"), TaintKind.REDIRECT),
    )
