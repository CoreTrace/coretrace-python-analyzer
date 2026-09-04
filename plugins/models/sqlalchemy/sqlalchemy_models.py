"""SQLAlchemy security models: raw SQL execution sinks.

Symbols follow the engine's call-chain rule: the result of calling a symbol denotes
that symbol, so ``create_engine(url).connect().execute`` is
``python.sqlalchemy.create_engine.connect.execute``.
"""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import Model, Sink, TaintKind

_EXECUTORS = (
    "sqlalchemy.create_engine",
    "sqlalchemy.create_engine.connect",
    "sqlalchemy.create_engine.begin",
    "sqlalchemy.engine.create_engine",
    "sqlalchemy.engine.create_engine.connect",
    "sqlalchemy.orm.Session",
    "sqlalchemy.orm.sessionmaker",
    "sqlalchemy.orm.scoped_session",
)


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class SqlAlchemyModels(ModelPlugin):
    name: ClassVar[str] = "sqlalchemy-models"
    models: ClassVar[tuple[Model, ...]] = tuple(
        Sink(_sym(f"{executor}.{method}"), TaintKind.SQL | TaintKind.CREDENTIAL)
        for executor in _EXECUTORS
        for method in ("execute", "exec_driver_sql", "scalar", "scalars")
    )
