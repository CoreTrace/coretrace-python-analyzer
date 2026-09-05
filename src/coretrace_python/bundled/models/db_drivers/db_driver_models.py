"""Database driver models: the statement argument of aiopg, asyncpg, psycopg2 and PyMySQL
query methods is a SQL sink; the parameter tuple or mapping is not a statement."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import Model, Sink, TaintKind

_STATEMENT_ONLY = ((TaintKind.SQL, (0,)),)
_CURSOR_METHODS = ("execute", "executemany", "mogrify")
_ASYNCPG_METHODS = ("execute", "executemany", "fetch", "fetchrow", "fetchval", "cursor")

# Every way a cursor is reached: through a connection object, an annotated class or a
# pool; the symbol derivation follows call chains, so ``connect().cursor().execute`` is
# ``connect.cursor.execute``.
_CURSORS = (
    "aiopg.connect.cursor",
    "aiopg.Connection.cursor",
    "aiopg.connection.Connection.cursor",
    "aiopg.Cursor",
    "aiopg.cursor.Cursor",
    "aiopg.create_pool.acquire.cursor",
    "aiopg.Pool.acquire.cursor",
    "aiopg.pool.Pool.acquire.cursor",
    "aiopg.create_pool.cursor",
    "aiopg.Pool.cursor",
    "psycopg2.connect.cursor",
    "psycopg2.extensions.connection.cursor",
    "psycopg2.extensions.cursor",
    "psycopg2.extras.DictCursor",
    "psycopg2.extras.RealDictCursor",
    "pymysql.connect.cursor",
    "pymysql.connections.Connection.cursor",
    "pymysql.Connection.cursor",
    "pymysql.cursors.Cursor",
    "pymysql.cursors.DictCursor",
)
_ASYNCPG_CONNECTIONS = (
    "asyncpg.connect",
    "asyncpg.Connection",
    "asyncpg.connection.Connection",
    "asyncpg.create_pool",
    "asyncpg.Pool",
    "asyncpg.pool.Pool",
    "asyncpg.create_pool.acquire",
    "asyncpg.Pool.acquire",
    "asyncpg.pool.Pool.acquire",
)


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class DbDriverModels(ModelPlugin):
    name: ClassVar[str] = "db-driver-models"
    models: ClassVar[tuple[Model, ...]] = (
        *(
            Sink(_sym(f"{cursor}.{method}"), TaintKind.SQL, _STATEMENT_ONLY)
            for cursor in _CURSORS
            for method in _CURSOR_METHODS
        ),
        *(
            Sink(_sym(f"{connection}.{method}"), TaintKind.SQL, _STATEMENT_ONLY)
            for connection in _ASYNCPG_CONNECTIONS
            for method in _ASYNCPG_METHODS
        ),
    )
