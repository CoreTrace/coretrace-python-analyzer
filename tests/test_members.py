"""A ``Members`` model says what the attributes and items of a class's instances give.

Some libraries give objects by names the project chooses: a pymongo client gives the
database it is dotted or indexed with, a database gives a collection. Symbols follow
attribute paths, so those names used to end up in the symbol (``Client.shop.users.find``)
or, for an item, to vanish into the container's symbol (``Client.find``), and no model
could list them. A ``Members`` model describes the instances of a class:

- ``typed`` maps an attribute to the class of what it gives, called or not
  (``get_database``, or a ``db`` property);
- ``dynamic``, when set, is the class of every item and of every attribute outside
  ``defined`` and ``typed``.

Every path to a collection then denotes the collection class, the one an annotated
parameter denotes, and a single sink on ``Collection.find`` covers them all.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.analysis import AnalysisManager
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.interprocedural import CallGraphAnalysis, ExternalSymbol
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import (
    Members,
    SecurityModelRegistry,
    Sink,
    Source,
    TaintAnalysis,
    TaintKind,
)

CLIENT = SymbolId("python.docstore.Client")
DATABASE = SymbolId("python.docstore.database.Database")
COLLECTION = SymbolId("python.docstore.collection.Collection")
FIND = COLLECTION.attribute("find")
MEMBERS = (
    Members(CLIENT, DATABASE, defined=("close", "list_database_names"), typed=(("get_database", DATABASE),)),
    Members(
        DATABASE,
        COLLECTION,
        defined=("command", "list_collection_names"),
        typed=(("get_collection", COLLECTION), ("client", CLIENT)),
    ),
    # A collection gives its sub-collections by name.
    Members(COLLECTION, COLLECTION, defined=("delete_many", "find", "find_one", "insert_one", "name")),
    # Attributes typed without dynamic members, like Flask-PyMongo's ``db``.
    Members(SymbolId("python.docstore.flask.Store"), typed=(("db", DATABASE),)),
)


def manager_for(source_text: str, *models: object) -> AnalysisManager:
    registry = SecurityModelRegistry()
    registry.register(*MEMBERS, *models)  # type: ignore[arg-type]
    return engine.build_manager(build_hir(SourceManager().add_source("app.py", source_text)), registry)


def targets(source_text: str, function: str) -> list[SymbolId | None]:
    graph = manager_for(source_text).get(CallGraphAnalysis)
    return [s.target.symbol if isinstance(s.target, ExternalSymbol) else None for s in graph.sites(function)]


APP = (
    "import docstore\nfrom docstore.flask import Store\n\n"
    "def f(q):\n"
    "    client = docstore.Client()\n"
    "    store = Store()\n"
    "    return {call}\n"
)


@pytest.mark.parametrize(
    "call, symbol",
    [
        ("client.shop.users.find(q)", FIND),
        ("client['shop']['users'].find(q)", FIND),
        ("client.shop['users'].find(q)", FIND),
        ("client['shop'].users.find(q)", FIND),
        ("client.get_database('shop').get_collection('users').find(q)", FIND),
        ("client.shop.users.archive.find(q)", FIND),
        ("store.db.users.find(q)", FIND),
        ("client.shop.command(q)", DATABASE.attribute("command")),
        ("client.shop.client.close()", CLIENT.attribute("close")),
        ("client.close()", CLIENT.attribute("close")),
        # What a member method returns is no member: a document's ``str.find``.
        ("client.shop.users.find_one(q)['name'].find(q)", COLLECTION.attribute("find_one").attribute("find")),
    ],
)
def test_attributes_and_items_give_the_class_the_model_names(call: str, symbol: SymbolId) -> None:
    assert targets(APP.format(call=call), "f")[-1] == symbol


def test_module_level_names_give_the_same_classes() -> None:
    source = (
        "import docstore\n\n"
        "client = docstore.Client()\n"
        "db = client.shop\n"
        "users = db['users']\n"
        "orders = client.get_database('shop').orders\n\n"
        "def f(q):\n"
        "    users.find(q)\n"
        "    orders.find_one(q)\n"
        "    db.users.delete_many(q)\n"
    )

    assert targets(source, "f") == [FIND, COLLECTION.attribute("find_one"), COLLECTION.attribute("delete_many")]


def test_annotated_parameters_and_inherited_attributes_give_the_same_classes() -> None:
    source = (
        "import docstore\nfrom docstore.database import Database\n\n"
        "def f(db: Database, q):\n"
        "    return db.users.find(q)\n\n"
        "class Shop(docstore.Client):\n"
        "    def orders(self, q):\n"
        "        return self.shop.orders.find(q)\n"
    )

    assert targets(source, "f") == [FIND]
    assert targets(source, "Shop.orders") == [FIND]


def test_one_sink_on_the_member_class_covers_every_path() -> None:
    source = (
        "import docstore\n\n"
        "client = docstore.Client()\n"
        "db = client['shop']\n\n"
        "def by_attribute():\n    client.shop.users.find(input())\n\n"
        "def by_item():\n    db['users'].find(input())\n\n"
        "def by_getter():\n    client.get_database('shop').get_collection('users').find(input())\n"
    )
    manager = manager_for(
        source, Source(SymbolId("python.builtins.input"), "stdin"), Sink(FIND, TaintKind.NOSQL)
    )

    sinks = [
        (function.name, str(flow.sink.symbol))
        for function in manager.module.body
        if isinstance(function, nodes.Function)
        for flow in manager.get(TaintAnalysis, function).flows
    ]
    assert sinks == [("by_attribute", str(FIND)), ("by_item", str(FIND)), ("by_getter", str(FIND))]


def test_defined_names_are_kept_sorted_so_the_models_repr_is_stable() -> None:
    members = Members(CLIENT, DATABASE, defined=frozenset({"list_database_names", "close"}))  # type: ignore[arg-type]

    assert members.defined == ("close", "list_database_names")
    assert members == Members(CLIENT, DATABASE, defined=("list_database_names", "close"))


PLUGIN_MANIFEST = (
    'name = "docstore-models"\nversion = "1.0.0"\nplugin_api = ">=1,<2"\nrequires = []\n'
    'provides = ["model.docstore"]\n\n[entrypoint]\nmodule = "docstore_models"\nclass = "DocstoreModels"\n'
)
PLUGIN = '''
from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import Members, Model, Sink, TaintKind

CLIENT = SymbolId("python.docstore.Client")
DATABASE = SymbolId("python.docstore.database.Database")
COLLECTION = SymbolId("python.docstore.collection.Collection")


class DocstoreModels(ModelPlugin):
    name: ClassVar[str] = "docstore-models"
    models: ClassVar[tuple[Model, ...]] = (
        Members(CLIENT, DATABASE),
        Members(DATABASE, COLLECTION, defined=("command",)),
        Members(COLLECTION, COLLECTION, defined=("find",)),
        # Any rule shows the flow reaching the sink; SQL has one.
        Sink(COLLECTION.attribute("find"), TaintKind.SQL),
    )
'''


@pytest.mark.parametrize("jobs", [1, 2])
def test_a_plugin_models_members_in_a_project_analysis(tmp_path: Path, jobs: int) -> None:
    plugin = tmp_path / "plugins" / "docstore_models"
    plugin.mkdir(parents=True)
    (plugin / "plugin.toml").write_text(PLUGIN_MANIFEST, encoding="utf-8")
    (plugin / "docstore_models.py").write_text(PLUGIN, encoding="utf-8")
    root = tmp_path / "project"
    root.mkdir()
    for name in ("app.py", "admin.py"):
        (root / name).write_text(
            "import docstore\n\ndb = docstore.Client()['shop']\n\ndef run():\n    return db.users.find(input())\n",
            encoding="utf-8",
        )

    analysis = engine.analyze_project(root, [engine.BUNDLED_PLUGINS, tmp_path / "plugins"], jobs=jobs)

    found = sorted(
        (Path(str(f.span.source_id)).name, f.span.start_line) for f in analysis.findings if f.rule_id == "sql-injection"
    )
    assert found == [("admin.py", 6), ("app.py", 6)]
