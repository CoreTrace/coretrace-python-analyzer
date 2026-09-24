"""A sink call made safe by one of its arguments: ``yaml.load(data, Loader=SafeLoader)``.

A ``SafeArgument`` model says that a call to a sink whose argument (by keyword, or at a
position) denotes one of some values is not a sink for some kinds. Only a value the
call gives explicitly makes it safe: an absent argument, another value, a variable or
unpacked arguments leave the sink as it is, so a doubt is always reported.
"""

from __future__ import annotations

import pytest

from coretrace_python import engine
from coretrace_python.analysis import AnalysisManager
from coretrace_python.findings import Finding
from coretrace_python.frontend import build_hir
from coretrace_python.hir import nodes
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceManager
from coretrace_python.taint import (
    ModelTable,
    SafeArgument,
    SecurityModelAnalysis,
    SecurityModelRegistry,
    Sink,
    Source,
    TaintAnalysis,
    TaintKind,
)

PLUGINS = engine.BUNDLED_PLUGINS
SAFE = SafeArgument(SymbolId("python.db.load"), "mode", ("python.db.SAFE",), position=1, kinds=TaintKind.CODE)


def models(*extra: Sink) -> ModelTable:
    registry = SecurityModelRegistry()
    registry.register(
        Source(SymbolId("python.builtins.input"), "stdin"),
        Sink(SymbolId("python.db.load"), TaintKind.CODE),
        SAFE,
        *extra,
    )
    return registry.freeze()


def flows(source_text: str, table: ModelTable) -> list[tuple[str, TaintKind]]:
    module = build_hir(SourceManager().add_source("safe.py", source_text))
    manager = AnalysisManager(module)
    manager.register(*engine.ALL_ANALYSES)
    manager.provide(SecurityModelAnalysis, table)
    run = next(s for s in module.body if isinstance(s, nodes.Function) and s.name == "run")
    return [(str(flow.sink.symbol), flow.kinds) for flow in manager.get(TaintAnalysis, run).flows]


# --------------------------------------------------------------------------- the model


def test_safe_arguments_are_models_of_the_table() -> None:
    table = models()

    assert table.safe_argument(SymbolId("python.db.load")) == SAFE
    assert table.safe_argument(SymbolId("python.os.system")) is None


@pytest.mark.parametrize(
    "call, reported",
    [
        ("db.load(input(), mode=db.SAFE)", False),
        ("db.load(input(), db.SAFE)", False),
        ("db.load(input())", True),
        ("db.load(input(), mode=db.UNSAFE)", True),
        ("db.load(input(), mode=choice)", True),
        ("db.load(input(), **options)", True),
    ],
)
def test_only_a_safe_value_given_explicitly_takes_the_kinds_off_the_sink(call: str, reported: bool) -> None:
    found = flows(f"import db\n\ndef run(choice, options):\n    {call}\n", models())

    assert bool(found) is reported


def test_a_safe_argument_holds_through_a_callee() -> None:
    source = "import db\n\ndef run():\n    load(input())\n\ndef load(text):\n    return db.load(text, db.SAFE)\n"

    assert flows(source, models()) == []


def test_a_safe_argument_only_takes_off_its_own_kinds() -> None:
    found = flows("import db\n\ndef run():\n    db.load(input(), db.SAFE)\n", models(Sink(SymbolId("python.db.load"), TaintKind.COMMAND)))

    assert found == [("python.db.load", TaintKind.COMMAND)]


# --------------------------------------------------------------------------- yaml.load


def deserialization(loader: str | None) -> list[Finding]:
    call = f"yaml.load(request.data{'' if loader is None else ', ' + loader})"
    source = f"import yaml\nfrom flask import request\n\ndef read():\n    return {call}\n"
    findings = engine.check(SourceManager().add_source("app.py", source), [PLUGINS])
    return [f for f in findings if f.rule_id == "insecure-deserialization"]


@pytest.mark.parametrize(
    "loader",
    ["Loader=yaml.SafeLoader", "Loader=yaml.CSafeLoader", "yaml.loader.SafeLoader", "Loader=yaml.cyaml.CBaseLoader"],
)
def test_yaml_load_with_a_safe_loader_is_not_an_insecure_deserialization(loader: str) -> None:
    assert deserialization(loader) == []


@pytest.mark.parametrize("loader", [None, "yaml.Loader", "Loader=yaml.FullLoader", "Loader=yaml.UnsafeLoader"])
def test_yaml_load_with_any_other_loader_still_is(loader: str | None) -> None:
    assert len(deserialization(loader)) == 1


def several_documents(call: str) -> list[Finding]:
    source = f"import yaml\nfrom flask import request\n\ndef read():\n    return list({call})\n"
    findings = engine.check(SourceManager().add_source("app.py", source), [PLUGINS])
    return [f for f in findings if f.rule_id == "insecure-deserialization"]


@pytest.mark.parametrize("function", ["load_all", "full_load_all", "unsafe_load_all"])
def test_the_loaders_of_several_documents_are_deserialization_sinks_too(function: str) -> None:
    assert len(several_documents(f"yaml.{function}(request.data)")) == 1


@pytest.mark.parametrize("call", ["yaml.load_all(request.data, Loader=yaml.SafeLoader)", "yaml.safe_load_all(request.data)"])
def test_the_safe_ways_to_load_several_documents_are_not(call: str) -> None:
    assert several_documents(call) == []
