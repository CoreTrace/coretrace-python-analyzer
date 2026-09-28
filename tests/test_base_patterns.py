"""Entry points by a pattern on the base class, with the parameters typed by their role.

A gRPC servicer subclasses a class generated per project, ``greeter_pb2_grpc.GreeterServicer``,
so no fixed symbol names it, and its RPC methods receive the client's message and a
``ServicerContext`` without a decorator or an annotation saying so. A ``BasePattern``
model matches the canonical symbol of a class's base against a regular expression, as
``NamedParameter`` matches parameter names, whatever the module's prefix and however
the base is imported, and says what the methods receive, by position after ``self``: a
parameter left untyped is attacker input of the model's kinds; one typed with a class
denotes that class, so a ``Source`` on one of its methods applies without the whole
object being tainted.

Only the RPC methods are entry points: those overriding a method the base defines when
the project holds the generated module, otherwise those taking exactly the parameters
the model lists. A utility method of the servicer is not an RPC. Inheritance identifies
a potential service; it does not prove the servicer is registered on a server.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from coretrace_python import engine
from coretrace_python.findings import Finding
from coretrace_python.plugins import ProjectContext, ProjectPlugin
from coretrace_python.source import SourceManager

MANIFEST = (
    'name = "grpc-test-models"\nversion = "1.0.0"\nplugin_api = ">=1,<2"\nrequires = []\n'
    'provides = ["model.grpc-test"]\n\n[entrypoint]\nmodule = "grpc_models"\nclass = "Grpc"\n'
)
PLUGIN = '''
from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import TEXT_KINDS, BasePattern, Model, Sink, Source, TaintKind

CONTEXT = SymbolId("python.grpc.ServicerContext")


class Grpc(ModelPlugin):
    name: ClassVar[str] = "grpc-test-models"
    models: ClassVar[tuple[Model, ...]] = (
        BasePattern(r"(?:^|\\.)\\w+_pb2_grpc\\.\\w+Servicer$", "grpc", parameters=(None, CONTEXT)),
        Source(CONTEXT.attribute("invocation_metadata"), "grpc", TEXT_KINDS),
        Sink(SymbolId("python.store.find"), TaintKind.NOSQL),
    )
'''
GENERATED = (
    "class GreeterServicer(object):\n"
    "    def SayHello(self, request, context):\n"
    "        raise NotImplementedError\n\n"
    "    def Stream(self, request_iterator, context):\n"
    "        raise NotImplementedError\n\n"
    "def add_GreeterServicer_to_server(servicer, server):\n"
    "    pass\n"
)
HEADER = "import os\nimport store\nfrom google.protobuf.json_format import MessageToDict\n"
IN_PROJECT = ("from app.proto import greeter_pb2_grpc", "greeter_pb2_grpc.GreeterServicer")
ABSENT = ("import greeter_pb2_grpc", "greeter_pb2_grpc.GreeterServicer")
SAY_HELLO = "    def SayHello(self, request, context):\n        os.system(request.name)\n"
LINE = 8


def plugins(tmp_path: Path) -> Path:
    plugin = tmp_path / "plugins" / "grpc_models"
    plugin.mkdir(parents=True, exist_ok=True)
    (plugin / "plugin.toml").write_text(MANIFEST, encoding="utf-8")
    (plugin / "grpc_models.py").write_text(PLUGIN, encoding="utf-8")
    return tmp_path / "plugins"


def project(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "project"
    for relative, text in {"app/__init__.py": "", "app/proto/__init__.py": "", **files}.items():
        (root / relative).parent.mkdir(parents=True, exist_ok=True)
        (root / relative).write_text(text, encoding="utf-8")
    return root


def servicer(base: tuple[str, str], body: str) -> str:
    base_import, name = base
    return f"{HEADER}{base_import}\n\nclass Greeter({name}):\n{body}"


def reported(findings: tuple[Finding, ...]) -> list[tuple[str, int, str]]:
    return sorted(
        (f.rule_id, f.span.start_line, f.metadata["source_label"])
        for f in findings
        if f.rule_id in ("command-injection", "nosql-injection")
    )


def analyze(tmp_path: Path, files: dict[str, str], **options: object) -> list[tuple[str, int, str]]:
    root = project(tmp_path, files)
    roots = [engine.BUNDLED_PLUGINS, plugins(tmp_path)]
    return reported(engine.analyze_project(root, roots, **options).findings)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- recognition


@pytest.mark.parametrize(
    "base",
    [
        IN_PROJECT,
        ("from app.proto import greeter_pb2_grpc as pb", "pb.GreeterServicer"),
        ("import app.proto.greeter_pb2_grpc as pb", "pb.GreeterServicer"),
        ("from app.proto.greeter_pb2_grpc import GreeterServicer", "GreeterServicer"),
        ("from app.proto.greeter_pb2_grpc import GreeterServicer as Base", "Base"),
    ],
    ids=["module", "module-alias", "import-as", "name", "name-alias"],
)
def test_a_class_whose_base_matches_the_pattern_receives_attacker_input(tmp_path: Path, base: tuple[str, str]) -> None:
    files = {"app/proto/greeter_pb2_grpc.py": GENERATED, "app/servicer.py": servicer(base, SAY_HELLO)}

    assert analyze(tmp_path, files) == [("command-injection", LINE, "grpc")]


@pytest.mark.parametrize(
    "first",
    ["logging.Handler", "LoggingMixin"],
    ids=["an-installed-class", "a-class-of-the-module"],
)
def test_a_servicer_with_another_base_before_the_generated_one_is_typed_all_the_same(tmp_path: Path, first: str) -> None:
    body = SAY_HELLO + "        os.system(dict(context.invocation_metadata())['x-user'])\n"
    module = (
        f"{HEADER}import logging\nfrom app.proto import greeter_pb2_grpc\n\n"
        "class LoggingMixin:\n"
        "    def log(self, message):\n"
        "        pass\n\n"
        f"class Greeter({first}, greeter_pb2_grpc.GreeterServicer):\n{body}"
    )
    files = {"app/proto/greeter_pb2_grpc.py": GENERATED, "app/servicer.py": module}

    assert analyze(tmp_path, files) == [("command-injection", LINE + 5, "grpc"), ("command-injection", LINE + 6, "grpc")]


def test_a_generated_module_absent_from_the_project_still_matches(tmp_path: Path) -> None:
    assert analyze(tmp_path, {"app/servicer.py": servicer(ABSENT, SAY_HELLO)}) == [("command-injection", LINE, "grpc")]


@pytest.mark.parametrize(
    "base",
    [
        ("from app.proto import greeter_pb2", "greeter_pb2.GreeterServicer"),
        ("from app.proto import greeter_pb2_grpc", "greeter_pb2_grpc.GreeterStub"),
        ("from app import services", "services.GreeterServicer"),
        ("import greeter_pb2_grpc", "greeter_pb2_grpc.GreeterServicerMixin"),
    ],
    ids=["not-a-grpc-module", "a-stub", "a-project-class-named-servicer", "a-name-going-on-after-servicer"],
)
def test_a_base_outside_the_pattern_is_no_entry_point(tmp_path: Path, base: tuple[str, str]) -> None:
    files = {
        "app/proto/greeter_pb2.py": "class GreeterServicer:\n    pass\n",
        "app/proto/greeter_pb2_grpc.py": GENERATED + "\nclass GreeterStub:\n    pass\n\nclass GreeterServicerMixin:\n    pass\n",
        "app/services.py": "class GreeterServicer:\n    def SayHello(self, request, context):\n        pass\n",
        "app/servicer.py": servicer(base, SAY_HELLO),
    }

    assert analyze(tmp_path, files) == []


def test_async_methods_and_client_streams_are_covered(tmp_path: Path) -> None:
    body = (
        "    async def SayHello(self, request, context):\n"
        "        os.system(request.name)\n\n"
        "    async def Stream(self, request_iterator, context):\n"
        "        async for message in request_iterator:\n"
        "            os.system(message.name)\n"
    )
    files = {"app/proto/greeter_pb2_grpc.py": GENERATED, "app/servicer.py": servicer(IN_PROJECT, body)}

    assert analyze(tmp_path, files) == [("command-injection", LINE, "grpc"), ("command-injection", LINE + 4, "grpc")]


def test_a_sync_client_stream_is_covered(tmp_path: Path) -> None:
    body = (
        "    def Stream(self, request_iterator, context):\n"
        "        for message in request_iterator:\n"
        "            os.system(message.name)\n"
    )
    files = {"app/proto/greeter_pb2_grpc.py": GENERATED, "app/servicer.py": servicer(IN_PROJECT, body)}

    assert analyze(tmp_path, files) == [("command-injection", LINE + 1, "grpc")]


@pytest.mark.parametrize("jobs", [1, 2])
def test_modules_analysed_in_other_processes_recognise_the_servicer(tmp_path: Path, jobs: int) -> None:
    body = SAY_HELLO + "        os.system(dict(context.invocation_metadata())['x-user'])\n"
    files = {
        "app/proto/greeter_pb2_grpc.py": GENERATED,
        "app/servicer.py": servicer(IN_PROJECT, body),
        "app/other.py": "X = 1\n",
    }

    expected = [("command-injection", LINE, "grpc"), ("command-injection", LINE + 1, "grpc")]
    assert analyze(tmp_path, files, jobs=jobs) == expected


def test_a_decorator_matching_the_pattern_is_no_base(tmp_path: Path) -> None:
    module = (
        f"{HEADER}import greeter_pb2_grpc\n\n"
        "@greeter_pb2_grpc.GreeterServicer\n"
        "def run(request, context, extra):\n"
        "    os.system(request)\n"
    )

    assert analyze(tmp_path, {"app/run.py": module}) == []


def test_a_single_file_check_recognises_the_servicer_too(tmp_path: Path) -> None:
    source = SourceManager().add_source("servicer.py", servicer(ABSENT, SAY_HELLO))

    findings = engine.analyze_file(source, [engine.BUNDLED_PLUGINS, plugins(tmp_path)]).findings

    assert reported(findings) == [("command-injection", LINE, "grpc")]


# --------------------------------------------------------------------------- which methods


def test_only_the_methods_the_base_defines_are_rpcs_when_the_project_holds_it(tmp_path: Path) -> None:
    body = (
        "    def SayHello(self, request, context):\n"
        "        return self._greet(request.name, context)\n\n"
        "    def _greet(self, name, context):\n"
        "        os.system(name)\n\n"
        "    def render(self, request, context):\n"
        "        os.system(request.name)\n"
    )
    files = {"app/proto/greeter_pb2_grpc.py": GENERATED, "app/servicer.py": servicer(IN_PROJECT, body)}

    # ``_greet`` and ``render`` are no RPCs: the only flow is the one ``SayHello`` passes
    # to ``_greet``, reported at the call.
    assert analyze(tmp_path, files) == [("command-injection", LINE, "grpc")]


def test_a_utility_method_of_another_arity_gets_no_typed_parameter(tmp_path: Path) -> None:
    body = (
        "    def SayHello(self, request, context):\n"
        "        return None\n\n"
        "    def _audit(self, name, ctx, extra):\n"
        "        os.system(dict(ctx.invocation_metadata())['x-user'])\n"
    )
    files = {"app/proto/greeter_pb2_grpc.py": GENERATED, "app/servicer.py": servicer(IN_PROJECT, body)}

    # ``ctx`` is not a context the signature types: ``_audit`` takes three parameters.
    assert analyze(tmp_path, files) == []


def test_without_the_generated_module_the_rpc_signature_decides(tmp_path: Path) -> None:
    body = (
        "    def SayHello(self, request, context):\n"
        "        os.system(request.name)\n\n"
        "    def _load(self, name):\n"
        "        os.system(name)\n\n"
        "    def _log(self, message, level):\n"
        "        os.system(message)\n"
    )
    files = {"app/servicer.py": servicer(ABSENT, body)}

    # Two parameters after ``self`` is the RPC signature; ``_log`` has it too, and
    # without the generated module the engine cannot tell it from an RPC.
    assert analyze(tmp_path, files) == [("command-injection", LINE, "grpc"), ("command-injection", LINE + 6, "grpc")]


def test_a_project_plugin_sees_the_rpc_methods_as_grpc_entry_points(tmp_path: Path) -> None:
    seen: dict[str, str | None] = {}

    class Peek(ProjectPlugin):
        name = "peek"

        def analyze_project(self, ctx: ProjectContext) -> tuple[Finding, ...]:
            for module in ctx.modules:
                for function in ctx.functions(module):
                    seen[f"{module}:{function.name}"] = function.entry_point
            return ()

    body = SAY_HELLO + "\n    def _greet(self, name, context):\n        pass\n"
    files = {"app/proto/greeter_pb2_grpc.py": GENERATED, "app/servicer.py": servicer(IN_PROJECT, body)}
    root = project(tmp_path, files)

    engine.analyze_project(root, [engine.BUNDLED_PLUGINS, plugins(tmp_path)], plugins=[Peek()])

    assert seen["app.servicer:Greeter.SayHello"] == "grpc"
    assert seen["app.servicer:Greeter._greet"] is None
    assert seen["app.proto.greeter_pb2_grpc:GreeterServicer.SayHello"] is None


# --------------------------------------------------------------------------- what they receive


def test_the_message_carries_every_kind_including_its_dict_conversion(tmp_path: Path) -> None:
    body = (
        "    def SayHello(self, request, context):\n"
        "        store.find(MessageToDict(request))\n"
        "        store.find(request.filters)\n"
        "        store.find({'name': request.name})\n"
    )
    files = {"app/proto/greeter_pb2_grpc.py": GENERATED, "app/servicer.py": servicer(IN_PROJECT, body)}

    assert analyze(tmp_path, files) == [
        ("nosql-injection", LINE, "grpc"),
        ("nosql-injection", LINE + 1, "grpc"),
        ("nosql-injection", LINE + 2, "grpc"),
    ]


def test_the_context_gives_client_metadata_as_text_and_nothing_else(tmp_path: Path) -> None:
    body = (
        "    def SayHello(self, request, context):\n"
        "        for key, value in context.invocation_metadata():\n"
        "            os.system(value)\n"
        "        store.find({'key': dict(context.invocation_metadata())})\n"
        "        os.system(context.peer())\n"
        "        os.system(str(context))\n"
    )
    files = {"app/proto/greeter_pb2_grpc.py": GENERATED, "app/servicer.py": servicer(IN_PROJECT, body)}

    # The metadata is text, so no ``nosql-injection``; ``peer()`` is transport
    # information, and the context itself is not attacker input.
    assert analyze(tmp_path, files) == [("command-injection", LINE + 1, "grpc")]
