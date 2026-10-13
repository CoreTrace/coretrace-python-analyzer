"""XML parsers of the standard library and of lxml, each reported for what it risks.

The standard library's parsers run on Expat, which never reads a local file or opens a
connection, but expands the entities a document declares: a crafted document can exhaust
memory with Expat older than 2.7.2, a fact of run time (``pyexpat.EXPAT_VERSION``). lxml
resolves external entities by default before 5.0, and in ``iterparse`` and
``ETCompatXMLParser`` before 6.1 (CVE-2026-41066), which lets a crafted document read
local files; ``resolve_entities=True`` does so whatever the version, ``False`` or
``'internal'`` never. ``defusedxml`` offers the same functions safely. A document the
project wrote itself, a string constant or a module-level string bound once, is no
attacker's: its finding is kept at low confidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from coretrace_python.abstract.strings import ModuleStringsAnalysis
from coretrace_python.analysis import AnyAnalysis
from coretrace_python.findings import Confidence, Severity
from coretrace_python.interprocedural import CallGraphAnalysis
from coretrace_python.ir.model import Call, Constant, Global, Instruction, Value
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.plugins import CallReport, PluginContext, SymbolCallDetector
from coretrace_python.semantic.symbols import SymbolId


def _symbols(*paths: str) -> frozenset[SymbolId]:
    return frozenset(SymbolId(f"python.{path}") for path in paths)


_STANDARD_LIBRARY = _symbols(
    "xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring", "xml.etree.ElementTree.iterparse",
    "xml.etree.ElementTree.XMLParser", "xml.etree.ElementTree.fromstringlist",
    "xml.dom.minidom.parse", "xml.dom.minidom.parseString",
    "xml.dom.pulldom.parse", "xml.dom.pulldom.parseString",
    "xml.sax.parse", "xml.sax.parseString", "xml.sax.make_parser",
    "xml.dom.expatbuilder.parse", "xml.dom.expatbuilder.parseString",
)
_LXML = _symbols("lxml.etree.parse", "lxml.etree.fromstring", "lxml.etree.XMLParser", "lxml.etree.XML")
# Their default kept ``resolve_entities=True`` until lxml 6.1 (CVE-2026-41066).
_LXML_UNTIL_6_1 = _symbols("lxml.etree.iterparse", "lxml.etree.ETCompatXMLParser")
# A keyword that is not a constant: its value is unknown.
_UNKNOWN = object()


def _resolve_entities(call: Call, defs: Mapping[Value, Instruction]) -> object:
    """The constant ``resolve_entities=`` of ``call``, ``None`` when it is not passed."""

    for name, value in call.keywords:
        if name == "resolve_entities":
            made = defs.get(value)
            return made.value if isinstance(made, Constant) else _UNKNOWN
    return None


class UnsafeXmlPlugin(SymbolCallDetector):
    name: ClassVar[str] = "unsafe-xml"
    rule_id: ClassVar[str] = "unsafe-xml"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({SSAAnalysis, CallGraphAnalysis, ModuleStringsAnalysis})
    symbols: ClassVar[frozenset[SymbolId]] = _STANDARD_LIBRARY | _LXML | _LXML_UNTIL_6_1
    severity: ClassVar[Severity] = Severity.MEDIUM
    message_template: ClassVar[str] = "call to {symbol} parses XML unsafely; use defusedxml"

    def accepts(self, call: Call, symbol: SymbolId, defs: Mapping[Value, Instruction]) -> bool:
        # ``resolve_entities`` is an lxml option; the standard library has none.
        return _resolve_entities(call, defs) not in (False, "internal")

    def describe(
        self, ctx: PluginContext, call: Call, symbol: SymbolId, defs: Mapping[Value, Instruction]
    ) -> CallReport:
        if symbol in _STANDARD_LIBRARY:
            risk = "expands the entities a document declares, which can exhaust memory with Expat older than 2.7.2"
            advice = "use defusedxml"
        elif _resolve_entities(call, defs) is True:
            risk = "resolves external entities (resolve_entities=True), which lets a crafted document read local files"
            advice = "use defusedxml"
        elif symbol in _LXML_UNTIL_6_1:
            risk = (
                "resolves external entities by default before lxml 6.1 (CVE-2026-41066), "
                "which lets a crafted document read local files"
            )
            advice = "use defusedxml or resolve_entities=False"
        else:
            risk = "resolves external entities by default before lxml 5.0, which lets a crafted document read local files"
            advice = "use defusedxml"
        confidence = Confidence.LOW if self.written_by_the_project(ctx, call, defs) else self.confidence
        return CallReport(f"call to {symbol} {risk}; {advice}", confidence)

    def written_by_the_project(self, ctx: PluginContext, call: Call, defs: Mapping[Value, Instruction]) -> bool:
        """Whether the document ``call`` parses, its first argument, is a string constant
        or a module-level name bound once to one."""

        if not call.arguments:
            return False
        made = defs.get(call.arguments[0])
        if isinstance(made, Constant):
            return isinstance(made.value, str | bytes)
        return isinstance(made, Global) and made.name in ctx.get(ModuleStringsAnalysis)
