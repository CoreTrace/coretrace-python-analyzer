"""XML parsers of the standard library and lxml expand entities: a crafted document reads
local files or exhausts memory. ``defusedxml`` offers the same functions safely."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.analysis import AnyAnalysis
from coretrace_python.findings import Severity
from coretrace_python.interprocedural import CallGraphAnalysis
from coretrace_python.ir.ssa import SSAAnalysis
from coretrace_python.plugins import SymbolCallDetector
from coretrace_python.semantic.symbols import SymbolId

_PARSERS = (
    "xml.etree.ElementTree.parse", "xml.etree.ElementTree.fromstring", "xml.etree.ElementTree.iterparse",
    "xml.etree.ElementTree.XMLParser", "xml.etree.ElementTree.fromstringlist",
    "xml.dom.minidom.parse", "xml.dom.minidom.parseString",
    "xml.dom.pulldom.parse", "xml.dom.pulldom.parseString",
    "xml.sax.parse", "xml.sax.parseString", "xml.sax.make_parser",
    "xml.dom.expatbuilder.parse", "xml.dom.expatbuilder.parseString",
    "lxml.etree.parse", "lxml.etree.fromstring", "lxml.etree.XMLParser", "lxml.etree.iterparse",
    "lxml.etree.XML",
)


class UnsafeXmlPlugin(SymbolCallDetector):
    name: ClassVar[str] = "unsafe-xml"
    rule_id: ClassVar[str] = "unsafe-xml"
    requires: ClassVar[frozenset[AnyAnalysis]] = frozenset({SSAAnalysis, CallGraphAnalysis})
    symbols: ClassVar[frozenset[SymbolId]] = frozenset(SymbolId(f"python.{p}") for p in _PARSERS)
    severity: ClassVar[Severity] = Severity.MEDIUM
    message_template: ClassVar[str] = (
        "call to {symbol} parses XML with entity expansion enabled; use defusedxml"
    )
