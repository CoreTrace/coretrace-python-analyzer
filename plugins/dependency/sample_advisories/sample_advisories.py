"""A small, offline sample of published advisories (architecture §26).

This is a demonstration database: a handful of well-known CVEs with the APIs they
affect. A live OSV or GHSA feed belongs to a dedicated plugin.
"""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.dependency import Advisory
from coretrace_python.findings import Severity
from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class SampleAdvisories(ModelPlugin):
    name: ClassVar[str] = "sample-advisories"
    advisories: ClassVar[tuple[Advisory, ...]] = (
        Advisory(
            "CVE-2020-1747",
            "pyyaml",
            "<5.4",
            "yaml.load and full_load can execute arbitrary code from untrusted documents",
            Severity.CRITICAL,
            (_sym("yaml.load"), _sym("yaml.full_load"), _sym("yaml.unsafe_load")),
        ),
        Advisory(
            "CVE-2018-18074",
            "requests",
            "<2.20.0",
            "Authorization header is leaked on redirects to another host",
            Severity.HIGH,
            (_sym("requests.get"), _sym("requests.post"), _sym("requests.request"), _sym("requests.Session")),
        ),
        Advisory(
            "CVE-2020-28493",
            "jinja2",
            "<2.11.3",
            "regular expression denial of service in the urlize filter",
            Severity.MEDIUM,
            (_sym("jinja2.Environment"), _sym("jinja2.Template")),
        ),
        Advisory(
            "CVE-2021-33503",
            "urllib3",
            "<1.26.5",
            "regular expression denial of service when parsing authority in URLs",
            Severity.HIGH,
            (_sym("urllib3.PoolManager"), _sym("urllib3.request")),
        ),
        Advisory(
            "CVE-2023-30861",
            "flask",
            "<2.2.5",
            "session cookie may be leaked through caching proxies",
            Severity.HIGH,
            (_sym("flask.Flask"),),
        ),
    )
