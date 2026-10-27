"""Django templates that escape everything they render (architecture §17).

``render_to_string(name, context)`` returns HTML in which autoescaping escaped every
variable, unless the template says otherwise. The engine does not render templates; it
reads them, and establishes that a template escapes only when nothing in it, or in what
it extends or includes, can output data unescaped:

- no ``|safe`` or ``|safeseq``, no ``{% autoescape off %}``, and no tag, filter or tag
  library beyond Django's own, whose output a custom one could mark safe;
- no variable where HTML escaping does not protect it: in a ``<script>`` or ``<style>``
  block, an event handler, a ``style`` or ``srcdoc`` attribute, a URL attribute whose
  value does not start with a fixed relative or ``http(s)`` prefix, an unquoted
  attribute, an attribute or a tag name, including in such a block or tag the template
  leaves open, which once included runs into the markup that follows;
- no include of a template that ends inside a ``<script>`` or ``<style>`` block, a tag
  or an end tag, which the markup after the include then continues;
- none of this either once the page is put together as Django renders it, its blocks
  and includes in place (``_Composition``): what a block or an include puts inside a
  construct of another file is read there (#273);
- no Python file of the project turning autoescaping off.

A comment holding template tags may end at any of them, an include there closing it or a
condition around its ``<!--`` leaving it out, or run to its close when they render
nothing: the markup after its first tag is read, and must be in HTML data wherever the
other readings resume (#278).

Templates are found under the project's ``templates`` directories, by their path below
one. A template the engine cannot find — named by an expression, under a ``DIRS`` entry
of another name, shipped by an installed package — or cannot read is never assumed to
escape.

A template applying a filter of Django's own libraries calls the function behind it
whenever it is rendered, though no Python call names that function: ``{{ bio|striptags }}``
calls ``django.template.defaultfilters.striptags``. Every template found counts, whether
or not a Python call names it, since a class-based view renders its ``template_name``
inside Django. A template the engine cannot read may call any filter; the engine says
where the project names one.

A project tag library, a module of a ``templatetags`` directory, replaces a filter of
that name in every template loading it before applying the filter, as Django's parser
does: ``{% load custom %}{{ bio|striptags }}`` calls the project's ``striptags`` when
``custom.py`` registers one, a later load overrides an earlier one, and
``{% load striptags from custom %}`` selects. The engine reads what a library registers
on its ``register`` with the semantic layers, and where it cannot tell — no such library,
a file it cannot read or understand, several apps giving the name and disagreeing — the
filter is neither the built-in nor certainly replaced: no call is claimed, and the load
is listed among what the engine could not read. ``OPTIONS["builtins"]`` and
``OPTIONS["libraries"]`` of the settings are not read.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from collections import deque
from collections.abc import Callable, Container, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import ClassVar, NamedTuple, TypeAlias

from coretrace_python.analysis import Analysis, AnalysisContext
from coretrace_python.frontend import HIRBuildError, ParseError, build_hir
from coretrace_python.hir import nodes
from coretrace_python.hir.visitors import Node, children
from coretrace_python.interprocedural import (
    CallGraph,
    ExternalSymbol,
    TemplateFilter,
    discover_files,
)
from coretrace_python.semantic.imports import ImportResolutionError, analyze_imports
from coretrace_python.semantic.scopes import (
    BindingKind,
    ResolutionKind,
    ScopeError,
    ScopeId,
    ScopeTable,
    analyze_scopes,
)
from coretrace_python.semantic.symbols import SymbolId, analyze_symbols
from coretrace_python.source import SourceId, SourceManager, SourceSpan
from coretrace_python.taint.models import ModelTable

TEMPLATES_DIRECTORY = "templates"
TEMPLATETAGS_DIRECTORY = "templatetags"

_OUTPUT, _TAG, _URL = "\x00", "\x01", "/u"
# Where a page puts the markup of an include it cannot put in place: a name several files
# have, which Django resolves through loaders the engine does not read.
_INSERTED = "\x02"
_SYNTAX = re.compile(r"{{(.*?)}}|{%(.*?)%}|{#.*?#}", re.DOTALL)
_AUTOESCAPE_OFF = re.compile(r"""["']autoescape["']\s*:\s*False|\bautoescape\s*=\s*False""")

# Django's own libraries and tags.
_LIBRARIES = frozenset({"static", "i18n", "l10n", "tz", "cache", "humanize"})
_TAGS = frozenset(
    {
        "load", "extends", "include", "block", "endblock", "if", "elif", "else", "endif",
        "for", "empty", "endfor", "with", "endwith", "ifchanged", "endifchanged", "spaceless",
        "endspaceless", "filter", "endfilter", "autoescape", "endautoescape", "csrf_token",
        "now", "lorem", "widthratio", "templatetag", "regroup", "resetcycle", "url", "static",
        "get_static_prefix", "get_media_prefix", "firstof", "cycle", "trans", "translate",
        "blocktrans", "blocktranslate", "endblocktrans", "endblocktranslate", "plural",
        "get_current_language", "get_current_language_bidi", "get_available_languages",
        "get_language_info", "get_language_info_list", "language", "endlanguage", "localize",
        "endlocalize", "localtime", "endlocaltime", "timezone", "endtimezone",
        "get_current_timezone", "cache", "endcache",
    }
)
# Tags that print a value: checked where they stand, like a variable.
_PRINTING = frozenset({"firstof", "cycle", "trans", "translate"})
# Where Django defines the function behind each filter of its own libraries, by module;
# ``name:function`` for a filter registered under another name than its function's.
_FILTER_MODULES = {
    "django.template.defaultfilters": (
        "add addslashes capfirst center cut date default default_if_none dictsort dictsortreversed "
        "divisibleby escape:escape_filter escapejs:escapejs_filter escapeseq filesizeformat first "
        "floatformat force_escape get_digit iriencode join json_script last length length_is "
        "linebreaks:linebreaks_filter linebreaksbr linenumbers ljust lower make_list "
        "phone2numeric:phone2numeric_filter pluralize pprint random rjust safe safeseq "
        "slice:slice_filter slugify stringformat striptags time timesince:timesince_filter "
        "timeuntil:timeuntil_filter title truncatechars truncatechars_html truncatewords "
        "truncatewords_html unordered_list upper urlencode urlize urlizetrunc wordcount wordwrap yesno"
    ),
    "django.templatetags.i18n": "language_bidi language_name language_name_local language_name_translated",
    "django.templatetags.l10n": "localize unlocalize",
    "django.templatetags.tz": "localtime timezone:do_timezone utc",
    "django.contrib.humanize.templatetags.humanize": "apnumber intcomma intword naturalday naturaltime ordinal",
}
# The function behind each filter of Django's own libraries, which a template applying
# the filter calls.
FILTER_FUNCTIONS: Mapping[str, SymbolId] = MappingProxyType(
    {
        name: SymbolId(f"python.{module}.{function or name}")
        for module, filters in _FILTER_MODULES.items()
        for name, _, function in (entry.partition(":") for entry in filters.split())
    }
)
# Every filter but ``safe`` and ``safeseq`` escapes its input, or returns it for
# autoescaping to escape, when autoescaping is on.
_FILTERS = frozenset(FILTER_FUNCTIONS) - {"safe", "safeseq"}
# The class a project tag library binds ``register`` to, by either of its paths, and
# its methods registering tags, which register no filter.
_LIBRARY_CLASSES = frozenset(SymbolId(f"python.django.template.{p}") for p in ("Library", "library.Library"))
_TAG_REGISTRARS = frozenset({"tag", "tag_function", "simple_tag", "simple_block_tag", "inclusion_tag"})

_URL_ATTRIBUTES = frozenset(
    {
        "href", "src", "action", "formaction", "poster", "background", "cite", "data",
        "srcset", "ping", "manifest", "longdesc", "usemap", "codebase", "classid", "archive",
        "profile", "lowsrc", "dynsrc", "icon", "xlink:href",
    }
)
# A relative path (not ``//host``), a fragment, a query, or an http(s) URL whose host is
# fixed: no scheme such as ``javascript:`` can follow.
_SAFE_URL_PREFIX = re.compile(r"(?:/(?!/)|\.{1,2}/|[#?]|https?://[^/?#\x00\x01]+[/?#])")
_QUOTED = r"\"[^\"]*\"|'[^']*'"
# A start tag read as the HTML tokenizer reads one: the tag name runs to whitespace, ``/``
# or ``>``; between attributes, whitespace and a stray ``/`` are skipped; an attribute
# name, which may begin with ``=``, runs to whitespace, ``/``, ``>`` or ``=``; a value
# follows ``=``, quoted, or running to whitespace or ``>``. Each token is told apart by
# its first character, so matching is linear, where splitting runs between attributes
# took exponential time (#263). A tag the text ends in before its ``>`` still matches,
# to the end: a template may be included before more markup, which the tag then runs
# into, so its attributes are checked like any other's. A value that opens a quote
# stays quoted to the matching quote or, for the same reason, to the end of the text: it
# is never read again as an unquoted value.
_ATTRIBUTE_NAME = r"(?:=[^\s/>=]*+|[^\s/>=]++)"
_ATTRIBUTE_VALUE = r"(?:\"[^\"]*+(?:\"|\Z)|'[^']*+(?:'|\Z)|[^\s>]*+)"
_ATTRIBUTE = re.compile(rf"({_ATTRIBUTE_NAME})(?:\s*+=\s*+({_ATTRIBUTE_VALUE}))?")
_START_TAG = re.compile(rf"<([A-Za-z][^\s/>]*+)((?:[\s/]++|{_ATTRIBUTE_NAME}(?:\s*+=\s*+{_ATTRIBUTE_VALUE})?)*+)(>)?")
# A script or style block and an end tag the text leaves open run to its end as well, for
# the same reason (#272); their last group, like the start tag's, is then empty or None.
# Only ``script`` and ``style`` themselves: a tag name runs to whitespace, ``/`` or ``>``,
# so ``<style-switcher>`` is another element, whose content is markup.
_RAW_TEXT = re.compile(r"<(script|style)(?=[\s/>])[^>]*+>(.*?)(</\1\s*>|\Z)", re.DOTALL | re.IGNORECASE)
_END_TAG = re.compile(r"</[A-Za-z][^>]*+(>)?")
# ``-->``, ``--!>``, or the ``>`` that ends ``<!-->`` and ``<!--->`` at once.
_COMMENT_END = re.compile(r"--!?>")
# ``<{{ name }}`` or ``</ {{ name }}``: the variable would name a tag.
_NAMED_BY_OUTPUT = re.compile(rf"<[/ \t\n]*{_OUTPUT}")
# What an inserted markup could complete into a tag, an end tag or a comment: ``<``,
# ``</`` or ``<!`` and ``<!-``; before a marker, or at the end of a text.
_OPENER = r"<(?:[/ \t\n]*|!-?)"
_OPENED_BY_INSERTION = re.compile(rf"{_OPENER}{_INSERTED}")
_ENDING_OPENER = re.compile(rf"{_OPENER}\Z")
# Django's filter expressions: a constant or a variable, then filters, each with an
# optional argument, the way ``django.template.base.FilterExpression`` reads them.
_STRING = r"\"[^\"\\]*(?:\\.[^\"\\]*)*\"|'[^'\\]*(?:\\.[^'\\]*)*'"
_OPERAND = rf"{_STRING}|_\((?:{_STRING})\)|[\w.]+|[-+.]?\d[\d.e]*"
_HEAD = re.compile(rf"\s*({_OPERAND})?")
_FILTER = re.compile(rf"\s*\|\s*(\w+)(?::({_OPERAND}))?")
_TOKEN = re.compile(rf"(?:[^\s\"']+|{_STRING})+")
_BINDING = re.compile(r"(\w+)=")
# A variable with its first attribute: what a context entry holds, or what the request
# the request context processor adds gives (``request.GET``).
_VARIABLE = re.compile(r"([A-Za-z_]\w*)(?:\.(\w+))?")
_LITERALS = frozenset({"True", "False", "None"})
# The variable a block renders to keep the parent's content, as ``_chain`` reads it.
_BLOCK_SUPER = "block.super"
# The variable ``block``, which Django binds inside a block to the block itself: named
# anywhere else than in a bare ``{{ block.super }}``, it may give the parent's markup,
# marked safe, through a filter such as ``escape`` or ``default`` or through an alias
# (``{% with parent=block %}{{ parent.super }}``). A name such as Handlebars'
# ``@partial-block`` is not it.
_BLOCK_VARIABLE = re.compile(r"(?<![\w.@-])block(?![\w-])")

REQUEST_PROCESSOR = "django.template.context_processors.request"
_DJANGO_ENGINE = "django.template.backends.django.DjangoTemplates"
_ENGINES_SETTING = "TEMPLATES"


def escaped_templates(root: Path) -> frozenset[str]:
    """The names of the templates under ``root`` that escape every variable they render
    (``template_escaping``)."""

    return template_escaping(root).escaped


class TemplateEscaping(NamedTuple):
    """The names of the templates established to escape, and the pages the engine could
    not put together to establish it, as entries of the templates it could not read."""

    escaped: frozenset[str]
    unread: tuple[str, ...] = ()


def template_escaping(root: Path) -> TemplateEscaping:
    """The names of the templates under ``root`` that escape every variable they render,
    as ``render_to_string`` names them (their path below a ``templates`` directory). A
    template including one that ends inside a script or style block, a tag or an end tag
    is not among them: the markup after its include continues that construct. A
    template extending another renders it, and ends where it ends. Each file is read on
    its own, then the page it renders is put together and read too (``_Composition``):
    what a block or an include puts inside a construct of another file is read there."""

    found: dict[str, list[Path]] = {}
    for path in discover_files(root):
        if path.suffix == ".py" and _AUTOESCAPE_OFF.search(_read(path)):
            return TemplateEscaping(frozenset())
        for name in _names(path.relative_to(root).parts):
            found.setdefault(name, []).append(path)
    parsed = {path: _parse_file(path) for paths in found.values() for path in paths}
    composition = _Composition(found, parsed)
    local: dict[str, bool] = {}
    requires: dict[str, set[str]] = {}
    extends: dict[str, set[str]] = {}
    includes: dict[str, set[str]] = {}
    open_ended: set[str] = set()
    # The names a page inserts (``_INSERTED``), and those whose every file renders a page
    # ending in HTML data, as an inserted markup must.
    inserting: dict[str, set[str]] = {}
    settled: set[str] = set()
    for name, paths in found.items():
        verdicts = [_verdict(parsed[path]) for path in paths]
        pages = [composition.page(path) for path in paths]
        readings = [
            [_read_markup(markup) for markup in page.markups] if page is not None else [_NOT_READ] for page in pages
        ]
        local[name] = all(verdict.escapes for verdict in verdicts) and all(r.escapes for rs in readings for r in rs)
        inserting[name] = {inserted for page in pages if page is not None for inserted in page.inserted}
        if all(r.settled for rs in readings for r in rs):
            settled.add(name)
        requires[name] = {needed for verdict in verdicts for needed in verdict.extends | verdict.includes}
        extends[name] = {extended for verdict in verdicts for extended in verdict.extends}
        includes[name] = {included for verdict in verdicts for included in verdict.includes}
        if any(verdict.open_end for verdict in verdicts):
            open_ended.add(name)
    while grown := {name for name, extended in extends.items() if extended & open_ended} - open_ended:
        open_ended |= grown
    escaped = {
        name for name, safe in local.items() if safe and not includes[name] & open_ended and inserting[name] <= settled
    }
    changed = True
    while changed:
        kept = {name for name in escaped if requires[name] <= escaped}
        changed = kept != escaped
        escaped = kept
    unread = [
        *(f"{path.relative_to(root).as_posix()}, {_TOO_LARGE}" for path in composition.too_large),
        *(f"{path.relative_to(root).as_posix()}, {_TOO_MANY}" for path in composition.too_many),
    ]
    return TemplateEscaping(frozenset(escaped), tuple(sorted(unread)))


def _names(parts: tuple[str, ...]) -> Iterator[str]:
    for index, part in enumerate(parts[:-1]):
        if part == TEMPLATES_DIRECTORY:
            yield "/".join(parts[index + 1 :])


def _read(path: Path) -> str:
    return _text(path) or ""


class _Verdict(NamedTuple):
    """Whether a template escapes all it prints itself; the templates it extends and
    those it includes, which must escape too; and whether its text ends inside a
    construct, which the markup after its include continues."""

    escapes: bool
    extends: frozenset[str]
    includes: frozenset[str]
    open_end: bool


_REFUSED = _Verdict(escapes=False, extends=frozenset(), includes=frozenset(), open_end=False)


def _verdict(parsed: _Parsed) -> _Verdict:
    """What one template file establishes, read on its own."""

    if not parsed.ok:
        return _REFUSED
    reading = _read_markup(_flattened(parsed.nodes))
    return _Verdict(reading.escapes, parsed.extends, parsed.includes, reading.open_end)


def _parse_file(path: Path) -> _Parsed:
    """The template file ``path``: one the engine cannot read is not established to
    escape, like a template it cannot find."""

    text = _text(path)
    return _NOT_ESCAPING if text is None else _parse(text)


def _text(path: Path) -> str | None:
    """The text of ``path``, or None when it cannot be read."""

    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


_Node: TypeAlias = "str | _Block | _Include | _Super"


class _Block(NamedTuple):
    """A ``{% block %}``: its name, what it holds, and whether its ``{% endblock %}``
    closes it."""

    name: str
    nodes: tuple[_Node, ...]
    closed: bool


class _Include(NamedTuple):
    """An ``{% include %}`` of the template ``name``."""

    name: str


class _Super(NamedTuple):
    """``{{ block.super }}``, which renders the parent's definition of its block."""


@dataclass(frozen=True)
class _Parsed:
    """One template file as its syntax gives it: whether that syntax lets it escape
    (``ok``: Django's own tags, libraries and escaping filters only); the templates it
    extends and those it includes; and its ``nodes``, markup in which a variable is
    ``_OUTPUT``, a ``url`` or ``static`` tag ``_URL`` and any other tag ``_TAG``, with its
    blocks, includes and ``{{ block.super }}`` kept apart, and its blocks by name."""

    ok: bool
    extends: frozenset[str] = frozenset()
    includes: frozenset[str] = frozenset()
    nodes: tuple[_Node, ...] = ()
    blocks: Mapping[str, tuple[_Node, ...]] = field(default_factory=dict)


_NOT_ESCAPING = _Parsed(ok=False)


def _parse(text: str) -> _Parsed:
    """The template of ``text`` (``_Parsed``)."""

    extends: set[str] = set()
    includes: set[str] = set()
    blocks: dict[str, tuple[_Node, ...]] = {}
    # The blocks open around the position read, each with what it holds so far, under
    # the nodes the template holds outside them.
    nodes: list[_Node] = []
    opened: list[tuple[str, list[_Node]]] = []
    skipping: str | None = None
    position = 0
    text = text.replace(_OUTPUT, "").replace(_TAG, "").replace(_INSERTED, "")

    def held() -> list[_Node]:
        return opened[-1][1] if opened else nodes

    def close() -> None:
        name, inside = opened.pop()
        block = _Block(name, tuple(inside), closed=True)
        blocks.setdefault(name, block.nodes)
        held().append(block)

    for match in _SYNTAX.finditer(text):
        variable, tag = match.group(1), match.group(2)
        words = tag.split() if tag is not None else []
        if skipping is not None:
            if words[:1] == [skipping]:
                if skipping == "endverbatim":
                    held().append(text[position : match.start()])
                skipping, position = None, match.end()
            continue
        held().append(text[position : match.start()])
        position = match.end()
        if variable is not None:
            if variable.strip() == _BLOCK_SUPER:
                held().append(_Super())
                continue
            if not _escaping_filters(variable) or _names_block(variable):
                return _NOT_ESCAPING
            held().append(_OUTPUT)
        elif words and words[0] in ("comment", "verbatim"):
            skipping = f"end{words[0]}"
            if words[0] == "verbatim":
                position = match.end()
        elif words:
            name = words[0]
            if name not in _TAGS or name not in ("block", "endblock") and _names_block(tag):
                return _NOT_ESCAPING
            if name == "load" and not set(_loaded(words[1:])) <= _LIBRARIES:
                return _NOT_ESCAPING
            if name == "autoescape" and words[1:] != ["on"]:
                return _NOT_ESCAPING
            if name == "filter" and not _escaping_filters(tag.split(None, 1)[1] if len(words) > 1 else ""):
                return _NOT_ESCAPING
            if name in ("extends", "include"):
                needed = _constant(words[1] if len(words) > 1 else "")
                if needed is None:
                    return _NOT_ESCAPING
                if name == "extends":
                    extends.add(needed)
                    held().append(_TAG)
                else:
                    includes.add(needed)
                    held().append(_Include(needed))
            elif name == "block" and len(words) > 1:
                opened.append((words[1], []))
            elif name == "endblock" and opened:
                close()
            else:
                held().append(_OUTPUT if name in _PRINTING else _URL if name in ("url", "static") else _TAG)
    if skipping is not None:
        return _NOT_ESCAPING
    held().append(text[position:])
    while opened:
        name, inside = opened.pop()
        block = _Block(name, tuple(inside), closed=False)
        blocks.setdefault(name, block.nodes)
        held().append(block)
    return _Parsed(True, frozenset(extends), frozenset(includes), tuple(nodes), MappingProxyType(blocks))


def _names_block(expression: str) -> bool:
    """Whether ``expression`` names the variable ``block`` outside its string literals."""

    return _BLOCK_VARIABLE.search(re.sub(_STRING, "", expression)) is not None


def _flattened(nodes: Iterable[_Node]) -> str:
    """``nodes`` as one markup, each block, include and ``{{ block.super }}`` marked where
    it stands as the tag or variable it is."""

    parts: list[str] = []
    for node in nodes:
        if isinstance(node, str):
            parts.append(node)
        elif isinstance(node, _Block):
            parts.extend((_TAG, _flattened(node.nodes), _TAG if node.closed else ""))
        elif isinstance(node, _Include):
            parts.append(_TAG)
        else:
            parts.append(_OUTPUT)
    return "".join(parts)


# The size a page put together may reach, in characters, checked as it grows: nested
# includes can multiply a page beyond any size.
_PAGE_LIMIT = 8 * 1024 * 1024
# The pages one template may render with the files each template it extends may be, and
# their size together: many small pages never reach the bound of one.
_VARIANT_LIMIT = 64
_VARIANTS_SIZE_LIMIT = 16 * 1024 * 1024
_TOO_LARGE = "beyond 8 MiB once its blocks and includes are put together"
_TOO_MANY = "more than 64 pages, or 16 MiB in all, with each file the templates it extends may be"


class _Unrenderable(Exception):
    """A page Django could not render: a block holding a block of its own name."""


class _Page(NamedTuple):
    """The markups a template renders, one for each file each template its extends chain
    names may be, and the names of the includes it inserts there (``_INSERTED``), its
    own and those of the pages it includes."""

    markups: tuple[str, ...]
    inserted: frozenset[str] = frozenset()


class _Composition:
    """The page each template file renders, put together as Django renders it (#273):
    its extends chain from the root, each block taking the definition of the most derived
    template defining it and ``{{ block.super }}`` the next definition up, each include
    the page of the included template, or, for a name several files have, a template
    rendering several pages or one on the way to itself, an inserted markup standing for
    each (``_INSERTED``): a page inserted in HTML data reads as the markup it stands for
    there, nested to any depth, provided that markup is accepted and ends in data. A
    name several files have in the chain gives a page for each, up to ``_VARIANT_LIMIT``
    and ``_VARIANTS_SIZE_LIMIT`` together, beyond which ``too_many`` lists the template.
    A child's text outside its blocks is not part of a page. A page that cannot be put
    together is not established: a template it needs is missing or refused by its own
    syntax, it extends itself, a block of it holds itself, or it grows beyond
    ``_PAGE_LIMIT``, which ``too_large`` then lists."""

    def __init__(self, found: Mapping[str, Sequence[Path]], parsed: Mapping[Path, _Parsed]) -> None:
        self._found = found
        self._parsed = parsed
        # Only the pages another one includes are kept: a page is read once, and its
        # markup is needed again only where it is included.
        self._included = {
            paths[0]
            for p in parsed.values()
            for name in p.includes
            if len(paths := found.get(name, ())) == 1
        }
        self._pages: dict[Path, _Page | None] = {}
        self.too_large: set[Path] = set()
        self.too_many: set[Path] = set()

    def page(self, path: Path) -> _Page | None:
        """The page ``path`` renders, put together; None when it cannot be."""

        if path in self._pages:
            return self._pages[path]
        # Depth first over the includes each page renders, without recursion: a page is
        # put together once the pages it includes are.
        stack = [path]
        waiting: set[Path] = set()
        result: _Page | None = None
        while stack:
            current = stack[-1]
            if current in self._pages:
                stack.pop()
                continue
            chains = self._chains(current)
            targets = None if chains is None else self._targets(chains)
            if targets is None:
                page = None
            elif pending := [target for target in targets if target not in self._pages and target not in waiting]:
                waiting.add(current)
                stack.extend(pending)
                continue
            else:
                assert chains is not None
                page = self._render(current, chains, waiting)
            waiting.discard(current)
            stack.pop()
            if current == path:
                result = page
            if current in self._included or current != path:
                self._pages[current] = page
        return result

    def _chains(self, path: Path) -> list[list[_Parsed]] | None:
        """``path``, then what it extends, up to the root: one chain for each file each
        name it extends may be. As Django's loaders do, the files already in the chain
        are left out: a template extending its own name extends another file of it."""

        chains: list[list[_Parsed]] = []
        pending: list[tuple[list[_Parsed], frozenset[Path]]] = [([self._parsed[path]], frozenset({path}))]
        while pending:
            chain, seen = pending.pop()
            if not chain[-1].ok:
                return None
            if not chain[-1].extends:
                chains.append(chain)
                continue
            if len(chain[-1].extends) != 1:
                return None
            (name,) = chain[-1].extends
            parents = [parent for parent in self._found.get(name, ()) if parent not in seen]
            if not parents:
                return None
            pending.extend(([*chain, self._parsed[parent]], seen | {parent}) for parent in parents)
            if len(chains) + len(pending) > _VARIANT_LIMIT:
                self.too_many.add(path)
                return None
        return chains

    def _targets(self, chains: Iterable[Sequence[_Parsed]]) -> list[Path] | None:
        """The files the pages of ``chains`` include, those of a name one file has; None
        when a name they include has none, or a page cannot be rendered."""

        targets: list[Path] = []
        try:
            for chain in chains:
                for name in _includes(chain):
                    paths = self._found.get(name, ())
                    if not paths:
                        return None
                    if len(paths) == 1:
                        targets.append(paths[0])
        except _Unrenderable:
            return None
        return targets

    def _render(self, path: Path, chains: Iterable[Sequence[_Parsed]], waiting: Container[Path]) -> _Page | None:
        """The pages ``chains`` render; an include of a page being put together, on the
        way to itself, inserted (``_INSERTED``)."""

        markups: list[str] = []
        inserted: set[str] = set()
        together = 0
        for chain in chains:
            markup = self._markup(path, chain, waiting, inserted)
            if markup is None:
                return None
            together += len(markup)
            if together > _VARIANTS_SIZE_LIMIT:
                self.too_many.add(path)
                return None
            markups.append(markup)
        return _Page(tuple(markups), frozenset(inserted))

    def _markup(self, path: Path, chain: Sequence[_Parsed], waiting: Container[Path], inserted: set[str]) -> str | None:
        """The page of ``chain``, each definition put together once however many times
        the page renders it, and each bounded as it grows: a block rendering its parent
        twice at every level doubles the page, not the work."""

        made: dict[_Key, str] = {}
        root = _root(chain)
        # The definitions being put together, each with what it renders so far and its size.
        stack: list[tuple[_Key, Iterator[_Node], list[str], list[int]]] = [(root, iter(_definition(chain, root)), [], [0])]
        while stack:
            key, nodes, parts, size = stack[-1]
            node = next(nodes, None)
            if node is None:
                stack.pop()
                made[key] = piece = "".join(parts)
                if not stack:
                    return piece
            elif isinstance(node, str):
                piece = node
            elif isinstance(node, _Include):
                included = self._include_markup(node.name, waiting, inserted)
                if included is None:
                    return None
                piece = included
            else:
                inner = _resolved(chain, key, node)
                if inner is None:
                    continue
                if inner not in made:
                    stack.append((inner, iter(_definition(chain, inner)), [], [0]))
                    continue
                piece = made[inner]
            _, _, parts, size = stack[-1]
            parts.append(piece)
            size[0] += len(piece)
            if size[0] > _PAGE_LIMIT:
                self.too_large.add(path)
                return None
        return None

    def _include_markup(self, name: str, waiting: Container[Path], inserted: set[str]) -> str | None:
        """What an include of ``name`` puts in a page: the page of its one file, or an
        inserted markup; None when that page cannot be put together."""

        paths = self._found[name]
        recursive = len(paths) == 1 and paths[0] in waiting
        included = self._pages[paths[0]] if len(paths) == 1 and not recursive else None
        if included is not None and len(included.markups) == 1:
            inserted |= included.inserted
            return included.markups[0]
        if len(paths) == 1 and included is None and not recursive:
            return None
        inserted.add(name)
        return _INSERTED


# A definition a page renders: a block's, in the template of ``chain`` at that level, or,
# with no name, the root's nodes outside its blocks.
_Key = tuple[str | None, int]


def _root(chain: Sequence[_Parsed]) -> _Key:
    return None, len(chain) - 1


def _definition(chain: Sequence[_Parsed], key: _Key) -> tuple[_Node, ...]:
    name, level = key
    return chain[level].nodes if name is None else chain[level].blocks[name]


def _resolved(chain: Sequence[_Parsed], key: _Key, node: _Block | _Super) -> _Key | None:
    """The definition ``node`` renders, standing in the definition ``key``: for a block,
    that of the most derived template defining it; for ``{{ block.super }}``, the next
    one up, if any."""

    name, level = key
    if isinstance(node, _Block):
        return node.name, next(index for index, parsed in enumerate(chain) if node.name in parsed.blocks)
    if name is None:
        return None
    parent = next((index for index in range(level + 1, len(chain)) if name in chain[index].blocks), None)
    return None if parent is None else (name, parent)


def _includes(chain: Sequence[_Parsed]) -> list[str]:
    """The names the page of ``chain`` includes, each definition it renders visited once
    however many times it is rendered: a block holding itself, which Django cannot
    render, raises ``_Unrenderable``."""

    found: list[str] = []
    visited = {_root(chain)}
    stack: list[tuple[_Key, Iterator[_Node]]] = [(_root(chain), iter(_definition(chain, _root(chain))))]
    while stack:
        key, nodes = stack[-1]
        node = next(nodes, None)
        if node is None:
            stack.pop()
        elif isinstance(node, _Include):
            found.append(node.name)
        elif not isinstance(node, str) and (inner := _resolved(chain, key, node)) is not None:
            if any(inner == open_key for open_key, _ in stack):
                raise _Unrenderable(inner[0])
            if inner not in visited:
                visited.add(inner)
                stack.append((inner, iter(_definition(chain, inner))))
    return found


def _loaded(words: list[str]) -> list[str]:
    """The libraries ``{% load a b %}`` or ``{% load x y from lib %}`` loads."""

    return words[words.index("from") + 1 :] if "from" in words else words


def _escaping_filters(expression: str) -> bool:
    filters = re.sub(_QUOTED, "", expression).split("|")[1:]
    return all(f.split(":", 1)[0].strip() in _FILTERS for f in filters)


def _constant(word: str) -> str | None:
    return word[1:-1] if len(word) >= 2 and word[0] == word[-1] and word[0] in "\"'" else None


class _Reading(NamedTuple):
    """What one pass over a template's markup establishes: whether every output marker
    stands where HTML escaping protects it; whether the text ends inside a script or
    style block, a tag or an end tag, which the markup after its include continues; and
    whether it ends in HTML data, ``settled``: nothing of it left open, comment included,
    and no ``<``, ``</``, ``<!`` or ``<!-`` at its end for what follows to complete."""

    escapes: bool
    open_end: bool
    settled: bool = False


_NOT_READ = _Reading(escapes=False, open_end=False)


def _read_markup(html: str) -> _Reading:
    """Read ``html`` once, as the HTML tokenizer reads the page it is part of. Each
    construct is matched where it starts and one the text leaves open runs to its end,
    so every character is read once, where copying the rest of the text at each ``<``
    and rescanning what never closed took quadratic time (#272).

    A comment ends at its close, as a browser closes it, or at the first template tag
    inside it, whichever comes first, and what follows the tag is read as markup: an
    include there may close the comment, a condition around its ``<!--`` leave it out.
    A variable cannot close it, escaped. A comment left open, with no tag after it,
    hides the rest of the text, and hands nothing on: what follows its include stays
    inside it.

    A comment holding template tags may also end at a later one of them, or run to its
    close when they render nothing (#278). Each of these readings resumes, right after
    that tag or that close, where this one must then be in HTML data: there, they read
    what it reads. Where it is inside another construct, the text is refused. Such a
    comment left open does not end in data: its tags may render nothing, and it then
    hides what follows.

    An inserted markup (``_INSERTED``) may hold anything a file of its name holds: it is
    accepted only in HTML data, never in a comment, a script or style block, a tag or
    an end tag, nor after what it could complete into one. In data it is as if the
    markup were there, provided that markup is accepted and ends in data (#273).

    The reading stays linear, but for looking up inserted markups by position: it only
    moves forward, and every part of the text is looked at once. The points where other
    readings resume come in two sequences that never go back, the later tags of comments
    as they are listed and the closes of comments as these are read, so a queue of each
    holds them."""

    position = 0
    open_end = False
    # The first comment close after the comment being read, searched once for all the
    # comments that open before it; and the position after which none closes.
    close: re.Match[str] | None = None
    unclosed_from = len(html) + 1
    # Where other readings of comments holding tags resume, which this one must reach in
    # HTML data; how far the tags inside comments have been listed, a comment read inside
    # another sharing the rest of its region; whether such a comment is left open; and
    # where inserted markups stand, for a comment to look for one inside it at once.
    after_tags: deque[int] = deque()
    after_closes: deque[int] = deque()
    tags_listed_to = 0
    left_open = False
    inserted = [match.start() for match in re.finditer(_INSERTED, html)] if _INSERTED in html else []

    def crossed(start: int, end: int) -> bool:
        """Whether a point of resumption lies inside the construct read from ``start``
        to ``end``: those before it are reached in data, and leave the queues."""

        if not after_tags and not after_closes:
            return False
        for points in (after_tags, after_closes):
            while points and points[0] <= start:
                points.popleft()
        return any(points and points[0] < end for points in (after_tags, after_closes))

    while (start := html.find("<", position)) != -1:
        if html.startswith("<!--", start):
            if start >= unclosed_from:
                close = None
            elif close is None or close.start() < start + 2:
                close = _COMMENT_END.search(html, start + 2)
                if close is None:
                    unclosed_from = start
            hidden_to = len(html) if close is None else close.start()
            if inserted and (index := bisect_left(inserted, start + 4)) < len(inserted) and inserted[index] < hidden_to:
                return _NOT_READ
            first_tag = html.find(_TAG, start + 4, hidden_to)
            if first_tag != -1:
                if crossed(start, first_tag + 1):
                    return _NOT_READ
                tag = html.find(_TAG, max(first_tag + 1, tags_listed_to), hidden_to)
                while tag != -1:
                    after_tags.append(tag + 1)
                    tag = html.find(_TAG, tag + 1, hidden_to)
                tags_listed_to = max(tags_listed_to, hidden_to)
                if close is None:
                    left_open = True
                else:
                    after_closes.append(close.end())
                position, open_end = first_tag + 1, False
            elif close is not None:
                if crossed(start, close.end()):
                    return _NOT_READ
                position, open_end = close.end(), False
            else:
                if crossed(start, len(html)):
                    return _NOT_READ
                return _Reading(escapes=True, open_end=False)
        elif raw := _RAW_TEXT.match(html, start):
            if _OUTPUT in raw.group(2) or _INSERTED in raw.group(0) or not _attributes_escape(html[start : raw.start(2)]):
                return _NOT_READ
            if crossed(start, raw.end()):
                return _NOT_READ
            position, open_end = raw.end(), not raw.group(3)
        elif tag_match := _START_TAG.match(html, start):
            if _OUTPUT in tag_match.group(1) or _INSERTED in tag_match.group(0) or not _attributes_escape(tag_match.group(2)):
                return _NOT_READ
            if crossed(start, tag_match.end()):
                return _NOT_READ
            position, open_end = tag_match.end(), tag_match.group(3) is None
        elif end := _END_TAG.match(html, start):
            if _OUTPUT in end.group(0) or _INSERTED in end.group(0) or crossed(start, end.end()):
                return _NOT_READ
            position, open_end = end.end(), end.group(1) is None
        elif _NAMED_BY_OUTPUT.match(html, start) or _OPENED_BY_INSERTION.match(html, start):
            return _NOT_READ
        else:
            position = start + 1
    settled = not open_end and not left_open and not _ENDING_OPENER.search(html)
    return _Reading(escapes=True, open_end=open_end, settled=settled)


def _attributes_escape(attributes: str) -> bool:
    for match in _ATTRIBUTE.finditer(attributes):
        name, value = match.group(1).lower(), match.group(2)
        if _OUTPUT in name:
            return False
        if value is None or _OUTPUT not in value:
            continue
        if value[0] not in "\"'" or name.startswith("on") or name in ("style", "srcdoc"):
            return False
        if name in _URL_ATTRIBUTES:
            prefix = value[1:].split(_OUTPUT, 1)[0]
            if _TAG in prefix or not _SAFE_URL_PREFIX.match(prefix):
                return False
    return True


@dataclass(frozen=True)
class FilterCall:
    """A filter a project template applies: a call to the function behind it, placed at
    the filter's name in the template."""

    symbol: SymbolId
    span: SourceSpan


@dataclass(frozen=True)
class ProjectTemplates:
    """The templates found under the project's ``templates`` directories: their
    ``names``, as a render call names them; the filters of Django's own libraries they
    apply, as ``calls``, unless a project library they load replaces the filter; where
    they name a template the engine cannot read, or load a library it cannot read while
    applying a filter of that name, as ``unread``; and, by name, the filter calls
    rendering each template makes with the context keys reaching them, as ``filters``."""

    names: frozenset[str] = frozenset()
    calls: tuple[FilterCall, ...] = ()
    unread: tuple[str, ...] = ()
    filters: Mapping[str, tuple[TemplateFilter, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class _Application:
    """A filter a template applies: the function behind it, where, the names free in the
    template whose values reach its value and its argument, and the blocks it is in."""

    symbol: SymbolId
    span: SourceSpan
    value: frozenset[str]
    argument: frozenset[str]
    blocks: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Reference:
    """A template another one includes, or ``extends``, at ``offset`` in its ``blocks``:
    by ``name``, None when an expression names it. The referenced template's free names
    are ``bindings``, then, unless ``only``, what the ``scope`` binds there, then the
    referencing template's."""

    name: str | None
    offset: int
    bindings: Mapping[str, frozenset[str]] = field(default_factory=dict)
    only: bool = False
    scope: Mapping[str, frozenset[str]] = field(default_factory=dict)
    blocks: tuple[str, ...] = ()
    extends: bool = False

    def maps(self, names: frozenset[str]) -> frozenset[str]:
        found: set[str] = set()
        for name in names:
            variable = name.split(".", 1)[0]
            if variable in self.bindings:
                found |= _through(self.bindings[variable], name)
            elif not self.only:
                found |= _through(self.scope.get(variable, frozenset({variable})), name)
        return frozenset(found)


@dataclass(frozen=True)
class _Load:
    """A ``{% load %}`` of ``library`` at ``offset``, of the ``names`` it selects
    (``{% load a b from lib %}``), None for the whole library."""

    library: str
    names: frozenset[str] | None
    offset: int


@dataclass(frozen=True)
class _Library:
    """What the project's tag library files of one name register: the filter names they
    surely register, ``certain``, and those they may register, ``uncertain`` — None when
    they may register anything, as a file the engine cannot read or understand may."""

    certain: frozenset[str] = frozenset()
    uncertain: frozenset[str] | None = None

    def overrides(self, name: str) -> bool | None:
        """Whether loading the library replaces the filter ``name``; None when it may."""

        if name in self.certain:
            return True
        return None if self.uncertain is None or name in self.uncertain else False


@dataclass(frozen=True)
class _Template:
    """What one template file applies and references, the ``blocks`` it defines, and
    among them the ``extended`` ones, which render ``{{ block.super }}``, the loads under
    which it applies a filter the engine could not resolve, and the block each block
    stands in, None for one standing in none (#285)."""

    applications: tuple[_Application, ...]
    references: tuple[_Reference, ...]
    blocks: frozenset[str]
    extended: frozenset[str] = frozenset()
    unresolved: tuple[_Load, ...] = ()
    enclosing: Mapping[str, str | None] = field(default_factory=dict)


def project_templates(root: Path) -> ProjectTemplates:
    """What the templates under ``root`` call, and the templates they include or extend
    that the engine cannot read: named by an expression, or by a name found under no
    ``templates`` directory. A template file that cannot be read is unread too, and so
    is a template loading a library the engine cannot read, or find, or finds in several
    apps disagreeing, where it then applies a filter of that library's name. A name
    found in several files gives no ``filters``: which one renders depends on the
    loaders."""

    found = {path: tuple(_names(path.relative_to(root).parts)) for path in discover_files(root)}
    libraries = _libraries(found)
    templates = sorted(path for path, names in found.items() if names)
    files: dict[str, list[Path]] = {}
    for path in templates:
        for name in found[path]:
            files.setdefault(name, []).append(path)
    read: dict[Path, _Template] = {}
    unread: list[str] = []
    for path in templates:
        relative = path.relative_to(root).as_posix()
        text = _text(path)
        if text is None:
            unread.append(f"{relative}, unreadable")
            continue
        read[path] = _read_scopes(text, SourceId(str(path)), libraries)
        for reference in read[path].references:
            where = f"{relative}:{_position(text, reference.offset)[0]}"
            if reference.name is None:
                unread.append(f"{where} names a template by an expression")
            elif reference.name not in files:
                unread.append(f"{where} names {reference.name!r}, not found")
        for load in read[path].unresolved:
            library = libraries.get(load.library)
            reason = "not found" if library is None else "not read" if library.uncertain is None else "found in several files"
            unread.append(f"{relative}:{_position(text, load.offset)[0]} loads {load.library!r}, {reason}")
    calls = tuple(FilterCall(a.symbol, a.span) for template in read.values() for a in template.applications)
    # What each template reaches rendered on its own, for this analysis only.
    settled = _settled(files, read)
    filters = {
        name: tuple(
            dict.fromkeys(
                TemplateFilter(symbol, span, where, tuple(sorted(value)), tuple(sorted(argument)))
                for symbol, span, where, value, argument in settled.get(name, ())
            )
        )
        for name in files
    }
    return ProjectTemplates(frozenset(files), calls, tuple(unread), filters)


# A filter a template's render reaches: the function, where it is applied, the template
# applying it, and the names free in the rendered template reaching its value and argument.
_Reached = tuple[SymbolId, SourceSpan, str, frozenset[str], frozenset[str]]


class _Render(NamedTuple):
    """What rendering a template on its own applies, and the templates it includes, each
    with its reference."""

    applied: tuple[_Reached, ...]
    references: tuple[tuple[str, _Reference], ...]


def _page(name: str, readable: Callable[[str | None], _Template | None]) -> _Render:
    """What rendering ``name`` on its own applies and includes, its extends chain put
    together as Django puts it (#285).

    The chain runs from ``name`` up to its root, the template extending none. The root's
    blocks standing in no other block are placed; a placed block renders its most derived
    definition, then, while a definition renders ``{{ block.super }}``, the next one up;
    the blocks a rendered definition holds are placed in turn. A filter or an include
    renders when the definition of the innermost block it stands in renders; outside
    every block, only in the root, Django ignoring a child's text outside its blocks.

    When the chain reaches no known root, as through a parent named by an expression, a
    name several files have, a file the engine cannot read, or an extends cycle Django
    refuses, every block of the chain is placed: no filter is dropped on a placement the
    engine cannot establish.

    What the chain applies is listed from ``name`` up to the root, and what it includes
    from the root down to ``name``: the order of a walk of each path through extends."""

    chain: list[tuple[str, _Template]] = []
    seen: set[str] = set()
    known = True
    current: str | None = name
    while True:
        template = readable(current)
        if current is None or template is None or current in seen:
            known = False
            break
        chain.append((current, template))
        seen.add(current)
        parent = next((reference for reference in template.references if reference.extends), None)
        if parent is None:
            break
        current = parent.name
    defining: dict[str, list[int]] = {}
    for level, (_, template) in enumerate(chain):
        for block in template.blocks:
            defining.setdefault(block, []).append(level)
    root = chain[-1][1]
    pending = [block for block in root.blocks if root.enclosing.get(block) is None] if known else list(defining)
    placed: set[str] = set()
    shown: set[tuple[int, str]] = set()
    while pending:
        block = pending.pop()
        if block in placed:
            continue
        placed.add(block)
        for level in defining.get(block, []):
            shown.add((level, block))
            template = chain[level][1]
            pending.extend(inner for inner in template.blocks if template.enclosing.get(inner) == block)
            if block not in template.extended:
                break

    def renders(level: int, blocks: tuple[str, ...]) -> bool:
        return (level, blocks[-1]) in shown if blocks else known and level == len(chain) - 1

    applied = tuple(
        (application.symbol, application.span, template_name, application.value, application.argument)
        for level, (template_name, template) in enumerate(chain)
        for application in template.applications
        if renders(level, application.blocks)
    )
    references = tuple(
        (reference.name, reference)
        for level in reversed(range(len(chain)))
        for reference in chain[level][1].references
        if not reference.extends
        and reference.name is not None
        and readable(reference.name) is not None
        and renders(level, reference.blocks)
    )
    return _Render(applied, references)


def _renders(files: Mapping[str, list[Path]], read: Mapping[Path, _Template]) -> dict[str, _Render]:
    """What rendering each template on its own applies and includes. A name several files
    have, or a file the engine could not read, renders nothing."""

    def readable(name: str | None) -> _Template | None:
        paths = files.get(name or "", [])
        return read[paths[0]] if len(paths) == 1 and paths[0] in read else None

    return {name: _page(name, readable) for name in files if readable(name) is not None}


def _components(renders: Mapping[str, _Render]) -> list[list[str]]:
    """The strongly connected components of the renders, each after every component its
    references reach: Tarjan's algorithm, without recursion."""

    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []
    for root in renders:
        if root in index:
            continue
        # Each entry is a template and the position of the next reference to follow.
        work = [(root, 0)]
        while work:
            current, position = work.pop()
            if position == 0:
                index[current] = low[current] = len(index)
                stack.append(current)
                on_stack.add(current)
            references = renders[current].references
            for following in range(position, len(references)):
                below = references[following][0]
                if below not in index:
                    work.append((current, following + 1))
                    work.append((below, 0))
                    break
                if below in on_stack:
                    low[current] = min(low[current], index[below])
            else:
                if low[current] == index[current]:
                    component: list[str] = []
                    while not component or component[-1] != current:
                        component.append(stack.pop())
                        on_stack.discard(component[-1])
                    components.append(component)
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[current])
    return components


def _mapped(found: Iterable[_Reached], reference: _Reference) -> Iterator[_Reached]:
    """The filters a referenced template reaches, their names mapped through the reference."""

    for symbol, span, where, value, argument in found:
        yield symbol, span, where, reference.maps(value), reference.maps(argument)


def _canonical(found: _Reached) -> tuple[str, int, int, str, list[str], list[str]]:
    """The order of the filters a template in a cycle reaches beyond what it applies."""

    symbol, span, where, value, argument = found
    return where, span.start_line, span.start_column, str(symbol), sorted(value), sorted(argument)


# A filter application: the function, where it is applied, and the template applying it.
_Site = tuple[SymbolId, SourceSpan, str]


def _joined(found: Iterable[_Reached], into: dict[_Site, tuple[frozenset[str], frozenset[str]]]) -> None:
    """Join into ``into`` the names reaching the value and the argument of each filter
    application ``found`` holds."""

    for symbol, span, where, value, argument in found:
        values, arguments = into.get((symbol, span, where), (frozenset(), frozenset()))
        into[symbol, span, where] = values | value, arguments | argument


def _facts(names: Mapping[_Site, tuple[frozenset[str], frozenset[str]]], sites: Iterable[_Site]) -> list[_Reached]:
    """The filters at ``sites``, each with the names joined at its application."""

    return [(symbol, span, where, *names[symbol, span, where]) for symbol, span, where in sites]


def _settled(files: Mapping[str, list[Path]], read: Mapping[Path, _Template]) -> dict[str, list[_Reached]]:
    """The filters the render of each template reaches, in order (#284).

    What a template reaches is the least set holding what it applies, its extends chain
    put together (#285), and what each template it includes reaches, mapped through the
    reference's bindings. The sets are computed
    component by component, each after those its references reach, which are then
    final. No cycle is cut: a template including itself with other bindings reaches what
    Django renders at its next levels.

    In a cycle, the names reaching the value and the argument of each filter application
    are joined: one fact per application, whatever the paths that bring each name. The
    analysis reads those names position by position, joining what each brings, so the
    join loses nothing, and it keeps the facts few: bindings permuted around a cycle
    would otherwise make one fact of every combination of names. In a component, every
    template starts with no names and is recomputed from its references' facts; names
    only join, and the applications and names of a project are finitely many, so the
    names of an application grow at most once for each name. A template is recomputed
    when a fact it reads grew, until none grows.

    Once the facts are settled, a template outside any cycle lists what it applies,
    then what each reference reaches, in order, first occurrences only, as a walk of
    each path would. A template in a cycle has no such first occurrence, the cycle
    having no start: it lists what it applies, then the rest by template, position,
    function and names. The order thus depends only on the facts and the templates,
    never on the order of the computation."""

    renders = _renders(files, read)
    reached: dict[str, list[_Reached]] = {}
    for component in _components(renders):
        single = component[0]
        if len(component) == 1 and all(below != single for below, _ in renders[single].references):
            # Outside any cycle: what its references reach is final.
            found = dict.fromkeys(renders[single].applied)
            for below, reference in renders[single].references:
                found.update(dict.fromkeys(_mapped(reached[below], reference)))
            reached[single] = list(found)
            continue
        members = set(component)
        readers: dict[str, list[str]] = {member: [] for member in component}
        for member in component:
            for below, _ in renders[member].references:
                if below in members:
                    readers[below].append(member)
        names: dict[str, dict[_Site, tuple[frozenset[str], frozenset[str]]]] = {member: {} for member in component}
        sizes = dict.fromkeys(component, 0)
        pending = deque(component)
        queued = set(component)
        while pending:
            member = pending.popleft()
            queued.discard(member)
            grown: dict[_Site, tuple[frozenset[str], frozenset[str]]] = {}
            _joined(renders[member].applied, grown)
            for below, reference in renders[member].references:
                below_found = _facts(names[below], names[below]) if below in members else reached[below]
                _joined(_mapped(below_found, reference), grown)
            # The names only join, so the count of applications and names only grows.
            size = sum(1 + len(values) + len(arguments) for values, arguments in grown.values())
            if size > sizes[member]:
                names[member], sizes[member] = grown, size
                for reader in readers[member]:
                    if reader not in queued:
                        pending.append(reader)
                        queued.add(reader)
        for member in component:
            applied = _facts(names[member], dict.fromkeys((s, span, w) for s, span, w, _, _ in renders[member].applied))
            sites = {(s, span, w) for s, span, w, _, _ in applied}
            rest = _facts(names[member], (site for site in names[member] if site not in sites))
            reached[member] = [*applied, *sorted(rest, key=_canonical)]
    return reached


def _read_scopes(text: str, source: SourceId, libraries: Mapping[str, _Library]) -> _Template:
    """The filters a template applies and the templates it includes or extends, with the
    names free in it that reach each: through ``{% for %}``, ``{% with %}`` and the
    ``as`` of other tags, which bind a name until their block ends, the arguments of
    earlier filters, and the output of ``{% filter %}`` blocks. A filter is the one of
    Django's own libraries unless a project library, among ``libraries``, loaded before
    it in the file replaces it, as Django's parser resolves filters."""

    applications: list[_Application] = []
    references: list[_Reference] = []
    opened: list[str] = []
    defined: set[str] = set()
    extended: set[str] = set()
    enclosing: dict[str, str | None] = {}
    scopes: list[dict[str, frozenset[str]]] = [{}]
    blocks: list[tuple[list[tuple[str, int, frozenset[str]]], set[str]]] = []
    loaded: list[_Load] = []
    unresolved: dict[_Load, None] = {}

    def free(names: frozenset[str]) -> frozenset[str]:
        found: set[str] = set()
        for name in names:
            variable = name.split(".", 1)[0]
            bound = next((scope[variable] for scope in reversed(scopes) if variable in scope), None)
            found |= {name} if bound is None else _through(bound, name)
        return frozenset(found)

    def behind(name: str) -> SymbolId | _Load | None:
        """The function behind the filter ``name`` applied here: the one of Django's own
        libraries, unless the latest load so far of a library registering ``name``
        replaces it (None), or may (that load). Django's own libraries register no name
        of another, so their loads change nothing."""

        builtin = FILTER_FUNCTIONS.get(name)
        if builtin is None:
            return None
        for load in reversed(loaded):
            if (load.names is not None and name not in load.names) or load.library in _LIBRARIES:
                continue
            library = libraries.get(load.library)
            verdict = library.overrides(name) if library is not None else None
            if verdict is None:
                return load
            if verdict:
                return None
        return builtin

    def apply(head: frozenset[str], chain: list[tuple[str, int, frozenset[str]]]) -> frozenset[str]:
        """Record the filters of ``chain`` applied to a value the free names ``head``
        reach; the free names reaching the value of the whole expression."""

        value = head
        for name, offset, argument in chain:
            symbol = behind(name)
            if isinstance(symbol, _Load):
                unresolved[symbol] = None
            elif symbol is not None:
                line, column = _position(text, offset)
                span = SourceSpan(source, line, column)
                applications.append(_Application(symbol, span, value, free(argument), tuple(opened)))
            value |= free(argument)
        return value

    for offset, expression, tag in _expressions(text):
        if not tag:
            head, chain = _chain(expression, offset)
            if opened and _BLOCK_SUPER in head:
                extended.add(opened[-1])
            printed = apply(free(head), chain)
            for _, collected in blocks:
                collected |= printed
            continue
        tokens = [(match.start() + offset, match.group()) for match in _TOKEN.finditer(expression)]
        words = [word for _, word in tokens]
        name = words[0] if words else ""
        if name == "filter":
            # ``{% filter lower|striptags %}``: filters without a value, applied to the
            # block's output at its end.
            start = expression.index("filter") + len("filter")
            blocks.append((_chain("|" + expression[start:], offset + start - 1)[1], set()))
            continue
        if name == "endfilter" and blocks:
            chain, collected = blocks.pop()
            printed = apply(frozenset(collected), chain)
            if blocks:
                blocks[-1][1].update(printed)
            continue
        values: dict[str, frozenset[str]] = {}
        bindings: dict[str, frozenset[str]] = {}
        for start, word in tokens[1:]:
            bound = _BINDING.match(word)
            skipped = bound.end() if bound else 0
            head, chain = _chain(word[skipped:], start + skipped)
            reached = apply(free(head), chain)
            if bound:
                bindings[bound.group(1)] = reached
            else:
                values.setdefault(word, reached)
        if name == "block" and len(words) > 1:
            enclosing.setdefault(words[1], opened[-1] if opened else None)
            opened.append(words[1])
            defined.add(words[1])
        elif name == "endblock" and opened:
            opened.pop()
        elif name == "for" and "in" in words:
            loop = words.index("in")
            targets = [t for word in words[1:loop] for t in word.split(",") if t]
            iterated = values.get(words[loop + 1], frozenset()) if loop + 1 < len(words) else frozenset()
            scopes.append({"forloop": frozenset(), **{target: iterated for target in targets}})
        elif name == "with":
            as_form = len(words) == 4 and words[2] == "as"
            scopes.append({words[3]: values.get(words[1], frozenset())} if as_form else bindings)
        elif name in ("endfor", "endwith") and len(scopes) > 1:
            scopes.pop()
        elif name in ("include", "extends"):
            named = _constant(words[1]) if len(words) > 1 else None
            if name == "extends":
                references.append(_Reference(named, offset, extends=True))
            else:
                context = {k: v for scope in scopes for k, v in scope.items()}
                references.append(_Reference(named, offset, bindings, "only" in words, context, tuple(opened)))
        elif name == "load":
            selected = frozenset(words[1 : words.index("from")]) if "from" in words else None
            loaded.extend(_Load(library, selected, offset) for library in _loaded(words[1:]))
        elif "as" in words[1:-1]:
            target = words[words.index("as", 1) + 1]
            scopes[-1][target] = values.get(words[1], frozenset()) if name == "regroup" else frozenset()
    return _Template(
        tuple(applications), tuple(references), frozenset(defined), frozenset(extended), tuple(unresolved), enclosing
    )


def _libraries(paths: Iterable[Path]) -> dict[str, _Library]:
    """The project's tag libraries among ``paths``, by the name ``{% load %}`` gives
    them: the modules of the ``templatetags`` directories. Of several files of one name,
    in different apps, only what every file registers is certain, and one the engine
    cannot read leaves everything uncertain."""

    readings: dict[str, list[frozenset[str] | None]] = {}
    for path in paths:
        if path.suffix == ".py" and path.parent.name == TEMPLATETAGS_DIRECTORY and path.stem != "__init__":
            readings.setdefault(path.stem, []).append(_registered_filters(path))
    libraries: dict[str, _Library] = {}
    for name, found in readings.items():
        read = [names for names in found if names is not None]
        if len(read) < len(found):
            libraries[name] = _Library()
        else:
            certain = read[0].intersection(*read[1:])
            libraries[name] = _Library(certain, read[0].union(*read[1:]) - certain)
    return libraries


def _registered_filters(path: Path) -> frozenset[str] | None:
    """The names of the filters the tag library module ``path`` registers, or None when
    the engine cannot tell them all: the file cannot be read or parsed, ``register`` is
    not bound to a ``Library`` at module level, a registration's name is not written as
    a constant, or the library is filled or passed around in a way the engine does not
    read. The ``Library`` is known by its symbol, whatever the import spelling, and a
    registration under ``if``, ``try`` or a function counts."""

    try:
        module = build_hir(SourceManager().load_file(path))
        scopes = analyze_scopes(module)
        symbols = analyze_symbols(scopes, analyze_imports(module, scopes), module)
    except (OSError, UnicodeDecodeError, ParseError, HIRBuildError, ScopeError, ImportResolutionError):
        return None
    scope = scopes.module_scope.id
    if symbols.resolve(scope, "register") not in _LIBRARY_CLASSES:
        return None
    functions = {name for name, bound in scopes.module_scope.bindings.items() if bound.kind is BindingKind.FUNCTION}
    registered: set[str] = set()

    def record(name: str | None) -> bool:
        if name is not None:
            registered.add(name)
        return name is not None

    def visit(node: Node) -> bool:
        """Read the registrations under ``node``; False when one cannot be read."""

        if isinstance(node, nodes.Function):
            for decorator in node.decorators:
                if _library_attribute(symbols.resolve_expression(scope, decorator)) == "filter":
                    named = _decorated(decorator, node.name) if isinstance(decorator, nodes.Call) else node.name
                    if not record(named):
                        return False
                elif not visit(decorator):
                    return False
            return all(map(visit, (*node.parameters, *node.body)))
        if isinstance(node, nodes.Call) and isinstance(node.callee, nodes.Name | nodes.Attribute):
            callee = symbols.resolve_expression(scope, node.callee)
            if callee in _LIBRARY_CLASSES:
                return not (node.arguments or node.keywords)  # ``Library(filters=...)`` fills it unseen
            if _library_attribute(callee) == "filter":
                return record(_registered(node, functions)) and all(map(visit, (*node.arguments, *node.keywords)))
        if isinstance(node, nodes.Name | nodes.Attribute):
            symbol = symbols.resolve_expression(scope, node)
            if _library_attribute(symbol) in _TAG_REGISTRARS:
                return True
            if symbol in _LIBRARY_CLASSES or _library_attribute(symbol) is not None:
                return False  # the library, or its filters, in hands the engine does not follow
        if isinstance(node, nodes.Assign) and isinstance(node.target, nodes.Name):
            return visit(node.value)
        return all(map(visit, children(node)))

    return frozenset(registered) if all(map(visit, module.body)) else None


def _library_attribute(symbol: SymbolId | None) -> str | None:
    """The attribute of a ``Library`` that ``symbol`` names, ``filter`` for
    ``register.filter``; None for any other symbol."""

    if symbol is None:
        return None
    owner, _, name = symbol.canonical_name.rpartition(".")
    return name if "." in owner and SymbolId(owner) in _LIBRARY_CLASSES else None


def _decorated(call: nodes.Call, function: str) -> str | None:
    """What ``@register.filter(...)`` registers ``function`` as: the constant ``name`` it
    gives, or ``function`` itself when it gives only flags; None when the engine cannot
    tell."""

    given = _arguments(call, "name")
    if given is None:
        return None
    return function if given[0] is None else _string(given[0])


def _registered(call: nodes.Call, functions: Container[str]) -> str | None:
    """What ``register.filter(...)`` registers when called as a statement: the constant
    name of ``register.filter("x", fn)`` and ``register.filter(name="x", filter_func=fn)``,
    the function's own name for ``register.filter(fn)`` when the module defines
    ``fn``; None when the engine cannot tell."""

    given = _arguments(call, "name", "filter_func")
    if given is None:
        return None
    name, function = given
    if function is None:
        return name.identifier if isinstance(name, nodes.Name) and name.identifier in functions else None
    return _string(name)


def _arguments(call: nodes.Call, *parameters: str) -> list[nodes.Expression | None] | None:
    """The argument ``call`` gives each of ``parameters``, by position or keyword; None
    when it unpacks any, which could give them too."""

    if any(isinstance(a, nodes.Starred) for a in call.arguments) or any(k.name is None for k in call.keywords):
        return None
    keywords = {keyword.name: keyword.value for keyword in call.keywords}
    return [
        call.arguments[position] if position < len(call.arguments) else keywords.get(name)
        for position, name in enumerate(parameters)
    ]


def _string(expression: nodes.Expression | None) -> str | None:
    return expression.value if isinstance(expression, nodes.Constant) and isinstance(expression.value, str) else None


def _chain(expression: str, offset: int) -> tuple[frozenset[str], list[tuple[str, int, frozenset[str]]]]:
    """What a filter expression's value is reached by, and its filters, each with the
    offset of its name and what its argument is reached by."""

    head = _HEAD.match(expression)
    assert head is not None  # every part of it is optional
    chain = [
        (applied.group(1), offset + applied.start(1), _reached_by(applied.group(2)))
        for applied in _FILTER.finditer(expression, head.end())
    ]
    return _reached_by(head.group(1)), chain


def _reached_by(operand: str | None) -> frozenset[str]:
    """The variable an operand reads, with its first attribute; none for a constant."""

    variable = _VARIABLE.match(operand) if operand else None
    return frozenset() if variable is None or variable.group(1) in _LITERALS else frozenset({variable.group()})


def _through(bound: frozenset[str], name: str) -> frozenset[str]:
    """What ``name``, a variable with its first attribute, reads when its variable is
    ``bound`` to those names: ``query.q`` with ``query`` bound to ``request.GET`` reads
    ``request.GET``."""

    attribute = name.partition(".")[2]
    return frozenset(".".join(f"{b}.{attribute}".split(".")[:2]) if attribute else b for b in bound)


def request_processor(modules: Iterable[tuple[nodes.Module, ScopeTable]]) -> bool:
    """Whether every Django template engine the project's settings configure runs the
    ``request`` context processor, for certain: each module-level assignment to
    ``TEMPLATES`` is a literal list of literal engines, at least one of them
    ``DjangoTemplates``, and each of those lists the processor in a literal
    ``context_processors``; no other code names the module's ``TEMPLATES``, or a
    ``TEMPLATES`` it does not bind (a star import), which could change it. A
    ``TEMPLATES`` bound in a function or a class is another name, which configures
    nothing and changes nothing. A mere mention of the processor proves nothing."""

    assignments = mentions = 0
    for module, scopes in modules:
        for node, scope in _scoped(module, scopes):
            if isinstance(node, nodes.Name) and node.identifier == _ENGINES_SETTING:
                if scopes.resolve(scope, node.identifier).kind in (ResolutionKind.GLOBAL, ResolutionKind.UNBOUND):
                    mentions += 1
            elif isinstance(node, nodes.Assign) and _names_engines(node.target) and scope == scopes.module_scope.id:
                if not _runs_request_processor(node.value):
                    return False
                assignments += 1
    return assignments > 0 and mentions == assignments


def _scoped(module: nodes.Module, scopes: ScopeTable) -> Iterator[tuple[Node, ScopeId]]:
    """Every node of ``module`` with the scope it stands in."""

    stack: list[tuple[Node, ScopeId]] = [(node, scopes.module_scope.id) for node in module.body]
    while stack:
        node, scope = stack.pop()
        yield node, scope
        if isinstance(node, nodes.Function | nodes.Lambda | nodes.Class | nodes.Comprehension):
            scope = scopes.scope_for(node).id
        stack.extend((child, scope) for child in children(node))


def _names_engines(target: nodes.Expression) -> bool:
    return isinstance(target, nodes.Name) and target.identifier == _ENGINES_SETTING


def _runs_request_processor(engines: nodes.Expression) -> bool:
    if not isinstance(engines, nodes.List | nodes.Tuple):
        return False
    django = 0
    for engine in engines.elements:
        settings = _literal_dict(engine)
        backend = settings.get("BACKEND") if settings is not None else None
        if settings is None or not isinstance(backend, nodes.Constant) or not isinstance(backend.value, str):
            return False
        if backend.value != _DJANGO_ENGINE:
            continue
        django += 1
        options = _literal_dict(settings.get("OPTIONS"))
        processors = options.get("context_processors") if options is not None else None
        if not isinstance(processors, nodes.List | nodes.Tuple):
            return False
        if not any(isinstance(p, nodes.Constant) and p.value == REQUEST_PROCESSOR for p in processors.elements):
            return False
    return django > 0


def _literal_dict(expression: nodes.Expression | None) -> dict[str, nodes.Expression] | None:
    """A dict display with constant string keys, by key; None for anything else."""

    if not isinstance(expression, nodes.Dict):
        return None
    found: dict[str, nodes.Expression] = {}
    for key, value in expression.items:
        if not isinstance(key, nodes.Constant) or not isinstance(key.value, str):
            return None
        found[key.value] = value
    return found


def unread_renders(module: str, graph: CallGraph, models: ModelTable, names: frozenset[str]) -> Iterator[str]:
    """Where ``module`` renders a template the engine cannot read: named by an
    expression, or by a name none of the project's templates has."""

    found = {repr(name) for name in names}
    for function in graph.functions:
        for site in graph.sites(function):
            if not isinstance(site.target, ExternalSymbol):
                continue
            render = models.template_render(site.target.symbol)
            if render is None:
                continue
            given = site.arguments.given(render.keyword, render.position)
            if given is not None and not given[0]:
                continue  # names no template: the call fails
            where = f"{module}:{site.location.start_line}"
            named = given[1] if given is not None else None
            # A constant string, as Python writes it; anything else is an expression.
            if named is None or named[0] not in "'\"":
                yield f"{where} names a template by an expression"
            elif named not in found:
                yield f"{where} names {named}, not found"


def _expressions(text: str) -> Iterator[tuple[int, str, bool]]:
    """Each variable and tag of a template, with its offset and whether it is a tag,
    leaving out comments and what ``{% comment %}`` and ``{% verbatim %}`` enclose."""

    skipping: str | None = None
    for match in _SYNTAX.finditer(text):
        variable, tag = match.group(1), match.group(2)
        words = tag.split() if tag is not None else []
        if skipping is not None:
            if words[:1] == [skipping]:
                skipping = None
        elif words[:1] in (["comment"], ["verbatim"]):
            skipping = f"end{words[0]}"
        elif variable is not None:
            yield match.start(1), variable, False
        elif tag is not None:
            yield match.start(2), tag, True


def _position(text: str, offset: int) -> tuple[int, int]:
    """The one-based line and column of ``offset`` in ``text``."""

    return text.count("\n", 0, offset) + 1, offset - text.rfind("\n", 0, offset)


class EscapedTemplates(Analysis[frozenset[str]]):
    """The names of the project templates that escape everything they render, provided
    by the engine for a project; none on its own."""

    name: ClassVar[str] = "taint.escaped_templates"

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> frozenset[str]:
        return frozenset()
