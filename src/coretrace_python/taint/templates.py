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
  attribute, an attribute or a tag name;
- no Python file of the project turning autoescaping off.

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
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import ClassVar

from coretrace_python.analysis import Analysis, AnalysisContext
from coretrace_python.hir import nodes
from coretrace_python.hir.visitors import Node, children
from coretrace_python.interprocedural import (
    CallGraph,
    ExternalSymbol,
    TemplateFilter,
    discover_files,
)
from coretrace_python.semantic.scopes import ResolutionKind, ScopeId, ScopeTable
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.source import SourceId, SourceSpan
from coretrace_python.taint.models import ModelTable

TEMPLATES_DIRECTORY = "templates"

_OUTPUT, _TAG, _URL = "\x00", "\x01", "/u"
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
_ATTRIBUTE = re.compile(rf"([^\s\"'>/=]+)(?:\s*=\s*({_QUOTED}|[^\s\"'=<>`]+))?")
_START_TAG = re.compile(rf"<([A-Za-z][^\s/>]*)((?:\s*[^\s\"'>/=]+(?:\s*=\s*(?:{_QUOTED}|[^\s\"'=<>`]+))?)*)\s*/?>")
_RAW_TEXT = re.compile(r"<(script|style)\b[^>]*>(.*?)</\1\s*>", re.DOTALL | re.IGNORECASE)
_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_END_TAG = re.compile(r"</[A-Za-z][^>]*>")
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

REQUEST_PROCESSOR = "django.template.context_processors.request"
_DJANGO_ENGINE = "django.template.backends.django.DjangoTemplates"
_ENGINES_SETTING = "TEMPLATES"


def escaped_templates(root: Path) -> frozenset[str]:
    """The names of the templates under ``root`` that escape every variable they render,
    as ``render_to_string`` names them (their path below a ``templates`` directory)."""

    found: dict[str, list[Path]] = {}
    for path in discover_files(root):
        if path.suffix == ".py" and _AUTOESCAPE_OFF.search(_read(path)):
            return frozenset()
        for name in _names(path.relative_to(root).parts):
            found.setdefault(name, []).append(path)
    local: dict[str, bool] = {}
    requires: dict[str, set[str]] = {}
    for name, paths in found.items():
        verdicts = [_verdict(path) for path in paths]
        local[name] = all(safe for safe, _ in verdicts)
        requires[name] = {needed for _, needs in verdicts for needed in needs}
    escaped = {name for name, safe in local.items() if safe}
    changed = True
    while changed:
        kept = {name for name in escaped if requires[name] <= escaped}
        changed = kept != escaped
        escaped = kept
    return frozenset(escaped)


def _names(parts: tuple[str, ...]) -> Iterator[str]:
    for index, part in enumerate(parts[:-1]):
        if part == TEMPLATES_DIRECTORY:
            yield "/".join(parts[index + 1 :])


def _read(path: Path) -> str:
    return _text(path) or ""


def _verdict(path: Path) -> tuple[bool, set[str]]:
    """Whether one template file escapes all it prints, and what it needs: a file the
    engine cannot read is not established to escape, like a template it cannot find."""

    text = _text(path)
    return (False, set()) if text is None else _inspect(text)


def _text(path: Path) -> str | None:
    """The text of ``path``, or None when it cannot be read."""

    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _inspect(text: str) -> tuple[bool, set[str]]:
    """Whether the template escapes all it prints itself, and the templates it extends
    or includes, which must escape too."""

    requires: set[str] = set()
    html: list[str] = []
    skipping: str | None = None
    position = 0
    text = text.replace(_OUTPUT, "").replace(_TAG, "")
    for match in _SYNTAX.finditer(text):
        variable, tag = match.group(1), match.group(2)
        words = tag.split() if tag is not None else []
        if skipping is not None:
            if words[:1] == [skipping]:
                if skipping == "endverbatim":
                    html.append(text[position : match.start()])
                skipping, position = None, match.end()
            continue
        html.append(text[position : match.start()])
        position = match.end()
        if variable is not None:
            if not _escaping_filters(variable):
                return False, requires
            html.append(_OUTPUT)
        elif words and words[0] in ("comment", "verbatim"):
            skipping = f"end{words[0]}"
            if words[0] == "verbatim":
                position = match.end()
        elif words:
            name = words[0]
            if name not in _TAGS:
                return False, requires
            if name == "load" and not set(_loaded(words[1:])) <= _LIBRARIES:
                return False, requires
            if name == "autoescape" and words[1:] != ["on"]:
                return False, requires
            if name == "filter" and not _escaping_filters(tag.split(None, 1)[1] if len(words) > 1 else ""):
                return False, requires
            if name in ("extends", "include"):
                needed = _constant(words[1] if len(words) > 1 else "")
                if needed is None:
                    return False, requires
                requires.add(needed)
            html.append(_OUTPUT if name in _PRINTING else _URL if name in ("url", "static") else _TAG)
    if skipping is not None:
        return False, requires
    html.append(text[position:])
    return _escapes_where_printed("".join(html)), requires


def _loaded(words: list[str]) -> list[str]:
    """The libraries ``{% load a b %}`` or ``{% load x y from lib %}`` loads."""

    return words[words.index("from") + 1 :] if "from" in words else words


def _escaping_filters(expression: str) -> bool:
    filters = re.sub(_QUOTED, "", expression).split("|")[1:]
    return all(f.split(":", 1)[0].strip() in _FILTERS for f in filters)


def _constant(word: str) -> str | None:
    return word[1:-1] if len(word) >= 2 and word[0] == word[-1] and word[0] in "\"'" else None


def _escapes_where_printed(html: str) -> bool:
    """Whether every output marker of ``html`` stands where HTML escaping protects it."""

    position = 0
    while (start := html.find("<", position)) != -1:
        rest = html[start:]
        comment = _COMMENT.match(rest)
        raw = _RAW_TEXT.match(rest)
        tag = _START_TAG.match(rest)
        end = _END_TAG.match(rest)
        if comment:
            position = start + comment.end()
        elif raw:
            if _OUTPUT in raw.group(2) or not _attributes_escape(raw.group(0)[: raw.start(2)]):
                return False
            position = start + raw.end()
        elif tag:
            if _OUTPUT in tag.group(1) or not _attributes_escape(tag.group(2)):
                return False
            position = start + tag.end()
        elif end:
            if _OUTPUT in end.group(0):
                return False
            position = start + end.end()
        else:
            # ``<{{ name }}``: the variable would name a tag, escaping cannot stop it.
            if rest[1:].lstrip("/ \t\n").startswith(_OUTPUT):
                return False
            position = start + 1
    return True


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
    ``names``, as a render call names them; the filters they apply, as ``calls``; where
    they name a template the engine cannot read, as ``unread``; and, by name, the filter
    calls rendering each template makes with the context keys reaching them, as
    ``filters``."""

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
class _Template:
    """What one template file applies and references, and the ``blocks`` it defines."""

    applications: tuple[_Application, ...]
    references: tuple[_Reference, ...]
    blocks: frozenset[str]

    def rendered(self, blocks: tuple[str, ...], overridden: frozenset[str]) -> bool:
        """Whether what stands in ``blocks`` renders when a template extending this one
        defines the ``overridden`` blocks: a template extending another renders only
        its blocks, where they replace the blocks of that name in what it extends."""

        extends = any(reference.extends for reference in self.references)
        return not overridden.intersection(blocks) and (bool(blocks) or not extends)


def project_templates(root: Path) -> ProjectTemplates:
    """What the templates under ``root`` call, and the templates they include or extend
    that the engine cannot read: named by an expression, or by a name found under no
    ``templates`` directory. A template file that cannot be read is unread too. A name
    found in several files gives no ``filters``: which one renders depends on the
    loaders."""

    found = {path: tuple(_names(path.relative_to(root).parts)) for path in discover_files(root)}
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
        read[path] = _read_scopes(text, SourceId(str(path)))
        for reference in read[path].references:
            where = f"{relative}:{_position(text, reference.offset)[0]}"
            if reference.name is None:
                unread.append(f"{where} names a template by an expression")
            elif reference.name not in files:
                unread.append(f"{where} names {reference.name!r}, not found")
    calls = tuple(FilterCall(a.symbol, a.span) for template in read.values() for a in template.applications)
    filters = {
        name: tuple(
            dict.fromkeys(
                TemplateFilter(symbol, span, where, tuple(sorted(value)), tuple(sorted(argument)))
                for symbol, span, where, value, argument in _reaching(name, files, read, frozenset())
            )
        )
        for name in files
    }
    return ProjectTemplates(frozenset(files), calls, tuple(unread), filters)


def _reaching(
    name: str,
    files: Mapping[str, list[Path]],
    read: Mapping[Path, _Template],
    visiting: frozenset[str],
    overridden: frozenset[str] = frozenset(),
) -> Iterator[tuple[SymbolId, SourceSpan, str, frozenset[str], frozenset[str]]]:
    """The filters rendering the template ``name`` applies, in it and in what it includes
    or extends, each with the template applying it and the names free in ``name`` whose
    values reach its value and its argument; the templates extending ``name`` on the way
    define the ``overridden`` blocks."""

    paths = files.get(name, [])
    if len(paths) != 1 or paths[0] not in read or name in visiting:
        return
    template = read[paths[0]]
    for application in template.applications:
        if template.rendered(application.blocks, overridden):
            yield application.symbol, application.span, name, application.value, application.argument
    for reference in template.references:
        if reference.name is None:
            continue
        if reference.extends:
            found = _reaching(reference.name, files, read, visiting | {name}, overridden | template.blocks)
        elif template.rendered(reference.blocks, overridden):
            found = _reaching(reference.name, files, read, visiting | {name})
        else:
            continue
        for symbol, span, where, value, argument in found:
            yield symbol, span, where, reference.maps(value), reference.maps(argument)


def _read_scopes(text: str, source: SourceId) -> _Template:
    """The filters a template applies and the templates it includes or extends, with the
    names free in it that reach each: through ``{% for %}``, ``{% with %}`` and the
    ``as`` of other tags, which bind a name until their block ends, the arguments of
    earlier filters, and the output of ``{% filter %}`` blocks."""

    applications: list[_Application] = []
    references: list[_Reference] = []
    opened: list[str] = []
    defined: set[str] = set()
    scopes: list[dict[str, frozenset[str]]] = [{}]
    blocks: list[tuple[list[tuple[str, int, frozenset[str]]], set[str]]] = []

    def free(names: frozenset[str]) -> frozenset[str]:
        found: set[str] = set()
        for name in names:
            variable = name.split(".", 1)[0]
            bound = next((scope[variable] for scope in reversed(scopes) if variable in scope), None)
            found |= {name} if bound is None else _through(bound, name)
        return frozenset(found)

    def apply(head: frozenset[str], chain: list[tuple[str, int, frozenset[str]]]) -> frozenset[str]:
        """Record the filters of ``chain`` applied to a value the free names ``head``
        reach; the free names reaching the value of the whole expression."""

        value = head
        for name, offset, argument in chain:
            symbol = FILTER_FUNCTIONS.get(name)
            if symbol is not None:
                line, column = _position(text, offset)
                span = SourceSpan(source, line, column)
                applications.append(_Application(symbol, span, value, free(argument), tuple(opened)))
            value |= free(argument)
        return value

    for offset, expression, tag in _expressions(text):
        if not tag:
            head, chain = _chain(expression, offset)
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
        elif "as" in words[1:-1]:
            target = words[words.index("as", 1) + 1]
            scopes[-1][target] = values.get(words[1], frozenset()) if name == "regroup" else frozenset()
    return _Template(tuple(applications), tuple(references), frozenset(defined))


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
