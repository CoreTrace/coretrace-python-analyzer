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
of another name, shipped by an installed package — is never assumed to escape.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

from coretrace_python.analysis import Analysis, AnalysisContext
from coretrace_python.interprocedural import discover_files

TEMPLATES_DIRECTORY = "templates"

_OUTPUT, _TAG, _URL = "\x00", "\x01", "/u"
_SYNTAX = re.compile(r"{{(.*?)}}|{%(.*?)%}|{#.*?#}", re.DOTALL)
_AUTOESCAPE_OFF = re.compile(r"""["']autoescape["']\s*:\s*False|\bautoescape\s*=\s*False""")

# Django's own libraries, tags and filters. Every filter but ``safe`` and ``safeseq``
# escapes its input, or returns it for autoescaping to escape, when autoescaping is on.
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
_FILTERS = frozenset(
    {
        "add", "addslashes", "capfirst", "center", "cut", "date", "default", "default_if_none",
        "dictsort", "dictsortreversed", "divisibleby", "escape", "escapejs", "escapeseq",
        "filesizeformat", "first", "floatformat", "force_escape", "get_digit", "iriencode",
        "join", "json_script", "last", "length", "length_is", "linebreaks", "linebreaksbr",
        "linenumbers", "ljust", "lower", "make_list", "phone2numeric", "pluralize", "pprint",
        "random", "rjust", "slice", "slugify", "stringformat", "striptags", "time", "timesince",
        "timeuntil", "title", "truncatechars", "truncatechars_html", "truncatewords",
        "truncatewords_html", "unordered_list", "upper", "urlencode", "urlize", "urlizetrunc",
        "wordcount", "wordwrap", "yesno", "language_name", "language_name_local",
        "language_bidi", "language_name_translated", "localize", "unlocalize", "localtime",
        "utc", "timezone", "apnumber", "intcomma", "intword", "naturalday", "naturaltime",
        "ordinal",
    }
)

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
        verdicts = [_inspect(_read(path)) for path in paths]
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
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


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


class EscapedTemplates(Analysis[frozenset[str]]):
    """The names of the project templates that escape everything they render, provided
    by the engine for a project; none on its own."""

    name: ClassVar[str] = "taint.escaped_templates"

    @classmethod
    def compute(cls, ctx: AnalysisContext) -> frozenset[str]:
        return frozenset()
