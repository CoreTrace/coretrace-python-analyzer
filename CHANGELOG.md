# Changelog

## 0.22.0 (2026-10-08)

### Compatibility and migration

- Baselines change format twice in this release, and no baseline is ever converted or rewritten on its own. Without a key, baselines are recorded in schema 3, whose entries hold digests of the text a finding covers instead of that text (#226); with a key, in schema 4, keyed with HMAC-SHA-256 (#235). Schema 1 and 2 files are still read without a key, with exact matching only: an entry identifies a finding on a single line as before, a finding over several lines is reported new, and every run warns on standard error that the file may contain secrets in plain text. While a key is given, only a schema 4 baseline is read: an unkeyed one (schema 1, 2 or 3) stops the check with exit status 2. To migrate, review the findings, then record the baseline explicitly with `--record-baseline` (schema 3, or schema 4 with a key); the old file's secrets remain in the history of a repository that committed it.
- A keyed baseline needs its key: from the file `--baseline-key-file` names, which must lie outside the analysed directory and be another file than the baseline, or else from `CORETRACE_BASELINE_KEY`; the file comes first. The key is at least 16 bytes, trailing line breaks are not part of it, and an empty variable is an error. Without the key, or with another one, the check stops with exit status 2 and records nothing; recording over a schema 4 baseline without its key is refused too. Rotating the key is an explicit `--record-baseline` under the new key. Generate the key at random (`python -c "import secrets; print(secrets.token_hex(32))"`) and keep it out of the repository: a key a person chooses can be guessed from the baseline (#225).
- Findings may move or reappear once: dependency and configuration findings of a check given a relative root are now located relative to that root (`uv.lock`, not `proj/uv.lock`) (#212); findings in JSON, TOML and lock files are located at their own line or by a JSON pointer (#222); a vulnerable package pinned in a lock file is located at its own `[[package]]` entry. Baselines recorded before should be recorded again after review.
- A finding whose line cannot be established has a file location: in the JSON report its `line`, `column`, `end_line` and `end_column` are `null` and a `pointer` field names the value (RFC 6901); its SARIF location has no `region`, the pointer under the location's `properties`; the text report shows `path:` without a line. Inline suppressions apply only to findings at a verified line (#222).
- `command-injection` severities change: an element of an argument list run without a shell is reported by what the input controls there, `medium` by default, `high` when an option of the program runs it, refuted when a constant prefix keeps it from being an option or an option keeps it as data (#217). The rule id is unchanged; the message of an option injection is titled `Option injection` (#232). Existing suppressions and baselines of the rule keep matching by rule id; baselined findings whose severity changed are still baselined.
- A file whose syntax is nested more than 200 levels deep (a long chain of `+` or chained calls, which only generated code writes) is reported as a `syntax-error` and not analysed, instead of aborting the whole scan (#234).
- The cache format changes (14): caches built by an earlier version miss once.
- Plugin API: `Finding.span` is a `Location`, a `SourceSpan` or a `FileLocation` (#222); `Assessment` gains optional `title` and `metadata` fields (#232). Plugins that read `finding.span.start_line` should check for a `SourceSpan` first.

### Baseline

- `--record-baseline` records the current findings as the baseline even when the file exists; the file (the target of a symbolic link) is replaced atomically, keeping its permissions, only once the analysis succeeded and the report is rendered, so the previous baseline stays in place when the check fails (#235).
- `--baseline-key-file FILE` gives the key of a schema 4 baseline; `CORETRACE_BASELINE_KEY` gives it otherwise. The key never appears in a report, message or file; a `key_check` value in the baseline tells the key apart without revealing it (#235).
- An entry is recognised by a digest of the text of every line its finding covers: a secret written over several lines, whose first line does not hold it, is new once its body changes (#223, #226). A finding at a file location is recognised by digests of its value and of its pointer, whose keys may themselves be secrets (#222, #226).
- Line numbers follow one rule everywhere, as Python counts lines (`\n`, `\r\n` or a lone `\r`, never U+2028 or a form feed), so a fingerprint or a suppression never refers to another line (#222).

### Secrets

- A string expression whose parts are all constant (`+` of strings, `sep.join` of a list or tuple of strings, an f-string whose parts are all constant) is judged as one value, reported once at the whole expression with the strongest finding of the value and its pieces; `PASSWORD = "Zx81kQpL" + "w0RtY7vB" + …` and `TOKEN = "ghp_" + "…"` are now reported. When the whole value is no secret, its pieces are judged on their own, as before (#231).
- A `.env`, YAML, INI or properties value that continues past its key's line (an open quote, a trailing backslash, deeper indentation) is located over every line it continues on (#226).
- Password hashes are no longer reported as hardcoded credentials: modular crypt and PHC strings, bcrypt, Werkzeug's `scrypt:`/`pbkdf2:` and Django's encodings; an identifier followed by text of another shape is still a plaintext password (#214).
- The `url` pattern no longer reports placeholders (`?token=...`, `<token>`) nor an IP address or `localhost` and a port before `@` (proxy specifications); a password runs to the last `@` before the host. A `SecretPattern` may name a `secret` group, which the placeholder check then judges (#215).
- In `package-lock.json` and `npm-shrinkwrap.json`, the keys of dependency, `requires` and `bin` maps are package or command names, not credential names (#216).

### Command injection

- The command a process starter runs (`subprocess.run`, `call`, `check_call`, `check_output`, `Popen`) is read element by element, with a documented option model for git, ssh, tar, rsync, find, rm, cmd, PowerShell, the shells and the interpreters, wrappers such as sudo, env, xargs and timeout read again with their program's model; the evidence says what the input controls (#217).
- The finding's `injection` metadata says what the input is when the rule establishes it: `command` (it runs or chooses what runs) or `option` (an option, or the value of an option not established to run it), in the JSON report and as the only `properties` of the SARIF result; it is absent when the kind cannot be established (#232, #236).
- The script after `pwsh -File` is a file name, however it is spelled (#229). `gtar` is read as GNU tar, `bsdtar` as libarchive's (`-I` names a file of patterns), and a bare `tar`'s `-I`, `--to-command` and `--checkpoint-action` are `high` and kept for review (#230).

### Dependencies

- A vulnerable package pinned in `uv.lock` or `poetry.lock` is located at its own entry, and the message states the evidence: `werkzeug 3.1.5, pinned in uv.lock, is in <3.1.6 (required by flask)` (#222). Requirements of `pyproject.toml` are located at their own element or key, or given a file location.
- `--advisories` and `--policy` paths, and the root itself, are resolved once, so their findings and notes are located relative to the root whatever the working directory (#212).

### Frontend

- Syntax nested deeper than the analysis follows is rejected before PyHIR is built, and Python 3.11's parser recursion is a parse error of the file, so the rest of the project is still analysed (#234).

### Documentation

- `docs/usage.md` documents keyed baselines, `--record-baseline`, `--baseline-key-file`, file locations and the `injection` metadata; `docs/plugins.md` documents `FileLocation`, `Assessment.title` and `metadata`, and the `secret` group of a `SecretPattern`. Repository governance files (contributing, conduct, authors, security) are added (#204).

## 0.21.0 (2026-09-30)

### Advisories

- An `argument` condition may carry `present: true`: the argument being passed at all, whatever its value, is the condition, as a `\r` in `web.Response(reason=…)` needs `reason` given, constant or not. It names the argument by keyword or position as today and excludes `values` and `default`. A call giving the argument — positionally, by keyword, or through a `**` literal with constant keys, folded into the keywords — meets it even when the value is unknown, so attacker input there makes the call exploitable; a call surely not giving it is ruled out (`app:5 python.aiohttp.web.Response(reason absent)`) and a project passing only such calls stays `not_affected`; a call unpacking `*args` or a `**mapping` whose keys are not written leaves it pending review (#195).
- A curated entry point may declare `suffixes`, for receivers the engine cannot type: `Item.objects.annotate(...)` derives the project's own `python.app.models.Item.objects.annotate`, which the canonical `python.django.db.models.QuerySet.annotate` entry point never matches. A suffix matches any symbol of the project's own modules ending with a dot plus the suffix, on dot boundaries as a `SuffixSink` matches, never another package's symbol; a queryset chain is declared explicitly (`objects.filter.annotate`), and a suffix is at least two dot-separated names. The finding keeps the advisory's symbol as `entry_point` and the derived one as `symbol`; conditions, `attacker_arguments` and the ruled-out evidence of contradicted calls apply through a suffix as through the exact symbol. An exact advisory sink whose symbol a bundled suffix sink also matches (`objects.extra`) now composes its kinds with the suffix sink's instead of shadowing them (#197).
- An advisory condition of kind `sequence` says the flaw spans two calls on one receiver: the first call leaves state on the object the entry point — the second call — reuses. It names the `method` the first call must be, by canonical name or `.`-suffix, and, optionally, the argument that call must carry (`{"kind": "sequence", "method": "Session.get", "argument": "verify", "values": ["False"], ...}`), so `s = requests.Session(); s.get(url, verify=False); s.get(other)` marks the second `get` reachable with the prior call as evidence (requests CVE-2024-35195). A receiver followed whole — bound once to the result of a call or a `with` and used only to call its methods — with no matching call on every path to the entry call rules it out (`app.fetch:6 python.requests.Session.get(no prior Session.get on the receiver)`), and a project with only such calls stays `not_affected`. A receiver the engine cannot follow (a parameter, a module-level instance, one passed to another function or mutated through an attribute), a matching call only in a branch or textually later, an unpacking that leaves the first call's arguments undecided, or an entry call that itself carries the named argument — its own prior across the iterations of a loop — leaves the condition pending review (#194).

### Plugins

- `CallSite.prior_calls` records, for a receiver the engine follows whole, the other external calls on the same receiver (`PriorCall`: symbol, location, arguments, and whether it surely executes before this one), in source order; `CallGraph.prior_calls_at` reads it by location, and `check_conditions` takes it to decide `sequence` conditions. The cache format changes.

## 0.20.0 (2026-09-30)

### Advisories

- An advisory condition of kind `keyword_name` says the attacker must choose a keyword name of the call, as Django's ORM takes column aliases and lookups (`annotate(**{alias: expr})`); it carries its text and nothing else. The engine decides it from the keys of what the call expands with `**`, apart from the mapping's values: keys carrying attacker input meet it and the call is exploitable; constant keys, a dict literal with string keys, `dict(total=...)` or plain keywords, contradict it whatever the values carry, so the call is ruled out (`app.views:12 python.app.models.Item.objects.annotate(keywords=total)`, `(keywords absent)` for a call passing no keyword) and a project passing only those stays `not_affected`; keys the engine cannot establish, a `**extra` parameter, a mapping built elsewhere, `dict(zip(...))`, leave it pending review, so the call is reachable, and exploitable when the mapping's values carry input (#193).

### Analysis

- The keys of a mapping carry taint of their own, apart from its values: a dict literal `{alias: expr}`, `dict([(alias, expr)])`, a comprehension `{k: expr for k in input}` and a subscript assignment `mapping[alias] = expr` taint the `keys` location of the mapping's abstract object, which `{**mapping}`, `dict(mapping)` and `dict(**mapping)` copy; the value taint of a literal is what it was. A call expanding such a mapping with `**` passes its keys as the keyword names of the call, a way of passing only an advisory sink reads. Keys through a project wrapper are not followed; `mapping.update(other)`, `mapping.setdefault(k, v)`, `for k in mapping` and `mapping.keys()` carry no key taint; a mapping bound by a `Phi` is unknown (#193).

### Plugins

- `Arguments.keyword_unpacked` says a call expands a `**mapping` whose keys it does not write; a `**` literal with constant keys that nothing else uses is recorded as its keywords, so `given()` decides safe arguments and argument conditions for it. The cache format changes.

## 0.19.0 (2026-09-29)

### Analysis

- Two files with the same Python module name, `a/app.py` and `z/app.py` outside any package, no longer overwrite each other: both are discovered, analysed and covered whatever the order they are found in. The engine tells them apart by their path from the root as a module name, `a.app` and `z.app`, in the module graph, the summary index, the cache keys and what project plugins see; a unique name stays what it was. An import of such a name resolves to the file in the importer's own root only, and one no root resolves is not followed. Each colliding file carries an `ambiguous-module` note and is covered as `ambiguous`, since a model or a route naming `python.app.main` applies to every definition of that symbol, and so does an importer whose import stayed unresolved; a VEX statement over such a project stays `under_investigation` (#182).

### Precision

- A `TEMPLATES` assigned inside a function or a class no longer counts as Django settings: only a module-level assignment can activate the `request` context processor, and only a mention of the module's `TEMPLATES` elsewhere leaves that activation uncertain. A function-local `TEMPLATES`, called or not, used to enable the implicit request source, upgrading a template filter finding to exploitable (#184).
- A template block that renders `{{ block.super }}` keeps the parent block's content, so the filters the parent applies stay fed by the render context, with the parent template as the place of the call; a block without it still replaces the parent's whole block, and a chain of templates keeps exactly the parents each level renders. The parent's filters used to drop out of the exploitable flow as soon as a child defined the block (#185).
- A project tag library registering a filter of a built-in's name replaces the built-in in every Django template loading it before applying the filter, as Django's parser does: `{% load custom %}{{ bio|striptags }}` calls the project's `striptags` when `app/templatetags/custom.py` registers one, so it is no longer a reachable or exploitable call to `django.template.defaultfilters.striptags`; the project's function is ordinary code, analysed as any other. A load affects only the filters after it, a later load overrides an earlier one, `{% load striptags from custom %}` replaces only what it names, and Django's own libraries change nothing. The analyzer reads the registrations on `register`, a `django.template.Library` however it is imported, in decorator and call form, at module level or under `if`, `try` or a function. Where it cannot tell what a library registers — no such library file, one it cannot read or parse, a name not written as a constant, `register` passed elsewhere or filled through `filters=` or `register.filters`, or two apps giving the name and registering different filters — a filter of that name applied under the load is neither the built-in nor certainly replaced: no call is claimed, and the load counts among the templates the analyzer could not read (`app/templates/app/profile.html:1 loads 'custom', not read`), so an advisory naming the filter stays `under_investigation` in the VEX document. The settings' `OPTIONS["libraries"]` and `OPTIONS["builtins"]` are not read (#183).

### Plugins

- `ModuleFunction.aliases` gives a project plugin the module-level names bound to a function by assigning one name to another, transitively and in source order, so an integration declaring a handler by the name a module binds (`handlers.main`) can report a name the engine resolves to no function; a method or a nested function has none. The cache format changes.
- An `EntryPoint` naming a project function or class applies through a module-level alias of it: `main = actual` makes `python.app.handlers.main` name `actual`, so a deployment declaring `handlers.main` reaches the function doing the work. An alias is an assignment of one name to another at module level, followed transitively and in source order, in a conditional or a `try` as well; a name bound inside a function or class, or to a call, an import or anything but a name, is no alias, and the engine still infers nothing from a name. A model naming a method wins over one naming its class, whichever name it uses.

## 0.18.0 (2026-09-28)

### Precision

- A Django template file the analyzer cannot read, because of its permissions, no longer counts as escaping everything it renders: it read the file as empty text, and an empty template escapes. The flow through `render_to_string` stays `xss`, and a template extending or including the unreadable one is not established to escape either, as for a template the analyzer cannot find. An unreadable file was already listed among the templates the project names but the run could not read.

### Plugins

- An `EntryPoint` may name a project function or class by its own symbol, `python.app.handlers.main`, so an integration reading a deployment declaration, a SAM template or a `serverless.yml`, can make a bare Lambda handler an entry point; the engine itself infers nothing from a function's name. `EntryPoint.inputs` limits the parameters that are input to the given positions, after `self` for a method: the handler's event, not its context (#180).

## 0.17.0 (2026-09-28)

### Plugins

- `BasePattern(pattern, label, parameters, kinds)` makes the methods of a class whose base's canonical symbol matches a regular expression entry points, for bases generated per project such as a gRPC servicer's, whatever the module's prefix and however the base is imported. Each parameter after `self` is, by position, either input of the model's kinds or an object of a class the model names, which the sources on that class taint without the object being input: a `Source` on `ServicerContext.invocation_metadata` gives the client's metadata, and `peer()` gives nothing. When the project holds the base, only the methods the base defines are entry points, so a servicer's utility methods are not; otherwise every method with the listed number of parameters is. `async` methods and the messages of an iterated parameter are covered (#176).

## 0.16.0 (2026-09-27)

### Advisories

- A filter of Django's own libraries that a project template applies is a call to the function behind it, at the template's line: `{{ bio|striptags }}` calls `django.template.defaultfilters.striptags`, and so do filters in tag arguments and `{% filter %}` blocks. An advisory entry point naming that function is reachable there, whether or not a Python call names the template, since a class-based view renders its `template_name` inside Django. A template the analyzer cannot read may apply any filter: when the project names one by an expression, or by a name found under no `templates` directory, in `render`, `render_to_string`, `TemplateResponse`, `{% include %}` or `{% extends %}`, an advisory whose entry points include a template filter stays `under_investigation` in the VEX document, and the notes say where. `render`, `TemplateResponse` and `SimpleTemplateResponse` are now template renders like `render_to_string` (#146).
- Attacker input in a render context reaching a template filter makes an advisory entry point naming that filter exploitable at the render call. The analyzer links them only where it is certain of the value: a dict literal with constant keys that the render call alone uses, and a filter the rendered template applies to a context variable, directly or through `{% for %}`, `{% with %}`, constant `{% include %}` and `{% extends %}`, earlier filter arguments and `{% filter %}` blocks, in the blocks that render. A name a tag binds shadows the context, and `{% include ... only %}` passes none of it. The filter's value is its first argument, the filter's own argument its second. A project function rendering what it receives carries it the same way (#146).
- The request the `request` context processor adds reaches a template's filters too, as `{{ request.GET.q|striptags }}`, only where the analyzer is certain of it: every Django template engine the settings assign to `TEMPLATES`, as literals no other code names, lists the processor; the render call passes the request (`render`, `TemplateResponse`, `render_to_string` given `request`) with a certain context, absent or a dict literal; nothing shadows `request`; and the template reads a text attribute of the request object, such as `GET`, `POST`, `COOKIES` or `headers`. Otherwise the filter stays reachable (#146).

## 0.15.0 (2026-09-26)

### Precision

- `open-redirect` judges a flow on the destination a browser resolves from the target's constant text, with its own criteria rather than SSRF's. A reference on the current site keeps the browser there, so the flow is refuted. Such a reference is `/` followed by a character that is not a slash, a backslash, a space or a control character, as in `"/profile/" + id`; or `?`, `#`, or a relative path whose first segment holds no `:`. A fixed absolute host makes the flow a hotspot, since the input chooses the path, where that host may redirect again. Everything else stays a vulnerability, including `"/" + next`: `//evil.com` is another host. The URL facts both rules read are one shared proof, `coretrace_python.taint.urls`, and `ssrf` now reads it too, with the same verdicts. The regression corpus is unchanged: its three `open-redirect` findings redirect to values built without constant text (#168).

### Advisories

- An advisory entry point may declare a `host` condition: the attacker must choose the host of the URL passed as the named argument. It is decided from the URL's constant text, the proof `ssrf` and `open-redirect` read. A fixed host with redirects disabled in the call leaves the call reachable, not exploitable. A fixed host with redirects followed keeps it exploitable, because a redirect may lead to a host the attacker controls, and the condition pending review says so. Input in the query does not choose the host. Anything else stays pending review, and so do the environment conditions. A `host` condition must name its argument and carry nothing else (#170).

## 0.14.0 (2026-09-26)

### Precision

- `ssrf` judges a flow on how `+` and f-strings build its URL. A fixed host is a limited proof: when constant text fixes `scheme://host` and ends the authority with `/`, `?` or `#` before any input, as in `"https://api.example.com/users/" + id`, the flow is a hotspot, because the input still chooses the path and a redirect may lead elsewhere. It is refuted only when the constant text fixes the path too, the input reaching the query or fragment only, and the call disables redirects (`allow_redirects=False`, `follow_redirects=False`). A module-level name counts as known text when the module binds it once to a string literal and never rebinds it. Everything else stays a vulnerability, including a base of unknown value such as an imported `BASE_URL`, which may leave the authority open. The advisory correlation keeps its own verdict. The regression corpus is unchanged: its six `ssrf` findings build their URL from values of unknown content (#165).

### Plugins

- `TaintDetector.judge(ctx, function, flow, verdict)` lets a rule refine the refutation's verdict on a flow for its own findings, without changing the verdict other consumers of the flow read (#165).

## 0.13.0 (2026-09-26)

### Precision

- The text attributes and URL parameters of a request object carry no `NOSQL`. Django, REST framework, aiohttp and tornado views read a request tainted as a whole, so `request.GET["name"]` and a URL parameter were `nosql-injection` like the body. Now `GET`, `POST`, `COOKIES`, `META`, `headers`, `query_params`, aiohttp's `query` and `match_info`, tornado's `arguments` and the other text attributes are text, and so are the URL parameters a view receives after the request. The body, the files, REST framework's `data` and aiohttp's `json()` keep the kinds of the request. The other kinds are unchanged, and so is the regression corpus. A helper function the request is passed to still reads it as a whole (#162).

### Plugins

- A `RequestObject(symbol, text=())` model says that the inputs from an entry point, a route registrar, a typed parameter or a source are request objects, and which of their attributes are text (#162).

## 0.12.0 (2026-09-26)

### Detection

- A module-level name bound to an attribute, an item or a call of another module-level name resolves in functions, as the same value does in a function body. `cursor = conn.cursor()` after `conn = sqlite3.connect(...)`, `db = client.shop` and `run = os.system` used to leave the calls made through them unknown, so a query built from request data and executed through a module-level cursor was not reported. Names resolve in statement order. The regression corpus is unchanged (#155).
- `nosql-injection` reports attacker input that may hold a structure reaching a NoSQL sink, such as a MongoDB filter, where a JSON body giving `{"$ne": null}` matches any value. Only input that may hold a structure carries `NOSQL`: JSON, the raw bodies a `json.loads` decodes, files, WebSocket messages and standard input. Text cannot hold an operator. The text sources of Flask, bottle and tornado, the URL parameters of their routes, the command line, the environment and `input()` no longer carry `NOSQL`. Neither does an entry-point parameter annotated with scalars (`str`, `Optional[int]`, `Annotated[str, Query()]`, `list[str]`, …), which FastAPI validates. Two limits remain. Django and aiohttp request objects stay tainted as a whole. The keys of a dict are not followed, so a string concatenated into `$where` is not reported. The engine ships no NoSQL sink: model plugins declare them (#158).

### Plugins

- `TEXT_KINDS` holds every kind but `NOSQL`: what text input carries. A model plugin declares its text sources with it (#158).

- A `Members(symbol, dynamic=None, defined=(), typed=())` model says what the attributes and items of a class's instances give, for libraries whose objects give others by names the project chooses. A pymongo client gives the database it is dotted or indexed with, a database gives a collection. The names used to end up in the symbol (`MongoClient.shop.users.find`), or an item vanished into its container's symbol (`MongoClient.find`), so no model could list them. With the model, every path to a collection denotes the collection class, the one a parameter annotated `Collection` denotes: `client.shop.users`, `client["shop"]["users"]`, `client.get_database("shop").get_collection("users")`, a module-level `db = client.shop`, an attribute inherited from the client class. A sink on `Collection.find` covers them all. Symbol resolution now depends on these models, which the engine provides to every module and worker (#157).

## 0.11.0 (2026-09-25)

### Detection

- `code-injection` reports attacker input reaching the code `eval` or `exec` runs, with the same verdicts as the other taint rules. The globals and locals passed with the code are data, not code. `dangerous-eval` still reports every call to `eval` or `exec`, whatever it runs. The regression corpus gains three findings, each reviewed as a true positive: pygoat's `mitre_lab_25_api` and `cmd_lab2` evaluate a POST field, and the `vulnerable-flask` fixture evaluates a query parameter (#152).

## 0.10.0 (2026-09-25)

### Reports

- A directory check names what its result was produced with, besides the engine and the sources. It lists each plugin it loaded, by manifest name and version, and each advisory file it read, by path, each with the SHA-256 digest of its content. The formats show them in these places:
  - JSON: `tool.components`;
  - SARIF: `tool.extensions`;
  - CycloneDX SBOM: `metadata.tools.components`, with their hashes;
  - OpenVEX: the document's `tooling`, so its `@id` changes with the advisory data.

  Every finding about an advisory names the plugin (`name@version`) or advisory file it comes from, in its `advisory_source` metadata. The cache key and the reports identify a plugin by the same digest (#149).

## 0.9.0 (2026-09-25)

### Precision

- An advisory entry point may name the `attacker_arguments` through which attacker input exploits it: by keyword, and by position when the argument may be passed positionally, a variadic one taking every later position. Attacker input in another argument leaves the call reachable instead of exploitable, so an advisory for `send_from_directory` that names its `path` no longer counts `download_name=`, and one for `requests.get` that names its `url` no longer counts the body. An argument unpacked with `*` or `**` may fill any of them: like an argument condition it leaves undecided, it does not rule the call out, so a wrapper forwarding `*args, **kwargs` still reaches the entry point. An entry point naming no argument counts every argument, as before. Each taint flow now records how its value is passed to the sink (#145).

## 0.8.0 (2026-09-25)

### Precision

- A `Validator` proves its argument safe only for the kinds it declares. A validator declared for `REDIRECT` used to refute a command injection through the same value; the flow is now a hotspot, and it is refuted only when the validator covers every kind reaching the sink (#143).
- A sanitizer called inside a project function protects the flows through that function, for every caller. That covers a helper that escapes before answering, a view redirecting to `reverse(...)`, and a helper rendering a template the analyzer shows escaping. Function summaries keep, for each parameter, the taint kinds cleared on every path from it to an external call or to the return value. A path that skips the sanitizer, or a kind it does not clear, still reaches the sink. The cache format is bumped (#134).

### Plugins

- `Plugin.project_models(root)` lets a plugin read models from the project under analysis, such as validators the project declares in a file. It is called once per directory check, in every process, and its models are part of the cache key. A model declared wrongly raises `ModelError`, which the command line now reports as an error (exit status 2) instead of a traceback (#140).
- A `Validator` model may name a function of the project by its project symbol (`python.hc.accounts.views._allow_redirect`), and the refutation recognises it in its own module too, where a call to it has no imported symbol. A project can thus declare its own validation helpers, and a flow they guard is refuted (#134).

## 0.7.0 (2026-09-25)

### Precision

- A dominating guard makes a flow a hotspot only when it examines what the sink receives. `if request.method == 'POST':` before `request.POST['cmd']` no longer lowers a vulnerability to a hotspot. A test of the value itself, of the same attribute, of a method called on it (`form.is_valid()`), or of any part of an object the flow passes whole still does. The regression snapshots record the verdict of each taint finding (#135).
- The SSRF sinks of Requests and httpx read the destination only: the URL (the first argument, the second after the method for `request` and `stream`, or `url=`) or the prepared request `send` takes. Attacker data in the body, the JSON, the headers or the query parameters is no longer a server-side request forgery. `Sink` gains `keywords` next to `positions`, and function summaries keep the name of each keyword argument, so a project function forwarding `url=` still reaches the sink; the cache format is bumped (#128).
- `render_to_string` escapes what it renders where the analyzer can establish it: on a directory check, it reads the project's Django templates, and a template escapes when neither it nor what it extends or includes marks output safe, uses a tag, filter or library beyond Django's own, or prints a variable where HTML escaping does not protect it, and no settings turn autoescaping off. Data reaching a response through such a template is no longer `xss`; any other template keeps the flow reported. `TemplateRender` declares such rendering calls, and the escaped templates are part of the cache key (#130).
- Django's `csrf.get_token` returns a token of letters and digits whatever the request holds, and `reverse`/`reverse_lazy` build a local path that attacker data in their arguments or query cannot turn into another host: the first is no longer an injection, the second no longer an open redirect. `reverse` still carries other kinds, since it leaves `'` unquoted (#132).

## 0.6.0 (2026-09-24)

### Reports

- `--vex PATH` writes an OpenVEX document with one statement per advisory affecting a requirement. A statement is `affected` when the project's code reaches the vulnerability, including findings the policy accepts or a comment suppresses. It is `not_affected` (`vulnerable_code_not_in_execute_path`) only for an advisory with entry points that nothing reaches, in a complete analysis, and when the lock file shows no other package requiring the vulnerable one. Anything else is `under_investigation`, with the reason (#97).

### Dependencies

- An advisory entry point marked `read` is an attribute whose getter runs the affected code, such as `request.form`: reading it is reachable, called or not — a subscript, an iteration or a method called on it reads it — with one finding per function, where it is first read (#111).
- A lock file records which packages require which. `DependencyGraph.required_by(name)` gives the other packages requiring a package; the project's own packages are not counted. `ProjectAnalysis.accepted` keeps the findings of advisories the policy accepts (#97).

### Detection

- `yaml.load_all`, `yaml.full_load_all` and `yaml.unsafe_load_all` are deserialization sinks like their single-document versions; `yaml.load_all` with a safe loader is not, and `yaml.safe_load_all` stays safe (#123).

### Precision

- A sink call can be made safe by one of its arguments: a `SafeArgument` model names the argument and the values that take kinds off the sink, only when the call gives one explicitly. `yaml.load` with `SafeLoader`, `BaseLoader` or their C versions, under every spelling, is no longer an insecure deserialization; an absent loader, another loader, a variable or unpacked arguments still are (#121).

### Plugins

- The call graph records the symbols each function reads, called or not, where it first reads each: `CallGraph.reads(function)` gives them as `SymbolRead` records, modules served from the cache keep them, and the cache format is bumped (#111).

## 0.5.0 (2026-09-24)

### Dependencies

- Argument conditions of advisory entry points are decided at each call, with a `position` for positional arguments and a `default` for absent ones: a call meeting them is reported with `conditions_met`, a call passing another known value does not reach the vulnerability and is listed in the requirement's `ruled_out`, and a call the analyzer cannot decide leaves them pending review (#110).

### Plugins

- `ProjectContext.functions(module)` gives project plugins every function of a module as its call graph names it, with its span and the label of the entry point it is (`http` for a route, `argv` for a command), decided by the taint engine's own rule; modules served from the cache keep them, and the cache format is bumped (#116).
- Call sites and external calls record what each argument denotes — a symbol, a constant as Python writes it, or nothing known — in an `Arguments` record: `CallSite.arguments` (formerly the argument counts), `ExternalCall.arguments`, and `TaintFlow.sink_arguments` for the sink call of a flow, through callees in other modules too (#110).

## 0.4.0 (2026-09-24)

### Analysis

- The module body and the bodies of top-level classes are analysed as the functions `<module>` and `Cls.<body>`: their calls are call sites, their values carry taint, and an advisory entry point called at import time or in a class body is reachable. Coverage counts them; the cache format is bumped so cached results gain their findings (#113).

### Dependencies

- Advisories distinguish the `affected_symbols` a fix changed from the public `entry_points` through which they are reached, each justified and carrying `conditions` (checkable argument values, or `semantic` ones kept as pending review); `modules` names what the package installs. Every dependency finding records its evidence `level`: `declared`, `imported`, `reachable` or `exploitable` (#109).
- A call to an API affected by several advisories of the pinned release reports every one of them, not the first listed (#109).
- One advisory per identifier and package: a later contributor replaces an earlier one, so a curated feed refines the bundled sample, and the sample names the modules its packages install (#109).
- A version specifier may be a union of ranges separated by `||`, as an advisory over several release series needs (`>=4.2,<4.2.28 || >=5.2,<5.2.11`); the OSV import produces one such advisory per package instead of one per range (#112).

### Plugins

- Every plugin module is registered in `sys.modules` before it runs, so a single-file plugin may define a dataclass under `from __future__ import annotations` (#105).
- `ProjectPlugin.refine(ctx, findings)` lets a project plugin reclassify the findings of a run: severity, confidence and added metadata only, with `refined_by` and the original values recorded; anything else raises `RefinementError` (#106).

## 0.3.0 (2026-09-22)

### Plugins

- Two plugins may declare the same symbol: an identical model is registered once and sinks merge their kinds and positions; a real conflict names both plugins instead of failing the run on the first duplicate (#92).
- A plugin's entrypoint may be a package, `<module>/__init__.py`, so a plugin can split its tables across files and import them relatively (#93).
- The cache key covers every file of a plugin directory, not only `.py` and `.toml`, so rules or advisories shipped as data invalidate cached results when they change (#94).

### Analysis

- New taint kinds: `NOSQL` in `TaintKind.ALL`; `LOG` and `PII` outside it, carried only by the values a model marks, so a NoSQL-injection, log-injection or personal-data detector no longer has to share a kind with another rule (#96).

### Precision

- A `Sanitizer` declared on a function of the analysed project takes precedence over the summary derived from its body, in the same file and across files, so a code base can declare its own validation layer (#95).

## 0.2.0 (2026-09-06)

### Adoption in an existing repository

- Report paths are relative to the checked root; the JSON report carries the root and the SARIF log declares it as the `SRCROOT` URI base, so code scanning attaches alerts to files (#75).
- `# coretrace: ignore` and `# coretrace: ignore[rule, rule]` silence a finding on its line, in Python sources and requirements files; suppressed findings are counted, listed and marked in the reports (#76).
- `--baseline PATH` records the accepted findings on the first run and fails later runs on new findings only; findings are recognised by file, rule, function and line text, not line number (#77).
- `--fail-on SEVERITY` sets the exit status to 1 only from that severity up (#78).

### Analysis

- Assignment expressions, `yield from`, starred assignment targets, class keyword arguments and any assignable `with` target are supported; they used to reject whole files (#80, #86).
- A `nonlocal` write made by a nested function flows back to the enclosing function when it calls that function directly, the last documented approximation (#84).
- An attribute a class does not define resolves through its base, so `self.get_argument` in a Tornado handler and `self.request` in a Django class-based view denote the framework's; static methods called on the class resolve to the method and pass no receiver (#89).
- Route registrations are found inside functions such as `setup_routes(app: Application)`, and `await f()` denotes what `f()` denotes (#88).

### Detection

- New security models: aiohttp, Tornado, Bottle, and the aiopg, asyncpg, psycopg2 and PyMySQL drivers (#88, #89).
- New rules: `insecure-tls`, `unsafe-xml`, `unsafe-archive-extraction`, `insecure-temp-file` and `weak-random` (#90).

### Precision

- Hex digests, subresource-integrity hashes and character-set constants are no longer high-entropy secrets; credentials in test code and template files are reported at low confidence; `token_type`-like names are not credentials (#81, #82, #87).
- Redirect sinks read their target argument only, so `redirect("url-name", arg)` is not an open redirect (#83).
- Environment variables and process output are operator-controlled: they carry no command or path kinds, except a downloaded script piped into a shell (#87).
- A container literal passed to a sink is serialised, never rendered, so it carries no HTML (#89).

### Performance and corpus

- A module's functions are collected once; 25 to 30 percent faster on large projects, measured on healthchecks, rich and wagtail and recorded in the usage guide (#79).
- The regression corpus grows to 19 repositories, including healthchecks, dvpwa, pygoat, the FastAPI full-stack template, httpie and luigi (#79, #85).

### Packaging

- The Apache License 2.0 text ships with the repository and the wheel (#74).

## 0.1.0 (2026-09-04)

First release on PyPI: the analyzer with its 26 bundled plugins, the regression suite on 13 public repositories and the usage and plugin guides.
