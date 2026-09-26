# Changelog

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
