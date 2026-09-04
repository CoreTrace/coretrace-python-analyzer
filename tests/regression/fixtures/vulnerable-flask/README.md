# Intentionally vulnerable Flask server

This project is a local fixture for exercising CoreTrace. It deliberately contains
security vulnerabilities and must never be deployed or exposed to a network.

## Analyze it

Run this command from the root of `coretrace-python-analyzer`:

```bash
coretrace-python-analyzer --check tests/regression/fixtures/vulnerable-flask
```

The project is expected to exercise these rules:

- `command-injection`, through a helper in another module;
- `sql-injection`, also through that helper module;
- `path-traversal`;
- `ssrf`;
- `xss`;
- `dangerous-eval`;
- `weak-crypto`;
- `hardcoded-secret`, using a synthetic key that is not a real credential.

`/safe-render` is a negative control: it applies `markupsafe.escape`, so the analyzer
should not report XSS for that route.

## Run it locally (optional)

Running the server is not required to analyze it. If you do run it, keep it local:

```bash
cd tests-project/vulnerable-flask
python -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python app.py
```

The application explicitly listens only on `127.0.0.1` with debug mode disabled. The
routes themselves remain intentionally unsafe.
