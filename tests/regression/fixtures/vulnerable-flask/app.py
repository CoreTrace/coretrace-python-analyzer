"""Intentionally vulnerable Flask application for CoreTrace demonstrations.

This application is a local test fixture. Do not deploy it or expose it to a network.
"""

from __future__ import annotations

import hashlib

import requests
from flask import Flask, Response, request, send_file
from markupsafe import escape
from vulnerable_services import find_user, initialize_database, run_command

app = Flask(__name__)

NOIR = "Noah"

# Synthetic and unusable, but shaped like an AWS access key so the secret detector sees it.
DEMO_AWS_ACCESS_KEY = "AKIA0000000000000000"
DEMO_AWS_ACCESS_KEY2 = "AKIA0000000000000000"


@app.route("/")
def index() -> dict[str, object]:
    return {
        "warning": "Intentionally vulnerable test application",
        "routes": (
            "/command?cmd=...",
            "/users?name=...",
            "/file?path=...",
            "/fetch?url=...",
            "/render?html=...",
            "/calculate?expression=...",
            "/digest?value=...",
            "/safe-render?text=...",
        ),
    }


@app.route("/command")
def command_injection() -> dict[str, int]:
    command = request.args["cmd"]
    return {"exit_code": run_command(command)}


@app.route("/users")
def sql_injection() -> dict[str, object]:
    username = request.args["name"]
    return {"rows": find_user(username)}


@app.route("/file")
def path_traversal() -> Response:
    return send_file(request.args["path"])


@app.route("/fetch")
def server_side_request_forgery() -> dict[str, int]:
    response = requests.get(request.args["url"], timeout=2)
    return {"status": response.status_code}


@app.route("/render")
def cross_site_scripting() -> Response:
    return Response(request.args["html"], mimetype="text/html")


@app.route("/calculate")
def code_injection() -> dict[str, str]:
    result = eval(request.args["expression"])
    return {"result": repr(result)}


@app.route("/digest")
def weak_cryptography() -> dict[str, str]:
    value = request.args["value"]
    return {"digest": hashlib.md5(value.encode()).hexdigest()}


@app.route("/safe-render")
def safe_render_control() -> Response:
    """Negative control: escaping should prevent an XSS finding for this route."""

    return Response(escape(request.args["text"]), mimetype="text/html")


if __name__ == "__main__":
    initialize_database()
    app.run(host="127.0.0.1", port=5000, debug=False)
