"""Intentionally unsafe service functions called by the Flask routes."""

from __future__ import annotations

import os
import sqlite3

DATABASE = "demo.db"


def initialize_database() -> None:
    connection = sqlite3.connect(DATABASE)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE)"
    )
    connection.execute("INSERT OR IGNORE INTO users(username) VALUES ('alice')")
    connection.commit()
    connection.close()


def run_command(command: str) -> int:
    # Intentionally unsafe: the command comes directly from an HTTP query parameter.
    return os.system(command)


def find_user(username: str) -> list[tuple[object, ...]]:
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    # Intentionally unsafe: string concatenation allows SQL injection.
    query = "SELECT id, username FROM users WHERE username = '" + username + "'"
    rows = cursor.execute(query).fetchall()
    connection.close()
    return rows
