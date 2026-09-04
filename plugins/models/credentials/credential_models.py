"""Credential models: password-named parameters are credentials, password hashing clears
them, and the database write sinks of the other model plugins also carry the
``CREDENTIAL`` kind, so a credential stored unhashed is a flow."""

from __future__ import annotations

from typing import ClassVar

from coretrace_python.plugins import ModelPlugin
from coretrace_python.semantic.symbols import SymbolId
from coretrace_python.taint import Model, NamedParameter, Sanitizer, TaintKind

_HASHERS = (
    "hashlib.pbkdf2_hmac",
    "hashlib.scrypt",
    "hashlib.sha256",
    "hashlib.sha512",
    "hashlib.sha3_256",
    "hashlib.blake2b",
    "hashlib.new",
    "bcrypt.hashpw",
    "bcrypt.kdf",
    "argon2.PasswordHasher.hash",
    "argon2.low_level.hash_secret",
    "werkzeug.security.generate_password_hash",
    "passlib.hash.pbkdf2_sha256.hash",
    "passlib.hash.bcrypt.hash",
    "passlib.hash.argon2.hash",
    "passlib.context.CryptContext.hash",
    "django.contrib.auth.hashers.make_password",
)


def _sym(path: str) -> SymbolId:
    return SymbolId(f"python.{path}")


class CredentialModels(ModelPlugin):
    name: ClassVar[str] = "credential-models"
    models: ClassVar[tuple[Model, ...]] = (
        NamedParameter(r"(?i)^(password|passwd|pwd|new_password|plain_password|secret)$", "credential", TaintKind.CREDENTIAL),
        *(Sanitizer(_sym(hasher), TaintKind.CREDENTIAL) for hasher in _HASHERS),
    )
