"""Rule-based v0.1 classifier patterns (CLASS-04).

NEVER promote content to Tier.PUBLIC from inference alone. This module ONLY signals
"this content matched a sensitive-content pattern" — the caller (_engine.classify)
applies tier=default_tier()=LOCAL to all positive matches.

Returned rule_name must be one of the documented strings below; the CLI surface (CLASS-05)
formats them as `classifier:<rule_name>`.
"""
from __future__ import annotations

import re
from pathlib import Path

# Credential patterns (catch the obvious shapes; v0.3 deferred adds ML-backed detection).
_CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern[bytes]]] = [
    (
        "credential_pem",
        re.compile(
            rb"-----BEGIN[ A-Z]+"
            rb"(PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|OPENSSH PRIVATE KEY|CERTIFICATE)"
            rb"-----"
        ),
    ),
    ("credential_aws_key", re.compile(rb"AKIA[A-Z0-9]{16}")),
    (
        "credential_jwt",
        re.compile(rb"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    ),
    ("credential_sk_token", re.compile(rb"\bsk-[A-Za-z0-9]{20,}\b")),
    (
        "credential_env_assignment",
        re.compile(
            # Match KEY=value where value is >=8 printable non-whitespace chars.
            # Intentionally broad to catch URLs (postgres://user:pass@host), tokens, etc.
            rb"^[A-Z][A-Z0-9_]*\s*=\s*['\"]?[\x21-\x7E]{8,}['\"]?$",
            re.MULTILINE,
        ),
    ),
]

# PII patterns. v0.1 ships obvious shapes; v0.3 extends.
_PII_PATTERNS: list[tuple[str, re.Pattern[bytes]]] = [
    ("pii_ssn", re.compile(rb"\b\d{3}-\d{2}-\d{4}\b")),
    ("pii_email", re.compile(rb"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    (
        "pii_phone_us",
        re.compile(rb"\b(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    ),
    ("pii_credit_card", re.compile(rb"\b(?:\d[ -]?){13,16}\b")),
]

# File-extension patterns (CLASS-04: known sensitive file types).
_SENSITIVE_FILE_EXTENSIONS: set[str] = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".keychain",
    ".env",
    ".pgp",
    ".gpg",
    ".asc",
    ".kdbx",
    ".keystore",
    ".jks",
}

# Dotfiles recognized regardless of suffix (bare .env has no suffix).
_SENSITIVE_DOTFILE_NAMES: set[str] = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
}


def classify_by_rules(content: bytes, path: str | None) -> str | None:
    """Return rule_name for the first matching pattern, or None if no match.

    Caller applies default_tier() (LOCAL) to all positive matches; this function never
    returns a tier — only a rule label. CLASS-04 forbids promoting content to PUBLIC.
    """
    # File-extension check first — cheapest, most specific signal.
    if path is not None:
        p = Path(path)
        suffix = p.suffix.lower()
        if suffix in _SENSITIVE_FILE_EXTENSIONS:
            return "credential_file_extension"
        # Special-case dotfiles whose suffix is the whole name (e.g., ".env" with no extension)
        if p.name in _SENSITIVE_DOTFILE_NAMES:
            return "credential_file_extension"
    # Credential pattern scan.
    for name, pat in _CREDENTIAL_PATTERNS:
        if pat.search(content):
            return name
    # PII pattern scan.
    for name, pat in _PII_PATTERNS:
        if pat.search(content):
            return name
    return None
