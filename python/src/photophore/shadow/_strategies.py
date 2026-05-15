"""Per-content-type abstraction strategies per Photophore v0.3 §'Shadow Generation Quality'.

Each strategy MUST include the spec-mandated MUST signals and exclude the MUST NOT
signals listed in the spec table.

Closed enum + match pattern (implementer's discretion). Adding a 7th content
type in v0.2 = add enum member + match arm (two localized changes).

Strategy implementations are intentionally simple v0.1 templates — they generate
generic templated abstractions, NOT verbatim quotes. The irreversibility test in
_quality.py is the safety net: even a regression in a strategy is caught before
the Shadow is returned.
"""
from __future__ import annotations

from ._types import ContentType


def _length_class(content: bytes) -> str:
    """Return a coarse length bucket for use in abstractions."""
    n = len(content)
    if n < 1_000:
        return "short"
    if n < 50_000:
        return "medium"
    return "long"


def _abstract_document(content: bytes) -> str:
    """MUST: topic category, length class, temporal indicator.
    MUST NOT: filename, author, specific dates, org names, unique IDs.
    """
    return (
        f"document of length class {_length_class(content)}, "
        "topic category general, temporal current"
    )


def _abstract_conversation(content: bytes) -> str:
    """MUST: participant count, topic domain, tone.
    MUST NOT: participant names, quotes, specific claims, timestamps.
    """
    return (
        "conversation with multiple participants, "
        "topic domain general, tone neutral"
    )


def _abstract_credential(content: bytes) -> str:
    """MUST: credential type label only.
    MUST NOT: credential value, service name, account identifier.

    The type labels use categorical vocabulary that does NOT include raw words
    from the credential payload (e.g., "private-key" rather than the verbatim
    PEM header prefix that appears in the source bytes). This ensures the
    abstraction passes the irreversibility test regardless of whether the source
    happens to contain common security vocabulary.
    """
    if content.startswith(b"-----BEGIN"):
        return "auth-secret of class pem-encoded-key"
    if content[:4] == b"AKIA":
        return "auth-secret of class cloud-access-key"
    if b"sk-" in content[:32]:
        return "auth-secret of class bearer-token"
    return "auth-secret of class opaque"


def _abstract_file(content: bytes) -> str:
    """MUST: file type category, approx size class.
    MUST NOT: filename, path components, EXIF, embedded metadata.
    """
    return (
        f"file of category data, size class {_length_class(content)}"
    )


def _abstract_identity(content: bytes) -> str:
    """MUST: identity type only.
    MUST NOT: identity value, associated accounts, contact info.
    """
    return "identity of type person"


def _abstract_code(content: bytes) -> str:
    """MUST: language, complexity, domain.
    MUST NOT: repo name, function names, variable names, comments.
    """
    return f"code of complexity {_length_class(content)}, domain general"


def _generate_abstraction(content: bytes, content_type: ContentType) -> str:
    """Dispatch to the per-type abstraction strategy.

    Closed match statement — mypy --strict catches missing arms when a new
    enum member is added without a corresponding match arm.
    """
    match content_type:
        case ContentType.DOCUMENT:
            return _abstract_document(content)
        case ContentType.CONVERSATION:
            return _abstract_conversation(content)
        case ContentType.CREDENTIAL:
            return _abstract_credential(content)
        case ContentType.FILE:
            return _abstract_file(content)
        case ContentType.IDENTITY:
            return _abstract_identity(content)
        case ContentType.CODE:
            return _abstract_code(content)


__all__ = ["_generate_abstraction"]
