"""Opening a sealed envelope.

The application takes ciphertext from a connector and the key from CoreLink, and
opens the secret itself. Nothing between the two holds both halves: the connector
is granted ``secrets:cache`` and keeps envelopes it has no authority to open, and
the application is granted ``secrets:unwrap`` and may open one it already has.

The additional authenticated data is rebuilt here from the secret id and version
and required to equal the value stored on the envelope. Decrypting with whatever
the envelope carries would detect an altered envelope, because the tag breaks,
but would bind nothing -- an envelope claiming to be some other secret would open
happily.

See docs/secret-delivery.md.
"""

import base64
import json

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#: Prefix of the additional authenticated data. Must match
#: ``crypto.SecretAAD`` on the platform byte for byte: the two are one wire
#: format, and changing either alone stops every envelope opening. Pinned by
#: ``sdk/testdata/sealed_envelope.json``, which the platform produces.
_AAD_PREFIX = "cl.secret.v1"


class StaleEnvelope(Exception):
    """A cached envelope the current key will not open.

    Separate from :class:`CorruptEnvelope` because the recoveries differ: ask the
    connector for a fresh envelope. A rollback attempt and a damaged envelope look
    identical at the AEAD and should not look identical in a log.
    """


class CorruptEnvelope(Exception):
    """An envelope that did not open and was not stale.

    The key belonged to the version the envelope claims and it still failed, so
    the ciphertext or the tag has been altered. Refetching will not help.
    """


class WrongSecret(Exception):
    """A connector answered with a different secret than the one asked for.

    The case the AAD does not cover. An envelope is bound to its own id and
    version, so another secret's id and envelope together are internally
    consistent and open cleanly -- under the wrong name. A compromised connector
    can therefore answer a request for one secret with another the application
    also holds unwrap on, and every cryptographic check passes.

    CoreLink returns the name the id really belongs to, and the application knows
    the name it asked for; neither alone can see the substitution, so the
    comparison happens here.
    """


def secret_aad(secret_id, version):
    """Return the additional authenticated data for a secret and version."""
    return f"{_AAD_PREFIX}|{secret_id}|{version}".encode()


def open_envelope(envelope_b64, dek, secret_id, version):
    """Open a sealed envelope and return the plaintext bytes.

    ``dek`` is the key CoreLink returned for this secret. ``secret_id`` and
    ``version`` are the authorized context the AAD is rebuilt from, not values
    read out of the envelope.
    """
    try:
        raw = base64.b64decode(envelope_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise CorruptEnvelope(f"the envelope is not base64: {exc}") from exc

    try:
        body = json.loads(raw)
    except ValueError as exc:
        raise CorruptEnvelope(f"the envelope is not an envelope: {exc}") from exc

    expected = secret_aad(secret_id, version)
    stored = body.get("aad")
    # An envelope carrying no AAD was written before binding existed, and opens
    # with none. That is not a rollback -- the thing this must never be confused
    # with -- and the platform skips its own compare for these too. Passing the
    # expected value here instead would break every secret written before the
    # binding did, which is all of them at a given installation until the first
    # rotation.
    effective = expected if stored else None
    if stored and base64.b64decode(stored) != expected:
        # Sealed for a different secret or version. Named as stale rather than
        # corrupt: the likely cause is a connector holding an old envelope, and
        # the recovery is to ask it again.
        raise StaleEnvelope(
            f"the envelope is bound to something other than {secret_id} version {version}"
        )

    try:
        ciphertext = base64.b64decode(body["encrypted_data"])
        nonce = base64.b64decode(body["nonce"])
    except (KeyError, ValueError, TypeError) as exc:
        raise CorruptEnvelope(f"the envelope is missing its ciphertext: {exc}") from exc

    try:
        return AESGCM(dek).decrypt(nonce, ciphertext, effective)
    except InvalidTag as exc:
        # The key was for the version the envelope claims and the binding
        # matched, so this is not a rollback: something has been altered.
        raise CorruptEnvelope(
            "the envelope did not open with the key for its own version"
        ) from exc


def value_from(plaintext):
    """Return the secret's value from a stored record.

    What is sealed is the record, which wraps the value. Older records may be the
    bare value, so that is the fallback rather than an error.
    """
    try:
        record = json.loads(plaintext)
    except ValueError:
        return plaintext.decode()
    if isinstance(record, dict) and record.get("value"):
        return record["value"]
    return plaintext.decode()


def envelope_path(name):
    """Escape a secret name for a URL, keeping the slashes that are part of it.

    A ``.`` or ``..`` segment is refused rather than escaped. Clients and servers
    normalise dot segments in a path, so such a name would be asked for as a
    different one, and no secret can be named that way: the platform's own path
    validation rejects ``..``.
    """
    from urllib.parse import quote

    trimmed = name.strip("/")
    if not trimmed:
        raise ValueError("a secret name is required")
    parts = trimmed.split("/")
    for part in parts:
        if not part:
            raise ValueError(f"{name!r} has an empty path segment")
        if part in (".", ".."):
            raise ValueError(f"{name!r} is not a secret name")
    return "/".join(quote(p, safe="") for p in parts)


class Certificate:
    """A TLS bundle stored as a secret's value."""

    __slots__ = ("certificate", "private_key", "ca_chain")

    def __init__(self, certificate, private_key, ca_chain=""):
        self.certificate = certificate
        self.private_key = private_key
        self.ca_chain = ca_chain

    def __eq__(self, other):
        return (
            isinstance(other, Certificate)
            and self.certificate == other.certificate
            and self.private_key == other.private_key
            and self.ca_chain == other.ca_chain
        )

    def __repr__(self):
        # Never the key. This object exists to be handed to a TLS library, and a
        # repr in a log or traceback should not be where it escapes.
        return f"Certificate(certificate={self.certificate[:32]!r}..., private_key=<redacted>)"


def certificate_from(value):
    """Parse a TLS bundle out of a secret's value.

    The value is one level deeper than it looks: the stored record wraps it, and
    for a certificate the value is itself JSON. ``value_from`` unwraps the
    record, and this parses what came out.

    Both halves are required. A secret that merely happens to be JSON would
    otherwise come back as a certificate with empty fields, which is worse than
    an error because it fails later and somewhere else.
    """
    try:
        bundle = json.loads(value)
    except ValueError as exc:
        raise ValueError(f"not a TLS certificate bundle: {exc}") from exc
    if not isinstance(bundle, dict):
        raise ValueError("not a TLS certificate bundle")
    cert = bundle.get("certificate", "")
    key = bundle.get("private_key", "")
    if not cert or not key:
        raise ValueError("carries no certificate and key")
    return Certificate(cert, key, bundle.get("ca_chain", ""))
