"""Leased credentials: request, keep alive while in use, hand back.

This is the other half of what a short-lived credential needs. A secret that
rotates is followed by re-reading it; a leased credential expires, and the
holder is the only party that knows it is still needed.

Renewal bounds itself. CoreLink refuses past the credential's maximum lifetime,
so keeping one alive for as long as it is used is not the same as keeping it
forever -- which is why ``keep_alive`` is safe to run in the background, and why
it stops rather than retrying when it is refused.

The wire shapes here were verified against a running CoreLink rather than read
off the handler: the lease listing is wrapped in ``data`` (not ``leases``) and
the credential is a string (not an object). Both were guessed wrong first.

See docs/secret-delivery.md.
"""

import threading

#: Resource types a credential can be leased against.
RESOURCE_SECRET = "secret"
RESOURCE_DATABASE = "database"
RESOURCE_CLOUD = "cloud"

_RESOURCE_TYPES = (RESOURCE_SECRET, RESOURCE_DATABASE, RESOURCE_CLOUD)


class LeaseExhausted(Exception):
    """This credential will not extend again.

    It has reached its maximum lifetime, so retrying is pointless: request a new
    credential instead. Distinct from an ordinary failure because the recovery
    differs, and CoreLink does not say which limit was reached because the action
    is the same either way.
    """


class LeaseNotFound(Exception):
    """The lease is unknown, already revoked, or belongs to another identity.

    Deliberately indistinguishable: a caller learns nothing about leases that
    are not its own.
    """


class Lease:
    """A credential and the terms it was issued under."""

    __slots__ = ("id", "credential", "expires_at", "issued_at")

    def __init__(self, id, credential="", expires_at=None, issued_at=None):
        self.id = id
        self.credential = credential
        self.expires_at = expires_at
        self.issued_at = issued_at

    def __repr__(self):
        # A lease is logged while tracing its lifecycle far more often than a
        # secret is, so its default rendering must not be where the credential
        # escapes.
        return f"Lease(id={self.id!r}, expires_at={self.expires_at!r}, credential=<redacted>)"


def _lease_from(payload):
    return Lease(
        id=payload.get("lease_id") or payload.get("id", ""),
        credential=payload.get("credential", ""),
        expires_at=payload.get("expires_at"),
        issued_at=payload.get("issued_at"),
    )


def _seconds_until(when):
    """Seconds until an RFC3339 timestamp, or 60 when it cannot be read.

    CoreLink sends an expiry on issue and not on renewal, so after the first
    renewal there is nothing to measure against and a minute is the fallback.
    """
    if not when:
        return 60.0
    from datetime import datetime, timezone

    text = str(when).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return 60.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max((parsed - datetime.now(timezone.utc)).total_seconds(), 0.0)


def _term_seconds(lease, default=60.0):
    """How long the lease was issued for, from its own issue and expiry."""
    if not lease.issued_at or not lease.expires_at:
        return default
    start = _seconds_until(lease.issued_at)
    end = _seconds_until(lease.expires_at)
    term = end - start
    return term if term > 0 else default
