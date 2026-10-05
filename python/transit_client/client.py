"""Transit API client for Tech Blend Secrets Management."""

import base64
import logging
import threading
import time
from urllib.parse import quote

import requests

from transit_client import leases, sealed

log = logging.getLogger(__name__)


class TransitClient:
    """Client for the Tech Blend Transit API.

    Authentication is via NHI (Non-Human Identity) passwordless attestation.
    Call bootstrap() before making any API calls. The client automatically
    renews its session in the background every 50 minutes.

    Args:
        transit_url: Base URL of the transit agent.
        platform_url: Base URL of the Tech Blend platform (for NHI connect/heartbeat).
        nhi_id: NHI identity ID for fingerprint-based authentication.
        ca_cert_file: Optional path to a CA certificate for TLS pinning.
    """

    def __init__(self, transit_url, platform_url="", nhi_id="", ca_cert_file="", attest=None):
        self._url = transit_url.rstrip("/")
        self._ca_cert_file = ca_cert_file or True  # True = default CA bundle; path = pinned CA
        self._platform_url = platform_url.rstrip("/") if platform_url else ""
        self._nhi_id = nhi_id
        # attest supplies the attestation to present, instead of the SDK
        # detecting one: a callable returning (type, evidence).
        #
        # For a workload that runs nowhere the SDK can recognise -- a product
        # with no connector, no pod and no instance identity document -- and
        # federates to its own OIDC issuer instead. Return ("oidc", <token>).
        #
        # A callable rather than a string, because these tokens are short lived
        # by design. It is called on every connect and reconnect, so a session
        # that drops at three in the morning re-mints rather than replaying
        # something that expired hours ago.
        #
        # Nothing it returns authorises anything: CoreLink verifies the token
        # against the issuer pinned to this identity, and the grant decides what
        # the identity may do.
        self._attest = attest
        self._session_id = None
        self._session_lock = threading.Lock()
        self._heartbeat_timer = None
        # The shortest interval keep_alive will wait between renewals. A second
        # in production so a lease with no usable expiry cannot make it spin;
        # lowered by tests, which would otherwise spend a second per renewal
        # proving timing that is not what they are checking.
        self._keep_alive_floor = 1.0
        self._session = requests.Session()
        if ca_cert_file:
            self._session.verify = ca_cert_file

    def bootstrap(self):
        """Connect via NHI fingerprint attestation and start the background heartbeat."""
        self._nhi_connect()

    def list_secrets(self):
        """Return the secrets available to this client.

        A connector serves envelopes by name and offers no way to enumerate
        them: an application asks for what it was configured to ask for. There
        is nothing to list, so this raises rather than returning an empty list
        that would read as "no secrets".
        """
        raise RuntimeError(
            "a connector serves envelopes by name and offers no listing; "
            "name the secrets this application needs"
        )

    def get_secret(self, name):
        """Return the value of a single secret by name.

        Takes the sealed envelope from the connector, asks CoreLink for the key
        to that secret, and opens it here. The connector cannot read what it
        served and CoreLink never sees the plaintext, so the value exists in
        this process and nowhere else.

        It used to ask the connector for plaintext. That endpoint answers 410
        now, and this goes the sealed way instead, so an application already
        calling get_secret needs no change.
        """
        return self.get_secret_sealed(name)

    def get_secret_sealed(self, name):
        """Open a secret from a sealed envelope. See :meth:`get_secret`.

        Requires ``secrets:unwrap`` on the secret, and a connector granted
        ``secrets:cache`` on it.

        A stale envelope is retried once with the connector told to refetch,
        which is the case this exists for: the connector holding a version
        CoreLink has since rotated past. A second failure of the same kind is
        reported as stale rather than retried forever.
        """
        if not self._url:
            raise RuntimeError("get_secret_sealed needs a connector; set transit_url")
        if not self._platform_url or not self._nhi_id:
            raise RuntimeError(
                "get_secret_sealed needs an identity; set platform_url and nhi_id"
            )
        try:
            return self._open_sealed(name, refresh=False)
        except sealed.StaleEnvelope:
            return self._open_sealed(name, refresh=True)

    def request_credential(self, resource_type, resource_id, ttl_seconds=0):
        """Ask CoreLink for a credential leased for a while.

        ``resource_type`` is one of ``leases.RESOURCE_SECRET``,
        ``RESOURCE_DATABASE`` or ``RESOURCE_CLOUD``. A zero TTL takes CoreLink's
        default; asking for longer than policy allows is CoreLink's decision, and
        the lease says what was actually granted.
        """
        if not self._platform_url or not self._nhi_id:
            raise RuntimeError("request_credential needs an identity; set platform_url and nhi_id")
        if resource_type not in leases._RESOURCE_TYPES:
            raise ValueError(
                f"resource type {resource_type!r} is not one of {leases._RESOURCE_TYPES}"
            )
        if not resource_id:
            raise ValueError("a resource id is required")

        body = {"resource_type": resource_type, "resource_id": resource_id}
        if ttl_seconds > 0:
            body["ttl_seconds"] = int(ttl_seconds)

        resp = self._platform_request("POST", "/api/v1/nhi-agent/credentials", json=body)
        if resp.status_code != 200:
            raise RuntimeError(
                f"CoreLink refused to issue a credential (status {resp.status_code})"
            )
        lease = leases._lease_from(resp.json())
        if not lease.id:
            raise RuntimeError("CoreLink issued a credential with no lease id")
        return lease

    def renew_lease(self, lease_id):
        """Extend a lease, or say why it will not extend.

        Raises :class:`leases.LeaseExhausted` at the credential's maximum
        lifetime. That is not a failure to retry: request a new credential.
        """
        if not lease_id:
            raise ValueError("a lease id is required")
        resp = self._platform_request(
            "POST", f"/api/v1/nhi-agent/leases/{quote(lease_id, safe='')}/renew"
        )
        if resp.status_code == 200:
            return
        if resp.status_code == 422:
            raise leases.LeaseExhausted("this credential cannot be extended further")
        if resp.status_code == 404:
            raise leases.LeaseNotFound("lease not found")
        raise RuntimeError(f"renewing the lease failed (status {resp.status_code})")

    def release_credential(self, lease_id):
        """Hand a credential back before it expires.

        Worth doing rather than letting it lapse: it stops working at once, which
        closes the window between finishing with it and its expiry. A lease
        already gone is not an error, because the caller's intent is satisfied
        either way.
        """
        if not lease_id:
            raise ValueError("a lease id is required")
        resp = self._platform_request(
            "DELETE", f"/api/v1/nhi-agent/credentials/{quote(lease_id, safe='')}"
        )
        if resp.status_code in (200, 204, 404):
            return
        raise RuntimeError(f"releasing the credential failed (status {resp.status_code})")

    def list_leases(self):
        """The identity's active leases, without their credentials.

        The material is handed over once, at issue. Useful after a restart: a
        process that lost track of what it holds can find out rather than
        requesting more and leaving the old ones to expire.
        """
        resp = self._platform_request("GET", "/api/v1/nhi-agent/credentials")
        if resp.status_code != 200:
            raise RuntimeError(f"listing leases failed (status {resp.status_code})")
        # "data" is the key CoreLink sends; this read "leases" until a live call
        # proved otherwise.
        return [leases._lease_from(row) for row in resp.json().get("data", [])]

    def keep_alive(self, lease, on_expiry=None):
        """Renew a lease in the background for as long as it is in use.

        Renews at half the remaining life, so a missed attempt has another before
        the credential lapses, and stops when CoreLink refuses. ``on_expiry`` is
        called once with the reason, which is how an application learns it must
        request a new credential.

        Returns a function that stops the renewals. It does not release the
        lease; ``release_credential`` does that.
        """
        stopped = threading.Event()

        # The term the lease was issued for, used to time renewals after the
        # first: CoreLink reports an expiry on issue and not on renewal, so
        # there is nothing else to measure against.
        term = leases._term_seconds(lease)

        def loop():
            remaining = leases._seconds_until(lease.expires_at) or term
            while not stopped.is_set():
                wait = max(remaining / 2, self._keep_alive_floor)
                if stopped.wait(wait):
                    return
                try:
                    self.renew_lease(lease.id)
                except Exception as exc:  # noqa: BLE001 -- reported, not swallowed
                    if on_expiry is not None:
                        on_expiry(exc)
                    return
                remaining = term

        thread = threading.Thread(target=loop, name="corelink-keepalive", daemon=True)
        thread.start()
        return stopped.set

    def get_certificate(self, name):
        """Return a TLS bundle, fetched through the sealed path and parsed here.

        A certificate is a secret whose value is a bundle, so it needs no
        delivery mechanism of its own: the same envelope, the same key, the same
        binding. The connector used to serve a bundle's parts from plaintext it
        held in memory, which was the last readable thing in that process.

        The private key exists in this process and nowhere else.
        """
        return sealed.certificate_from(self.get_secret_sealed(name))

    def _open_sealed(self, name, refresh):
        """One attempt at fetching, unwrapping and opening."""
        envelope = self._fetch_envelope(name, refresh)
        dek, version, authoritative_name = self._unwrap_dek(envelope["secret_id"])
        try:
            # The name CoreLink says this id belongs to must be the name that was
            # asked for. See sealed.WrongSecret: the AAD binds an envelope to its
            # own id and version, so a substituted secret opens cleanly and only
            # this comparison catches it.
            if authoritative_name and authoritative_name != name.strip("/"):
                raise sealed.WrongSecret(
                    f"asked for {name.strip('/')!r} and the connector answered "
                    f"with {authoritative_name!r}"
                )
            # The key belongs to whatever version CoreLink currently holds. A
            # different one means this envelope is behind, and saying so is
            # clearer than letting the AEAD fail for an unexplained reason.
            if version != envelope.get("version"):
                raise sealed.StaleEnvelope(
                    f"the connector served version {envelope.get('version')}, "
                    f"CoreLink is on {version}"
                )
            plaintext = sealed.open_envelope(
                envelope["envelope"], dek, envelope["secret_id"], version
            )
        finally:
            del dek
        return sealed.value_from(plaintext)

    def _platform_request(self, method, path, json=None):
        """Send an authenticated request to CoreLink."""
        with self._session_lock:
            session_id = self._session_id
        if not session_id:
            raise RuntimeError("no CoreLink session; call bootstrap() first")
        return self._session.request(
            method,
            f"{self._platform_url}{path}",
            headers={"X-NHI-Session": session_id},
            json=json,
            timeout=10,
        )

    def _fetch_envelope(self, name, refresh):
        """Take the sealed envelope from the connector.

        Unauthenticated, because the connector has nothing to decide: what it
        serves cannot be opened without a grant CoreLink checks.
        """
        url = f"{self._url}/v1/envelopes/{sealed.envelope_path(name)}"
        if refresh:
            url += "?refresh=1"
        resp = self._session.get(url, timeout=10)
        if resp.status_code != 200:
            raise RuntimeError(
                f"the connector has no envelope for {name!r} "
                f"(status {resp.status_code}: {resp.text[:200].strip()})"
            )
        envelope = resp.json()
        if not envelope.get("envelope") or not envelope.get("secret_id"):
            raise RuntimeError(f"the connector served an incomplete envelope for {name!r}")
        return envelope

    def _unwrap_dek(self, secret_id):
        """Ask CoreLink for the key to one secret.

        CoreLink unwraps its own copy, so nothing this process holds takes part:
        an application handed somebody else's ciphertext cannot have it opened by
        naming a secret it is entitled to.
        """
        with self._session_lock:
            session_id = self._session_id
        if not session_id:
            raise RuntimeError("no CoreLink session; call bootstrap() first")

        resp = self._session.post(
            f"{self._platform_url}/api/v1/nhi-agent/secrets/{quote(secret_id, safe='')}/unwrap",
            headers={"X-NHI-Session": session_id},
            timeout=10,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"CoreLink refused to unwrap (status {resp.status_code}: "
                f"{resp.text[:200].strip()})"
            )
        body = resp.json()
        dek = base64.b64decode(body.get("dek", ""))
        if not dek:
            raise RuntimeError("CoreLink returned no key")
        # The name is CoreLink's answer to "which secret is this id?", which only
        # it can give. The caller compares it against what it asked for.
        return dek, body.get("version"), body.get("name", "")

    def list_configs(self):
        """Return a list of dicts with 'name', 'file_name', and 'content' keys."""
        resp = self._authed_get(f"{self._url}/v1/configs")
        resp.raise_for_status()
        return resp.json().get("configs", [])

    def get_config(self, name):
        """Return the rendered content of a single config file by name."""
        resp = self._authed_get(f"{self._url}/v1/configs/{name}")
        resp.raise_for_status()
        return resp.json().get("content", "")

    def close(self):
        """Stop background timers and disconnect the NHI session."""
        if self._heartbeat_timer is not None:
            self._heartbeat_timer.cancel()
            self._heartbeat_timer = None
        self._nhi_disconnect()

    # -------------------------------------------------------------------------
    # NHI fingerprint session management
    # -------------------------------------------------------------------------

    def _collect_attestation(self):
        """Return (attest_type, evidence), asking the caller first.

        A workload that federates to its own issuer knows how to get its token
        and the SDK does not; a pod or a host is the other way round.
        """
        if self._attest is not None:
            return self._attest()
        return self._detect_attestation()

    def _detect_attestation(self):
        """Auto-detect the runtime environment and return (attest_type, evidence).

        Detection order:
          1. Kubernetes: service account token projected by the kubelet.
          2. Host fallback: stable fingerprint derived from the binary hash.

        AWS, Azure, and GCP detection require HTTP calls to instance metadata
        endpoints and are left as future work. The server accepts "host" for
        non-cloud deployments.

        The returned evidence must never be logged -- it may contain a
        Kubernetes service account JWT.
        """
        # Kubernetes: service account token projected by the kubelet.
        try:
            with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
                token = f.read().strip()
            if token:
                return "kubernetes", token
        except OSError:
            pass

        # Host fallback: use the stable fingerprint as evidence.
        from .fingerprint import compute_fingerprint
        fp, _ = compute_fingerprint(self._nhi_id)
        return "host", fp

    def _nhi_connect(self):
        """Connect to platform using attestation evidence."""
        attest_type, evidence = self._collect_attestation()
        # evidence must not be logged -- it may contain a Kubernetes SA token.
        resp = self._session.post(
            f"{self._platform_url}/api/v1/nhi-agent/connect",
            json={
                "nhi_id": self._nhi_id,
                "attestation": {"type": attest_type, "evidence": evidence},
            },
            timeout=10,
        )
        if resp.status_code == 403:
            raise RuntimeError("NHI identity verification failed")
        resp.raise_for_status()
        data = resp.json()
        session_id = data["session_id"]

        # Treat a missing status field as "active" for backward compatibility.
        status = data.get("status") or "active"
        if status == "pending_approval":
            prefix = session_id[:8]
            log.info("Waiting for admin approval (session: %s)...", prefix)
            self._poll_approval(session_id)
        elif status != "active":
            raise RuntimeError(f"NHI connect returned unexpected status: {status!r}")

        with self._session_lock:
            self._session_id = session_id
        self._schedule_heartbeat()

    def _poll_approval(self, session_id):
        """Poll the platform every 5 seconds until the session is approved or rejected.

        Raises RuntimeError on rejection or timeout (5 minutes).
        """
        url = f"{self._platform_url}/api/v1/nhi-agent/connect/{session_id}/status"
        for _ in range(60):  # 60 * 5s = 5 minutes
            time.sleep(5)
            try:
                resp = self._session.get(url, timeout=10)
                if resp.ok:
                    status = resp.json().get("status")
                    if status == "active":
                        return
                    if status == "rejected":
                        raise RuntimeError("Connect request rejected by admin")
            except RuntimeError:
                raise
            except Exception:
                pass  # transient error; keep polling
        raise RuntimeError("Approval timeout (5 minutes)")

    def _nhi_heartbeat(self):
        """Renew NHI session by re-collecting attestation evidence."""
        attest_type, evidence = self._collect_attestation()
        # evidence must not be logged -- it may contain a Kubernetes SA token.
        try:
            with self._session_lock:
                sid = self._session_id
            resp = self._session.post(
                f"{self._platform_url}/api/v1/nhi-agent/heartbeat",
                headers={"X-NHI-Session": sid},
                json={"attestation": {"type": attest_type, "evidence": evidence}},
                timeout=10,
            )
            if resp.status_code in (401, 403):
                self._nhi_connect()
                return
            resp.raise_for_status()
        except Exception:
            try:
                self._nhi_connect()
            except Exception:
                pass
        self._schedule_heartbeat()

    def _schedule_heartbeat(self):
        """Schedule next heartbeat in 50 minutes."""
        if self._heartbeat_timer:
            self._heartbeat_timer.cancel()
        self._heartbeat_timer = threading.Timer(3000, self._nhi_heartbeat)
        self._heartbeat_timer.daemon = True
        self._heartbeat_timer.start()

    def _nhi_disconnect(self):
        """Best-effort session disconnect."""
        with self._session_lock:
            sid = self._session_id
        if not sid:
            return
        try:
            self._session.post(
                f"{self._platform_url}/api/v1/nhi-agent/disconnect",
                headers={"X-NHI-Session": sid},
                timeout=5,
            )
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _auth_header(self):
        with self._session_lock:
            sid = self._session_id
        if sid:
            return {"X-NHI-Session": sid}
        return {}

    def _authed_get(self, url):
        """GET with NHI session auth; on 401 reconnects and retries once."""
        resp = self._session.get(url, headers=self._auth_header(), timeout=10)
        if resp.status_code != 401:
            return resp

        # Session expired: reconnect and retry once.
        try:
            self._nhi_connect()
        except Exception:
            pass
        return self._session.get(url, headers=self._auth_header(), timeout=10)
