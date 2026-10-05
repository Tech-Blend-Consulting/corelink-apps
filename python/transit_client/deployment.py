"""The deployment file: what an application was configured to ask for.

.. code-block:: yaml

    nhiId:          11111111-2222-3333-4444-555555555555
    serviceAccount: orders
    secrets:
      - production/dbone
      - production/apikey

It tells the SDK which identity to attest as and which secrets to ask for. That
is all it is.

**Nothing in it grants anything**, and that must stay true even when somebody
proposes provisioning grants from it as a convenience. Anyone who can edit a
Deployment can add a path to this file; if that provisioned access, "edit
deployments" would quietly become "read any secret". The file is a request. The
grant on the NHI is the only answer, and CoreLink checks it on every call
regardless of what is written here.

Neither value is sensitive. The NHI id is a pointer, not a credential: Connect
looks the identity up by the id presented and then verifies the evidence against
*that identity's* binding, so an application naming someone else's id and
attesting with its own ServiceAccount fails the claim match.

**Deliberately not a YAML parser.** YAML is a large language -- anchors, flow
collections, multi-line scalars, implicit typing -- and most of it is ways for a
file to mean something other than it appears to. Three keys are needed, so
everything else is refused rather than guessed at. A file using a feature this
does not implement fails loudly instead of being read as something its author did
not write, which is the safe direction: this file decides which secrets an
application asks for.

Pinned against the other five SDKs by ``sdk/testdata/deployment_cases.json``.
"""

import base64
import json
import os

#: Where the file is looked for when no path is given.
DEFAULT_DEPLOYMENT_PATH = "/etc/corelink/secrets.yaml"

#: Environment variable that overrides the default path.
DEPLOYMENT_PATH_ENV = "CORELINK_DEPLOYMENT_FILE"

_SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"


class DeploymentError(Exception):
    """A deployment file that could not be read as written."""


class Deployment:
    """A parsed deployment file."""

    __slots__ = ("nhi_id", "service_account", "secrets", "path")

    def __init__(self, nhi_id="", service_account="", secrets=None, path=""):
        self.nhi_id = nhi_id
        self.service_account = service_account
        self.secrets = secrets or []
        self.path = path

    def __repr__(self):
        return (
            f"Deployment(nhi_id={self.nhi_id!r}, service_account={self.service_account!r}, "
            f"secrets={self.secrets!r}, path={self.path!r})"
        )

    def verify_service_account(self):
        """Raise if the pod is not running as the ServiceAccount the file names.

        **A misconfiguration check, not a security control.** The projected
        token's claims are read without verifying its signature, because nothing
        this concludes is trusted: CoreLink verifies that token properly, against
        the identity's own binding, and that is what decides whether the workload
        is who it says. Re-deciding it here would be a second authorization path
        for one question.

        What it is for: a Deployment whose secrets.yaml names one ServiceAccount
        while the pod spec says another will fail at CoreLink with a claim
        mismatch, later and somewhere less obvious. Saying so at startup turns a
        confusing refusal into an obvious one.

        No name, no token, or an unreadable one: no opinion, no error.
        """
        if not self.service_account:
            return
        try:
            with open(_SA_TOKEN_PATH) as fh:
                token = fh.read()
        except OSError:
            return
        actual = _service_account_from_token(token)
        if actual is None:
            return
        if actual != self.service_account:
            raise DeploymentError(
                f"{self.path} names serviceAccount {self.service_account!r} but this pod "
                f"is running as {actual!r}; the deployment file and the pod spec disagree"
            )


def _resolve_path(path):
    return path or os.environ.get(DEPLOYMENT_PATH_ENV) or DEFAULT_DEPLOYMENT_PATH


def load_deployment(path=None):
    """Read the deployment file, raising if it is missing or unreadable."""
    path = _resolve_path(path)
    try:
        with open(path) as fh:
            text = fh.read()
    except OSError as exc:
        raise DeploymentError(f"reading the deployment file {path}: {exc}") from exc

    try:
        d = _parse(text)
    except DeploymentError as exc:
        raise DeploymentError(f"{path}: {exc}") from None
    d.path = path

    if not d.nhi_id:
        raise DeploymentError(f"{path}: nhiId is required; it names the identity to attest as")
    if not d.secrets:
        raise DeploymentError(
            f"{path}: secrets is required; an application asks for what it was "
            "configured to ask for rather than discovering what exists"
        )
    return d


def load_deployment_if_present(path=None):
    """``load_deployment``, except that a missing file returns ``None``.

    For an application that can be configured either way. A file that exists and
    does not parse is still an error: the difference that matters is "no file"
    against "a file I could not read", and silently ignoring the second would run
    the application on a configuration nobody wrote.
    """
    look_in = _resolve_path(path)
    if not os.path.exists(look_in):
        return None
    return load_deployment(look_in)


def _parse(text):
    """Read the one shape this file has, and refuse the rest."""
    d = Deployment()
    seen = set()
    list_key = None

    for n, raw in enumerate(text.split("\n"), start=1):
        if "\t" in raw:
            raise DeploymentError(f"line {n}: tabs are not allowed in indentation")

        # A comment is only a comment at the start of a line here. Stripping a
        # trailing "#" would corrupt any value that legitimately contains one.
        trimmed = raw.strip()
        if not trimmed or trimmed.startswith("#"):
            continue
        if trimmed.startswith("---") or trimmed.startswith("..."):
            raise DeploymentError(f"line {n}: multiple documents are not supported")
        if "&" in trimmed or "*" in trimmed:
            raise DeploymentError(f"line {n}: anchors and aliases are not supported")

        # A list entry, which belongs to the key above it.
        if trimmed.startswith("- ") or trimmed == "-":
            if list_key is None:
                raise DeploymentError(f"line {n}: a list entry with no key above it")
            item = _scalar(trimmed[1:].strip(), n)
            if not item:
                raise DeploymentError(f"line {n}: an empty list entry")
            if list_key != "secrets":
                raise DeploymentError(f"line {n}: {list_key!r} does not take a list")
            d.secrets.append(item)
            continue

        # Anything else must be a key at the left margin. Leading whitespace is
        # what makes it indented; trailing whitespace is invisible and harmless.
        if raw.lstrip(" ") != raw:
            raise DeploymentError(
                f"line {n}: unexpected indentation; this file is a flat set of keys"
            )
        if ":" not in trimmed:
            raise DeploymentError(f'line {n}: expected "key: value"')
        key, _, value = trimmed.partition(":")
        # YAML needs a space after the colon to make this a mapping at all --
        # "nhiId:abc" is a plain scalar, not a key.
        if value and not value.startswith(" "):
            raise DeploymentError(f"line {n}: a key needs a space after its colon")
        key = key.strip()
        value = value.strip()

        if key in seen:
            # Two values for one key: a reader has to pick, and either choice is
            # somebody's surprise.
            raise DeploymentError(f"line {n}: {key!r} appears more than once")
        seen.add(key)
        list_key = None

        if key in ("nhiId", "nhiID", "nhi_id"):
            d.nhi_id = _scalar(value, n)
        elif key in ("serviceAccount", "service_account"):
            d.service_account = _scalar(value, n)
        elif key == "secrets":
            if value == "":
                # The list form; entries follow on their own lines.
                list_key = "secrets"
                continue
            d.secrets.append(_scalar(value, n))
        else:
            # Refused rather than ignored. A typo in a key an application relies
            # on would otherwise be silence, and the application would run asking
            # for nothing.
            raise DeploymentError(f"line {n}: unknown key {key!r}")

    return d


def _scalar(v, n):
    """Read one plain value, refusing the YAML forms this does not implement."""
    if v == "":
        return ""
    if v.startswith("[") or v.startswith("{"):
        raise DeploymentError(
            f'line {n}: flow collections are not supported; use a "- item" list'
        )
    if v.startswith("|") or v.startswith(">"):
        raise DeploymentError(f"line {n}: multi-line scalars are not supported")
    if len(v) >= 2:
        first, last = v[0], v[-1]
        if (first == '"' and last == '"') or (first == "'" and last == "'"):
            inner = v[1:-1]
            if first in inner:
                raise DeploymentError(
                    f"line {n}: escapes inside a quoted value are not supported"
                )
            return inner
        if first in "\"'":
            raise DeploymentError(f"line {n}: a quoted value is not closed")
    elif v in ("\"", "'"):
        raise DeploymentError(f"line {n}: a quoted value is not closed")
    if ": " in v or v.endswith(":"):
        # YAML refuses ": " inside a plain scalar because it cannot tell the
        # value from a nested mapping.
        raise DeploymentError(f"line {n}: a value containing a colon must be quoted")
    if "#" in v:
        # Ambiguous: YAML would read " #" as a trailing comment, and a reader
        # that guesses either way is wrong for somebody.
        raise DeploymentError(f"line {n}: a value containing # must be quoted")
    return v


def _service_account_from_token(token):
    """The ServiceAccount name from a projected token, or None.

    The signature is not checked; see ``Deployment.verify_service_account``.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, TypeError):
        return None
    if not isinstance(claims, dict):
        return None
    # The subject, which is the canonical and flat form:
    #   system:serviceaccount:<namespace>:<name>
    # Every projected token carries it, so there is no need to reach into the
    # nested kubernetes.io claim for the same name.
    bits = claims.get("sub", "").split(":")
    if len(bits) == 4 and bits[0] == "system":
        return bits[3]
    return None
    return load_deployment(look_in)


def _parse(text):
    """Read the one shape this file has, and refuse the rest."""
    d = Deployment()
    seen = set()
    list_key = None

    for n, raw in enumerate(text.split("\n"), start=1):
        if "\t" in raw:
            raise DeploymentError(f"line {n}: tabs are not allowed in indentation")

        # A comment is only a comment at the start of a line here. Stripping a
        # trailing "#" would corrupt any value that legitimately contains one.
        trimmed = raw.strip()
        if not trimmed or trimmed.startswith("#"):
            continue
        if trimmed.startswith("---") or trimmed.startswith("..."):
            raise DeploymentError(f"line {n}: multiple documents are not supported")
        if "&" in trimmed or "*" in trimmed:
            raise DeploymentError(f"line {n}: anchors and aliases are not supported")

        # A list entry, which belongs to the key above it.
        if trimmed.startswith("- ") or trimmed == "-":
            if list_key is None:
                raise DeploymentError(f"line {n}: a list entry with no key above it")
            item = _scalar(trimmed[1:].strip(), n)
            if not item:
                raise DeploymentError(f"line {n}: an empty list entry")
            if list_key != "secrets":
                raise DeploymentError(f"line {n}: {list_key!r} does not take a list")
            d.secrets.append(item)
            continue

        # Anything else must be a key at the left margin. Leading whitespace is
        # what makes it indented; trailing whitespace is invisible and harmless.
        if raw.lstrip(" ") != raw:
            raise DeploymentError(
                f"line {n}: unexpected indentation; this file is a flat set of keys"
            )
        if ":" not in trimmed:
            raise DeploymentError(f'line {n}: expected "key: value"')
        key, _, value = trimmed.partition(":")
        # YAML needs a space after the colon to make this a mapping at all --
        # "nhiId:abc" is a plain scalar, not a key.
        if value and not value.startswith(" "):
            raise DeploymentError(f"line {n}: a key needs a space after its colon")
        key = key.strip()
        value = value.strip()

        if key in seen:
            # Two values for one key: a reader has to pick, and either choice is
            # somebody's surprise.
            raise DeploymentError(f"line {n}: {key!r} appears more than once")
        seen.add(key)
        list_key = None

        if key in ("nhiId", "nhiID", "nhi_id"):
            d.nhi_id = _scalar(value, n)
        elif key in ("serviceAccount", "service_account"):
            d.service_account = _scalar(value, n)
        elif key == "secrets":
            if value == "":
                # The list form; entries follow on their own lines.
                list_key = "secrets"
                continue
            d.secrets.append(_scalar(value, n))
        else:
            # Refused rather than ignored. A typo in a key an application relies
            # on would otherwise be silence, and the application would run asking
            # for nothing.
            raise DeploymentError(f"line {n}: unknown key {key!r}")

    return d


def _scalar(v, n):
    """Read one plain value, refusing the YAML forms this does not implement."""
    if v == "":
        return ""
    if v.startswith("[") or v.startswith("{"):
        raise DeploymentError(
            f'line {n}: flow collections are not supported; use a "- item" list'
        )
    if v.startswith("|") or v.startswith(">"):
        raise DeploymentError(f"line {n}: multi-line scalars are not supported")
    if len(v) >= 2:
        first, last = v[0], v[-1]
        if (first == '"' and last == '"') or (first == "'" and last == "'"):
            inner = v[1:-1]
            if first in inner:
                raise DeploymentError(
                    f"line {n}: escapes inside a quoted value are not supported"
                )
            return inner
        if first in "\"'":
            raise DeploymentError(f"line {n}: a quoted value is not closed")
    elif v in ("\"", "'"):
        raise DeploymentError(f"line {n}: a quoted value is not closed")
    if ": " in v or v.endswith(":"):
        # YAML refuses ": " inside a plain scalar because it cannot tell the
        # value from a nested mapping.
        raise DeploymentError(f"line {n}: a value containing a colon must be quoted")
    if "#" in v:
        # Ambiguous: YAML would read " #" as a trailing comment, and a reader
        # that guesses either way is wrong for somebody.
        raise DeploymentError(f"line {n}: a value containing # must be quoted")
    return v


def _service_account_from_token(token):
    """The ServiceAccount name from a projected token, or None.

    The signature is not checked; see ``Deployment.verify_service_account``.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, TypeError):
        return None
    if not isinstance(claims, dict):
        return None
    k8s = claims.get("kubernetes.io")
    if isinstance(k8s, dict):
        sa = k8s.get("serviceaccount")
        if isinstance(sa, dict) and sa.get("name"):
            return sa["name"]
    # Older tokens carry only the subject: system:serviceaccount:<ns>:<name>
    sub = claims.get("sub", "")
    bits = sub.split(":")
    if len(bits) == 4 and bits[0] == "system":
        return bits[3]
    return None
