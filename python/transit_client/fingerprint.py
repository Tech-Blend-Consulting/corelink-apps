"""Runtime fingerprint computation for NHI identity verification."""

import hashlib
import os
import platform
import subprocess
import sys


def compute_fingerprint(nhi_id: str) -> tuple[str, dict[str, str]]:
    """Compute a runtime fingerprint for this process.

    Returns (fingerprint_hex, metadata_dict).
    """
    meta = {}

    # Binary hash: SHA-256 of the running executable
    try:
        exec_path = sys.executable or os.path.abspath(sys.argv[0])
        with open(exec_path, "rb") as f:
            bin_hash = hashlib.sha256(f.read()).hexdigest()
    except (OSError, IndexError):
        bin_hash = hashlib.sha256(sys.version.encode()).hexdigest()
    meta["binary_hash"] = bin_hash

    # Machine ID
    machine_id = _read_machine_id()
    meta["machine_id"] = machine_id

    # Hostname
    hostname = platform.node()
    meta["hostname"] = hostname
    meta["os"] = platform.system().lower()
    meta["arch"] = platform.machine()

    # Combine and hash
    h = hashlib.sha256()
    h.update(bytes.fromhex(bin_hash))
    h.update(machine_id.encode())
    h.update(hostname.encode())
    h.update(nhi_id.encode())

    return h.hexdigest(), meta


def _read_machine_id() -> str:
    """Read platform-specific machine ID."""
    system = platform.system()

    if system == "Linux":
        try:
            with open("/etc/machine-id") as f:
                return f.read().strip()
        except OSError:
            pass
        # Docker fallback
        try:
            with open("/proc/self/cgroup") as f:
                for line in f:
                    parts = line.strip().split("/")
                    if parts and len(parts[-1]) >= 12:
                        return parts[-1][:12]
        except OSError:
            pass

    elif system == "Darwin":
        try:
            out = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                text=True, timeout=5,
            )
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    _, _, val = line.partition("=")
                    return val.strip().strip('"')
        except (subprocess.SubprocessError, OSError):
            pass

    elif system == "Windows":
        try:
            out = subprocess.check_output(
                ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"],
                text=True, timeout=5,
            )
            for line in out.splitlines():
                if "MachineGuid" in line:
                    return line.split()[-1]
        except (subprocess.SubprocessError, OSError):
            pass

    return platform.node()
