package transit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// ComputeFingerprint generates a runtime fingerprint for this process.
// The fingerprint is a SHA-256 hash of: binary hash + machine ID + hostname + NHI ID.
//
// The fingerprint and its component metadata are returned so the caller can
// include them in the connect/heartbeat payload. Neither the fingerprint nor
// the session ID derived from it should be written to logs.
func ComputeFingerprint(nhiID string) (string, map[string]string, error) {
	meta := map[string]string{}

	// Binary hash: SHA-256 of the running executable.
	execPath, err := os.Executable()
	if err != nil {
		return "", nil, fmt.Errorf("transit: cannot determine executable path: %w", err)
	}
	binData, err := os.ReadFile(execPath)
	if err != nil {
		return "", nil, fmt.Errorf("transit: cannot read executable: %w", err)
	}
	binHash := sha256.Sum256(binData)
	meta["binary_hash"] = hex.EncodeToString(binHash[:])

	// Machine ID (platform-specific).
	machineID := readMachineID()
	meta["machine_id"] = machineID

	// Hostname.
	hostname, _ := os.Hostname()
	meta["hostname"] = hostname
	meta["os"] = runtime.GOOS
	meta["arch"] = runtime.GOARCH

	// Combine all components and hash.
	h := sha256.New()
	h.Write(binHash[:])
	h.Write([]byte(machineID))
	h.Write([]byte(hostname))
	h.Write([]byte(nhiID))

	return hex.EncodeToString(h.Sum(nil)), meta, nil
}

// CollectAttestation auto-detects the runtime environment and returns the
// attestation type and evidence string to include in connect/heartbeat payloads.
//
// Detection order:
//  1. Kubernetes: presence of the projected service account token file.
//  2. Host fallback: derived from ComputeFingerprint (binary hash + machine ID).
//
// AWS, Azure, and GCP detection require HTTP calls to instance metadata
// endpoints; those introduce latency on non-cloud hosts and are left as
// future work (the server accepts "host" type for non-cloud deployments).
//
// The evidence value must never be written to logs -- it may contain a
// Kubernetes service account JWT.
func CollectAttestation(nhiID string) (attestType, evidence string, err error) {
	// Kubernetes: service account token projected by the kubelet.
	const saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	if token, readErr := os.ReadFile(saTokenPath); readErr == nil && len(token) > 0 {
		return "kubernetes", string(token), nil
	}

	// Host fallback: use the stable fingerprint as evidence.
	fp, _, err := ComputeFingerprint(nhiID)
	if err != nil {
		return "", "", err
	}
	return "host", fp, nil
}

// readMachineID returns a stable machine identifier using platform-specific
// sources. Falls back to hostname when no platform source is available.
func readMachineID() string {
	switch runtime.GOOS {
	case "linux":
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			return strings.TrimSpace(string(data))
		}
		// Docker fallback: derive a short ID from the cgroup hierarchy.
		if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				parts := strings.Split(line, "/")
				if len(parts) > 0 {
					id := parts[len(parts)-1]
					if len(id) >= 12 {
						return id[:12]
					}
				}
			}
		}
	case "darwin":
		if out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "IOPlatformUUID") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						return strings.Trim(strings.TrimSpace(parts[1]), `"`)
					}
				}
			}
		}
	case "windows":
		if out, err := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "MachineGuid") {
					fields := strings.Fields(line)
					if len(fields) >= 3 {
						return fields[len(fields)-1]
					}
				}
			}
		}
	}
	// Ultimate fallback.
	hostname, _ := os.Hostname()
	return hostname
}
