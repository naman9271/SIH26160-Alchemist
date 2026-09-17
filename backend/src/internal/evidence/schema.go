// Package evidence defines the shared vocabulary used by producers and consumers.
package evidence

const Version = "ipsec-evidence.v2"

const (
	ChildEncryption = "child.encryption_algorithm"
	ChildIntegrity = "child.integrity_algorithm"
	ChildMode = "child.mode"
	ChildPFS = "child.pfs"
	ChildLifetime = "child.lifetime_seconds"
	ReplayEnabled = "replay.enabled"
)

// Canonical preserves compatibility with previously stored evidence.
func Canonical(key string) string {
	switch key {
	case "child.esp_encryption": return ChildEncryption
	case "child.integrity": return ChildIntegrity
	default: return key
	}
}

// RequiredProperties is returned as a copy so policy callers cannot mutate it.
func RequiredProperties() []string {
	return []string{"ike.version", "ike.encryption", "ike.integrity", "ike.prf", "ike.dh_group", ChildMode, ChildEncryption, ChildIntegrity, ChildPFS, ChildLifetime, ReplayEnabled, "traffic.class", "metadata.exposure"}
}
