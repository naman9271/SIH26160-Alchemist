package model

// Canonical evidence property keys.  These keys are the contract shared by
// packet collection, gateway telemetry, Fusion, assessment, reports, and the
// browser API.  Do not introduce aliases: an unavailable fact must remain
// unavailable instead of being hidden behind a similarly named property.
const (
	PropertyIKEVersion           = "ike.version"
	PropertyIKEEncryption        = "ike.encryption"
	PropertyIKEIntegrity         = "ike.integrity"
	PropertyIKEPRF               = "ike.prf"
	PropertyIKEDHGroup           = "ike.dh_group"
	PropertyChildMode            = "child.mode"
	PropertyChildEncryption      = "child.encryption_algorithm"
	PropertyChildIntegrity       = "child.integrity_algorithm"
	PropertyChildPFS             = "child.pfs"
	PropertyReplayEnabled        = "replay.enabled"
	PropertyChildLifetimeSeconds = "child.lifetime_seconds"
	PropertyMetadataExposure     = "metadata.exposure"
)

// SecurityConfigurationProperties are the six facts used to calculate
// configuration-evidence coverage.  Lifetime is intentionally excluded: it
// is assessed when present but cannot be established from most passive PCAPs.
var SecurityConfigurationProperties = []string{
	PropertyIKEVersion,
	PropertyChildEncryption,
	PropertyChildIntegrity,
	PropertyIKEDHGroup,
	PropertyChildPFS,
	PropertyReplayEnabled,
}

// StatusMeaning is deliberately small and stable for UI/report provenance.
// UNKNOWN means the collection path could not establish a fact; it never
// means compliant, absent, disabled, or safe.
func StatusMeaning(status string) string {
	switch status {
	case "OBSERVED":
		return "passive packet observation"
	case "DERIVED":
		return "deterministic derivation from observed data"
	case "INFERRED":
		return "probabilistic metadata inference"
	case "VERIFIED_GATEWAY":
		return "read-only gateway or kernel verification"
	case "UNKNOWN":
		return "not evaluated"
	default:
		return "unspecified"
	}
}
