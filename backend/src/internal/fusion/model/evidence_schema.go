package model

// Canonical evidence property keys.  These keys are the contract shared by
// packet collection, gateway telemetry, Fusion, assessment, reports, and the
// browser API.  Do not introduce aliases: an unavailable fact must remain
// unavailable instead of being hidden behind a similarly named property.
const (
	PropertyIKEVersion                       = "ike.version"
	PropertyIKEEncryption                    = "ike.encryption"
	PropertyIKEIntegrity                     = "ike.integrity"
	PropertyIKEPRF                           = "ike.prf"
	PropertyIKEDHGroup                       = "ike.dh_group"
	PropertyIKEAuthentication                = "ike.authentication_methods"
	PropertyIKEEncryptionKeyBits             = "ike.encryption_key_length_bits"
	PropertyIKEAEADTagBits                   = "ike.aead_tag_length_bits"
	PropertyIKELifetimeSeconds               = "ike.lifetime_seconds"
	PropertyConfiguredIKEProposals           = "config.ike.proposals"
	PropertyChildMode                        = "child.mode"
	PropertyChildProtocol                    = "child.protocol"
	PropertyChildState                       = "child.state"
	PropertyChildDirection                   = "xfrm.direction"
	PropertyChildLocalSelectors              = "child.local_traffic_selectors"
	PropertyChildRemoteSelectors             = "child.remote_traffic_selectors"
	PropertyChildEncryption                  = "child.encryption_algorithm"
	PropertyChildIntegrity                   = "child.integrity_algorithm"
	PropertyChildEncryptionKeyBits           = "child.encryption_key_length_bits"
	PropertyChildAEADTagBits                 = "child.aead_tag_length_bits"
	PropertyChildPFS                         = "child.pfs"
	PropertyChildFreshExchange               = "child.fresh_exchange_observed"
	PropertyReplayEnabled                    = "replay.enabled"
	PropertyReplayWindow                     = "replay.window"
	PropertyReplayESN                        = "replay.extended_sequence_numbers"
	PropertyReplaySequence                   = "replay.sequence"
	PropertyChildLifetimeSeconds             = "child.lifetime_seconds"
	PropertyChildInstallAgeSeconds           = "child.install_age_seconds"
	PropertyChildRemainingLifetimeSeconds    = "child.remaining_lifetime_seconds"
	PropertySAConfigurationRuntimeConsistent = "sa.configuration_runtime_consistent"
	PropertyConfiguredChildProposals         = "config.child.proposals"
	PropertyMetadataExposure                 = "metadata.exposure"
	// PropertyMetadataProtectionRequired is an explicit deployment policy. It
	// is deliberately separate from ordinary ESP metadata observation: seeing
	// outer packet metadata alone is not a baseline failure.
	PropertyMetadataProtectionRequired = "policy.metadata_protection_required"
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
