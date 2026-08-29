package security

import "testing"

func TestAssessmentUsesOnlyAvailableFacts(t *testing.T) {
	result := Assess(Facts{})
	if result.Score != 100 || len(result.Findings) != 0 {
		t.Fatalf("unknown facts created findings: %+v", result)
	}
}

func TestAssessmentFindsWeakVerifiedConfiguration(t *testing.T) {
	disabled := false
	result := Assess(Facts{
		IKEVersion: "IKEv1", EncryptionAlgorithm: "3DES",
		IntegrityAlgorithm: "HMAC-SHA1", DHGroup: "GROUP2-MODP1024",
		PFS: &disabled, ReplayProtection: &disabled,
		SALifetimeSeconds: 172800, MetadataExposure: true,
	})
	if len(result.Findings) != 8 || result.Score >= 50 || result.ThreatMatrix[SeverityHigh] != 4 {
		t.Fatalf("unexpected assessment: %+v", result)
	}
	if result.Findings[0].Severity != SeverityHigh {
		t.Fatalf("findings are not severity ordered: %+v", result.Findings)
	}
}

func TestModernConfigurationHasOnlyResidualMetadataFinding(t *testing.T) {
	enabled := true
	result := Assess(Facts{
		IKEVersion: "IKEv2", EncryptionAlgorithm: "AES-256-GCM-16",
		IntegrityAlgorithm: "AEAD", DHGroup: "19-ECP256",
		PFS: &enabled, ReplayProtection: &enabled,
		SALifetimeSeconds: 3600, MetadataExposure: true,
	})
	if len(result.Findings) != 1 || result.Findings[0].RuleID != "IPSEC_METADATA_001" || result.Score != 97 {
		t.Fatalf("unexpected assessment: %+v", result)
	}
}
