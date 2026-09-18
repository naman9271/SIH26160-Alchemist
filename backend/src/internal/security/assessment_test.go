package security

import "testing"

func TestAssessmentUsesOnlyAvailableFacts(t *testing.T) {
	result := Assess(Facts{})
	if result.Score != 0 || result.Coverage != 0 || result.UnknownRule != 8 || len(result.Findings) != 0 {
		t.Fatalf("unknown facts created findings: %+v", result)
	}
}

func TestAssessmentFindsWeakVerifiedConfiguration(t *testing.T) {
	disabled := false
	result := Assess(Facts{
		IKEVersion: "IKEv1", EncryptionAlgorithm: "3DES",
		IntegrityAlgorithm: "HMAC-SHA1", DHGroup: "GROUP2-MODP1024",
		PFS: &disabled, ReplayProtection: &disabled,
		SALifetimeSeconds: 172800, SALifetimeKnown: true, MetadataExposure: true, MetadataKnown: true,
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
		SALifetimeSeconds: 3600, SALifetimeKnown: true, MetadataExposure: true, MetadataKnown: true,
	})
	if len(result.Findings) != 1 || result.Findings[0].RuleID != "IPSEC_METADATA_001" || result.Score != 95 || result.Coverage != 100 {
		t.Fatalf("unexpected assessment: %+v", result)
	}
}

func TestAlgorithmMatchingUsesExactNormalizedIdentifiers(t *testing.T) {
	strong := Assess(Facts{DHGroup: "GROUP14"})
	if len(strong.Findings) != 0 {
		t.Fatalf("GROUP14 was confused with GROUP1: %+v", strong.Findings)
	}
	weak := Assess(Facts{DHGroup: "DH_2"})
	if len(weak.Findings) != 1 || weak.Findings[0].RuleID != "IPSEC_DH_001" {
		t.Fatalf("DH_2 did not trigger the weak-group rule: %+v", weak.Findings)
	}
}
