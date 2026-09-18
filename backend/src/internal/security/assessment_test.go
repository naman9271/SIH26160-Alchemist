package security

import "testing"

func TestUnknownEvidenceNeverPasses(t *testing.T) {
	result := Assess(Facts{ResourceType: "ANALYSIS"})
	if result.ScoreAvailable || len(result.Findings) != 0 {
		t.Fatalf("unknown facts created credit or findings: %+v", result)
	}
	if result.PolicyID != SIHBaselinePolicyID || result.PolicyLabel != "SIH baseline compliance" {
		t.Fatalf("wrong policy identity: %+v", result)
	}
}

func TestD2UsesObservedScoreCoverageAndBoundsSeparately(t *testing.T) {
	enabled := true
	result := Assess(Facts{ResourceType: "XFRM_STATE", EncryptionAlgorithm: "AES-256-GCM-16", IntegrityAlgorithm: "AEAD", EncryptionKeyKnown: true, EncryptionKeyBits: 256, AEADTagKnown: true, AEADTagBits: 128, Direction: "in", ReplayProtection: &enabled, ReplayWindowKnown: true, ReplayWindow: 32})
	if !result.ScoreAvailable || !result.CoverageAvailable || !result.Provisional {
		t.Fatalf("expected a provisional observed score with coverage: %+v", result)
	}
	if result.Score <= result.SecurityLowerBound || result.SecurityUpperBound < result.Score || result.Coverage <= 0 || result.Coverage >= 100 {
		t.Fatalf("D2 score, coverage and bounds are inconsistent: %+v", result)
	}
}

func TestMetadataExposureOnlyFailsWhenAnExplicitPolicyRequiresProtection(t *testing.T) {
	recorded := Assess(Facts{ResourceType: "METADATA", MetadataKnown: true, MetadataExposure: true})
	if recorded.RuleResults["SIH_METADATA_001"].Status != ControlPass {
		t.Fatalf("ordinary outer metadata exposure must be recorded without a failure: %+v", recorded)
	}
	required := true
	protected := Assess(Facts{ResourceType: "METADATA", MetadataKnown: true, MetadataExposure: true, MetadataProtectionRequired: &required})
	if protected.RuleResults["SIH_METADATA_001"].Status != ControlFail {
		t.Fatalf("explicit metadata-protection requirement must be enforced: %+v", protected)
	}
}

func TestCriticalNullCipherCapsObservedScoreAndMetadataDoesNotFailByDefault(t *testing.T) {
	result := Assess(Facts{ResourceType: "VICI_IKE_SA", IKEVersion: "IKEv2", IKEEncryption: "NULL", IKEEncryptionKeyKnown: true, IKEEncryptionKeyBits: 128, IKEAuthentication: "PSK", DHGroup: "GROUP14", IKELifetimeKnown: true, IKELifetimeSeconds: 3600, MetadataKnown: true, MetadataExposure: true})
	if !result.CriticalFailure || !result.ScoreCapped || result.Score != 40 {
		t.Fatalf("critical NULL cipher did not apply the D2 cap: %+v", result)
	}
	if result.RuleResults["SIH_METADATA_001"].Status != ControlPass {
		t.Fatalf("ordinary metadata exposure was penalized: %+v", result.RuleResults)
	}
}

func TestChildSuiteUsesCompleteExactSuite(t *testing.T) {
	pass := Assess(Facts{ResourceType: "XFRM_STATE", EncryptionAlgorithm: "AES-256-GCM-16", IntegrityAlgorithm: "AEAD", EncryptionKeyKnown: true, EncryptionKeyBits: 256, AEADTagKnown: true, AEADTagBits: 128})
	if pass.RuleResults["SIH_CHILD_SUITE_001"].Status != ControlPass {
		t.Fatalf("approved suite did not pass: %+v", pass.RuleResults)
	}
	fail := Assess(Facts{ResourceType: "XFRM_STATE", EncryptionAlgorithm: "AES-128-GCM-8", IntegrityAlgorithm: "AEAD", EncryptionKeyKnown: true, EncryptionKeyBits: 128, AEADTagKnown: true, AEADTagBits: 64})
	if fail.RuleResults["SIH_CHILD_SUITE_001"].Status != ControlFail {
		t.Fatalf("short GCM tag did not fail: %+v", fail.RuleResults)
	}
	unknown := Assess(Facts{ResourceType: "XFRM_STATE", EncryptionAlgorithm: "AES-FOO", EncryptionKeyKnown: true, EncryptionKeyBits: 256})
	if unknown.RuleResults["SIH_CHILD_SUITE_001"].Status != ControlUnknown {
		t.Fatalf("unsupported algorithm was treated as a decision: %+v", unknown.RuleResults)
	}
}

func TestIKEAndChildSuitesAreIndependent(t *testing.T) {
	result := Assess(Facts{ResourceType: "VICI_CHILD_SA", IKEEncryption: "3DES", EncryptionAlgorithm: "AES-256-CBC", EncryptionKeyKnown: true, EncryptionKeyBits: 256, IntegrityAlgorithm: "HMAC-SHA-256"})
	if result.RuleResults["SIH_IKE_SUITE_001"].Status != ControlFail || result.RuleResults["SIH_CHILD_SUITE_001"].Status != ControlPass {
		t.Fatalf("IKE and CHILD suites were not independent: %+v", result.RuleResults)
	}
}

func TestBaselineGroupsAndLifetimes(t *testing.T) {
	strong := Assess(Facts{DHGroup: "GROUP14"})
	if strong.RuleResults["SIH_DH_001"].Status != ControlPass {
		t.Fatalf("GROUP14 failed: %+v", strong.RuleResults)
	}
	weak := Assess(Facts{DHGroup: "DH_2"})
	if weak.RuleResults["SIH_DH_001"].Status != ControlFail {
		t.Fatalf("DH_2 did not fail: %+v", weak.RuleResults)
	}
	unsupported := Assess(Facts{DHGroup: "DH_65000"})
	if unsupported.RuleResults["SIH_DH_001"].Status != ControlUnknown {
		t.Fatalf("unknown DH group was not UNKNOWN: %+v", unsupported.RuleResults)
	}
	lifetime := Assess(Facts{ResourceType: "VICI_CHILD_SA", SALifetimeKnown: true, SALifetimeSeconds: 3601})
	if lifetime.RuleResults["SIH_CHILD_LIFETIME_001"].Status != ControlFail {
		t.Fatalf("CHILD lifetime above one hour passed: %+v", lifetime.RuleResults)
	}
}

func TestReplayOnlyClaimsVerifiedInboundEnforcement(t *testing.T) {
	enabled := true
	inbound := Assess(Facts{ResourceType: "XFRM_STATE", Direction: "in", ReplayProtection: &enabled, ReplayWindowKnown: true, ReplayWindow: 32})
	if inbound.RuleResults["SIH_REPLAY_001"].Status != ControlPass {
		t.Fatalf("verified inbound replay did not pass: %+v", inbound.RuleResults)
	}
	outbound := Assess(Facts{ResourceType: "XFRM_STATE", Direction: "out", ReplayProtection: &enabled, ReplayWindowKnown: true, ReplayWindow: 32})
	if outbound.RuleResults["SIH_REPLAY_001"].Status != ControlNotApplicable {
		t.Fatalf("outbound replay was assessed as enforcement: %+v", outbound.RuleResults)
	}
}

func TestConfiguredProposalAllowlistUsesNormalizedFields(t *testing.T) {
	approved := Assess(Facts{ResourceType: "VICI_CONNECTION", ConfiguredIKEProposals: "encr=aes256gcm16|integ=|prf=prfsha384|ke=ecp384", ConfiguredChildProposals: "encr=aes256|integ=sha256|prf=|ke=modp2048"})
	if approved.RuleResults["SIH_IKE_POLICY_001"].Status != ControlPass || approved.RuleResults["SIH_CHILD_POLICY_001"].Status != ControlPass {
		t.Fatalf("approved configured proposals did not pass: %+v", approved.RuleResults)
	}
	weak := Assess(Facts{ResourceType: "VICI_CONNECTION", ConfiguredIKEProposals: "encr=3des|integ=sha1|prf=prfsha1|ke=modp1024"})
	if weak.RuleResults["SIH_IKE_POLICY_001"].Status != ControlFail {
		t.Fatalf("weak configured proposal did not fail: %+v", weak.RuleResults)
	}
}
