package fusion

import (
	"testing"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
)

func TestVerifiedGatewayOverridesDerivedConflict(t *testing.T) {
	result, err := New().Fuse("child.mode", []Evidence{
		{ID: "passive", Property: "child.mode", Value: "TUNNEL", Source: SourcePacketParser, Status: commonv1.EvidenceStatus_DERIVED, Confidence: .72},
		{ID: "vici", Property: "child.mode", Value: "TRANSPORT", Source: SourceVICI, Status: commonv1.EvidenceStatus_VERIFIED_GATEWAY, Confidence: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Value != "TRANSPORT" || result.Status != commonv1.EvidenceStatus_VERIFIED_GATEWAY || len(result.Conflicts) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestClassifierUnknownIsPreservedWithoutRethresholding(t *testing.T) {
	result, err := New().Fuse("traffic.class", []Evidence{{
		ID: "ml", Property: "traffic.class", Value: "video", Source: SourceMLClassifier,
		Status: commonv1.EvidenceStatus_INFERRED, Confidence: .46, IsUnknown: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Value != "UNKNOWN" || result.Status != commonv1.EvidenceStatus_UNKNOWN || result.Confidence != .46 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestSecurityFindingCannotCreatePrimaryFact(t *testing.T) {
	result, err := New().Fuse("ike.version", []Evidence{{
		ID: "finding", Property: "ike.version", Value: "IKEv1", Source: SourceSecurityRule,
		Status: commonv1.EvidenceStatus_OBSERVED, Confidence: 1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Value != "UNKNOWN" {
		t.Fatalf("security finding created a fact: %+v", result)
	}
	attached := AttachFindingRefs(result, "finding-1")
	if len(attached.FindingRefs) != 1 || attached.Value != "UNKNOWN" {
		t.Fatalf("post-fusion attachment changed conclusion: %+v", attached)
	}
}
