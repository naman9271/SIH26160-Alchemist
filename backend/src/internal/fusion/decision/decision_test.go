package decision

import (
	"context"
	"testing"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
	"google.golang.org/protobuf/types/known/structpb"
)

func evidence(t *testing.T, value string, source model.Source, status commonv1.EvidenceStatus, property string) model.EvidenceItem {
	t.Helper()
	id, _ := model.NewEvidenceID()
	return model.EvidenceItem{ID: id, PropertyKey: property, Value: structpb.NewStringValue(value), Source: source, Status: status, Confidence: 1, ObservedAt: time.Now().UTC()}
}

func TestVerifiedEvidenceOverridesDerived(t *testing.T) {
	definition, _ := policy.NewDefault().Resolve(context.Background(), model.DefaultPolicyID)
	passive := evidence(t, "TUNNEL", model.SourcePacketParser, commonv1.EvidenceStatus_DERIVED, "child.mode")
	vici := evidence(t, "TRANSPORT", model.SourceVICI, commonv1.EvidenceStatus_VERIFIED_GATEWAY, "child.mode")
	result, err := Select("child.mode", []model.EvidenceItem{passive, vici}, definition)
	if err != nil || result.Winner.ID != vici.ID || result.Rationale != "VERIFIED_OVERRIDES_DERIVED" {
		t.Fatalf("Select() = %+v, %v", result, err)
	}
}

func TestUnknownHighPrecedenceSourceDoesNotOverrideObserved(t *testing.T) {
	definition, _ := policy.NewDefault().Resolve(context.Background(), model.DefaultPolicyID)
	observed := evidence(t, "IKEv2", model.SourcePacketParser, commonv1.EvidenceStatus_OBSERVED, "ike.version")
	unknown := evidence(t, "UNKNOWN", model.SourceVICI, commonv1.EvidenceStatus_UNKNOWN, "ike.version")
	result, err := Select("ike.version", []model.EvidenceItem{unknown, observed}, definition)
	if err != nil || result.Winner.ID != observed.ID {
		t.Fatalf("UNKNOWN overrode observed fact: %+v, %v", result, err)
	}
}

func TestSecurityReferenceCannotCreateProtocolDecision(t *testing.T) {
	definition, _ := policy.NewDefault().Resolve(context.Background(), model.DefaultPolicyID)
	finding := evidence(t, "IKEv1", model.SourceSecurityRule, commonv1.EvidenceStatus_DERIVED, "ike.version")
	if _, err := Select("ike.version", []model.EvidenceItem{finding}, definition); err == nil {
		t.Fatal("security reference created a primary protocol fact")
	}
}
