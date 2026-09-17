package security_test

import (
	"context"
	"testing"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	corerisk "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/risk"
	coresecurity "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/security"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"google.golang.org/protobuf/types/known/structpb"
)

type conclusionFixture []model.FusedConclusion

func (f conclusionFixture) FusedConclusions(context.Context, string) ([]model.FusedConclusion, error) {
	return f, nil
}

func TestAssessmentAndRiskReuseDeterministicRules(t *testing.T) {
	service := coresecurity.New(conclusionFixture{
		{ID: "c1", PropertyKey: "ike.version", Value: structpb.NewStringValue("IKEv1"), Status: commonv1.EvidenceStatus_OBSERVED, Confidence: .9},
		{ID: "c2", PropertyKey: "child.encryption_algorithm", Value: structpb.NewStringValue("3DES"), Status: commonv1.EvidenceStatus_VERIFIED_GATEWAY, Confidence: 1},
		{ID: "c3", PropertyKey: "metadata.exposure", Value: structpb.NewStringValue("observed"), Status: commonv1.EvidenceStatus_DERIVED, Confidence: .8},
	})
	record, err := service.Run(context.Background(), "analysis", "policy")
	if err != nil || record.Result.Score >= 100 || len(record.Result.Findings) < 2 {
		t.Fatalf("record=%+v err=%v", record, err)
	}
	recommendations, err := service.Recommendations(context.Background(), record.ID)
	if err != nil || len(recommendations) == 0 {
		t.Fatalf("recommendations=%+v err=%v", recommendations, err)
	}
	risk := corerisk.New(service)
	score, err := risk.Score(context.Background(), record.ID)
	if err != nil || score.Score != uint32(record.Result.Score) || score.UnknownEvidenceCount == 0 {
		t.Fatalf("score=%+v err=%v", score, err)
	}
	breakdown, err := risk.Breakdown(context.Background(), record.ID)
	if err != nil || breakdown.Cryptography.Score >= breakdown.Cryptography.Maximum {
		t.Fatalf("breakdown=%+v err=%v", breakdown, err)
	}
}

func TestIKECipherNeverSubstitutesForChildCipher(t *testing.T) {
	service := coresecurity.New(conclusionFixture{
		{ID: "c1", PropertyKey: "ike.version", Value: structpb.NewStringValue("IKEv2.0"), Status: commonv1.EvidenceStatus_OBSERVED, Confidence: .95},
		{ID: "c2", PropertyKey: "ike.encryption", Value: structpb.NewStringValue("ENCR_20"), Status: commonv1.EvidenceStatus_OBSERVED, Confidence: .95},
		{ID: "c3", PropertyKey: "ike.dh_group", Value: structpb.NewStringValue("DH_19"), Status: commonv1.EvidenceStatus_OBSERVED, Confidence: .95},
	})

	record, err := service.Run(context.Background(), "analysis-aead", "policy")
	if err != nil {
		t.Fatal(err)
	}
	if record.UnknownEvidence != 7 {
		t.Fatalf("unknown evidence = %d, want 7 (only IKE version evaluated)", record.UnknownEvidence)
	}
	if record.Result.Score != 100 || len(record.Result.Findings) != 0 {
		t.Fatalf("assessment = %+v, want clean supported checks", record.Result)
	}

	risk := corerisk.New(service)
	score, err := risk.Score(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if score.UnknownEvidenceCount != 7 || score.Confidence != .12 || score.RiskLevel != "INDETERMINATE" {
		t.Fatalf("risk score = %+v, want explicit low coverage and indeterminate risk", score)
	}
}
