package security_test

import (
	"context"
	"testing"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	corerisk "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/risk"
	coresecurity "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/security"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"google.golang.org/protobuf/types/known/structpb"
)

type evidenceFixture []model.EvidenceItem

func (f evidenceFixture) EvidenceItems(context.Context, string) ([]model.EvidenceItem, error) {
	return f, nil
}

func TestAssessmentAndRiskReuseDeterministicRules(t *testing.T) {
	now := time.Now().UTC()
	service := coresecurity.New(evidenceFixture{
		{PropertyKey: "ike.version", Value: structpb.NewStringValue("IKEv1"), Status: commonv1.EvidenceStatus_OBSERVED, ObservedAt: now},
		{PropertyKey: "child.encryption_algorithm", Value: structpb.NewStringValue("3DES"), Status: commonv1.EvidenceStatus_VERIFIED_GATEWAY, ObservedAt: now},
		{PropertyKey: "metadata.exposure", Value: structpb.NewStringValue("observed"), Status: commonv1.EvidenceStatus_DERIVED, ObservedAt: now},
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
