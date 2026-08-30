package confidence_test

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/confidence"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/session"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/store"
	"google.golang.org/protobuf/types/known/structpb"
)

func item(t *testing.T, value string, source model.Source, status commonv1.EvidenceStatus, probability float64) model.EvidenceItem {
	t.Helper()
	id, _ := model.NewEvidenceID()
	return model.EvidenceItem{
		ID: id, PropertyKey: "child.mode", Value: structpb.NewStringValue(value), Source: source,
		Status: status, Confidence: probability, ObservedAt: time.Now().UTC().Add(-time.Minute),
		ResourceType: "CHILD_SA", ResourceID: "child-1",
	}
}

func TestCalculateVerifiedAgreement(t *testing.T) {
	service := confidence.New(nil, policy.NewDefault())
	winner := item(t, "TRANSPORT", model.SourceVICI, commonv1.EvidenceStatus_VERIFIED_GATEWAY, 1)
	support := item(t, "TRANSPORT", model.SourceXFRM, commonv1.EvidenceStatus_VERIFIED_GATEWAY, 1)
	quality := .96
	result, err := service.Calculate(context.Background(), confidence.CalculateRequest{
		PolicyID: model.DefaultPolicyID, PropertyKey: "child.mode", Candidates: []model.EvidenceItem{winner, support},
		WinningEvidenceID: winner.ID, CorrelationQuality: &quality,
	})
	if err != nil || result.Confidence < .95 || result.Band != model.ConfidenceVeryHigh || result.Breakdown.Agreement != 1 || result.Breakdown.ModelConfidence != nil {
		t.Fatalf("Calculate() = %+v, %v", result, err)
	}
}

func TestCalculateConflictReducesAgreement(t *testing.T) {
	service := confidence.New(nil, policy.NewDefault())
	winner := item(t, "TRANSPORT", model.SourceVICI, commonv1.EvidenceStatus_VERIFIED_GATEWAY, 1)
	conflicting := item(t, "TUNNEL", model.SourcePacketParser, commonv1.EvidenceStatus_DERIVED, .72)
	result, err := service.Calculate(context.Background(), confidence.CalculateRequest{
		PolicyID: model.DefaultPolicyID, PropertyKey: "child.mode", Candidates: []model.EvidenceItem{winner, conflicting}, WinningEvidenceID: winner.ID,
	})
	if err != nil || result.Breakdown.Agreement != .5 || result.Confidence >= 1 {
		t.Fatalf("Calculate(conflict) = %+v, %v", result, err)
	}
}

func TestCalibrateMLPreservesWorkerProbability(t *testing.T) {
	service := confidence.New(nil, policy.NewDefault())
	result, err := service.CalibrateML(context.Background(), confidence.CalibrateMLRequest{Probability: .46, ModelName: "xgboost", ModelVersion: "1.2.0"})
	if err != nil || result.Confidence != .46 || result.Band != model.ConfidenceLow || result.Status != commonv1.EvidenceStatus_INFERRED {
		t.Fatalf("CalibrateML() = %+v, %v", result, err)
	}
	unknown, err := service.CalibrateML(context.Background(), confidence.CalibrateMLRequest{Probability: .46, ModelName: "xgboost", ModelVersion: "1.2.0", IsUnknown: true})
	if err != nil || unknown.Status != commonv1.EvidenceStatus_UNKNOWN || unknown.Confidence != .46 {
		t.Fatalf("CalibrateML(unknown) = %+v, %v", unknown, err)
	}
}

func TestCalculateMLNeverBoostsProbability(t *testing.T) {
	service := confidence.New(nil, policy.NewDefault())
	winner := item(t, "VIDEO", model.SourceMLClassifier, commonv1.EvidenceStatus_INFERRED, .46)
	result, err := service.Calculate(context.Background(), confidence.CalculateRequest{
		PolicyID: model.DefaultPolicyID, PropertyKey: "traffic.class", Candidates: []model.EvidenceItem{winner}, WinningEvidenceID: winner.ID,
	})
	if err != nil || result.Confidence > .46 || result.Breakdown.ModelConfidence == nil || *result.Breakdown.ModelConfidence != .46 {
		t.Fatalf("ML confidence was boosted: %+v, %v", result, err)
	}
}

func TestGetBreakdown(t *testing.T) {
	memory := store.NewMemory()
	policies := policy.NewDefault()
	sessions := session.New(memory, policies)
	analysisID, _ := uuid.NewV7()
	run, err := sessions.Create(context.Background(), session.CreateRequest{AnalysisID: analysisID.String(), PolicyID: model.DefaultPolicyID})
	if err != nil {
		t.Fatal(err)
	}
	conclusionID, _ := model.NewConclusionID()
	breakdown := model.ConfidenceBreakdown{SourceTrust: 1, FinalConfidence: .98, Band: model.ConfidenceVeryHigh}
	_, err = memory.ApplyConclusions(context.Background(), run.ID, []model.FusedConclusion{{
		ID: conclusionID, AnalysisID: run.AnalysisID, PropertyKey: "ike.version", ResourceType: "IKE_SA", ResourceID: "ike-1", Breakdown: breakdown,
	}}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	service := confidence.New(memory, policies)
	result, err := service.GetBreakdown(context.Background(), confidence.GetBreakdownRequest{FusionRunID: run.ID, ConclusionID: conclusionID})
	if err != nil || result.FinalConfidence != .98 || result.Band != model.ConfidenceVeryHigh {
		t.Fatalf("GetBreakdown() = %+v, %v", result, err)
	}
}

func TestConfidenceValidation(t *testing.T) {
	service := confidence.New(nil, policy.NewDefault())
	_, err := service.CalibrateML(context.Background(), confidence.CalibrateMLRequest{Probability: math.NaN(), ModelName: "m", ModelVersion: "v"})
	assertKind(t, err, model.ErrorInvalidArgument)
	_, err = service.Calculate(context.Background(), confidence.CalculateRequest{PolicyID: model.DefaultPolicyID})
	assertKind(t, err, model.ErrorInvalidArgument)
}

func assertKind(t *testing.T, err error, kind model.ErrorKind) {
	t.Helper()
	var fusionErr *model.Error
	if !errors.As(err, &fusionErr) || fusionErr.Kind != kind {
		t.Fatalf("error = %v, want %s", err, kind)
	}
}
