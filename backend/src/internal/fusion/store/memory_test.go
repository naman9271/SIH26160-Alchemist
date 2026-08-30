package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestStoreRejectsStaleCorrelationSnapshot(t *testing.T) {
	memory, run := seededRun(t)
	correlationID, _ := model.NewCorrelationID()
	missingEvidenceID, _ := model.NewEvidenceID()
	_, err := memory.ReplaceCorrelations(context.Background(), run.ID, []model.CorrelationGroup{{
		ID: correlationID, ResourceType: "IKE_SA", ResourceID: "ike-1", EvidenceIDs: []string{missingEvidenceID},
	}})
	assertKind(t, err, model.ErrorFailedPrecondition)
}

func TestRemoveInvalidatesAffectedCorrelation(t *testing.T) {
	memory, run := seededRun(t)
	item := firstEvidence(run)
	correlationID, _ := model.NewCorrelationID()
	if _, err := memory.ReplaceCorrelations(context.Background(), run.ID, []model.CorrelationGroup{{
		ID: correlationID, ResourceType: "IKE_SA", ResourceID: "ike-1", EvidenceIDs: []string{item.ID},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := memory.RemoveEvidence(context.Background(), run.ID, item.ID); err != nil {
		t.Fatal(err)
	}
	updated, _ := memory.Get(context.Background(), run.ID)
	if len(updated.Correlations) != 0 {
		t.Fatalf("stale correlation survived removal: %+v", updated.Correlations)
	}
}

func seededRun(t *testing.T) (*Memory, model.Run) {
	t.Helper()
	memory := NewMemory()
	analysisID, _ := uuid.NewV7()
	runID, _ := model.NewFusionRunID()
	now := time.Now().UTC()
	run, err := memory.Create(context.Background(), model.Run{
		ID: runID, AnalysisID: analysisID.String(), State: model.RunStateActive,
		SourceCoverage: make(map[model.Source]model.SourceCoverage), EvidenceByID: make(map[string]model.EvidenceItem),
		EvidenceByProperty: make(map[string][]string), EvidenceByResource: make(map[string][]string), Correlations: make(map[string]model.CorrelationGroup),
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	evidenceID, _ := model.NewEvidenceID()
	item := model.EvidenceItem{
		ID: evidenceID, AnalysisID: analysisID.String(), PropertyKey: "ike.version", Value: structpb.NewStringValue("IKEv2"),
		Source: model.SourcePacketParser, Status: commonv1.EvidenceStatus_OBSERVED, Confidence: 1,
		ObservedAt: now, ResourceType: "IKE_SA", ResourceID: "ike-1", SchemaVersion: model.EvidenceSchemaVersion,
	}
	run, err = memory.AddEvidence(context.Background(), run.ID, []model.EvidenceItem{item})
	if err != nil {
		t.Fatal(err)
	}
	return memory, run
}

func firstEvidence(run model.Run) model.EvidenceItem {
	for _, item := range run.EvidenceByID {
		return item
	}
	return model.EvidenceItem{}
}

func assertKind(t *testing.T, err error, kind model.ErrorKind) {
	t.Helper()
	var fusionErr *model.Error
	if !errors.As(err, &fusionErr) || fusionErr.Kind != kind {
		t.Fatalf("error = %v, want %s", err, kind)
	}
}
