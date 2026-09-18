package conflict_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/conflict"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/correlation"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/ingest"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/session"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/store"
	"google.golang.org/protobuf/types/known/structpb"
)

type fixture struct {
	service    *conflict.Service
	correlator *correlation.Service
	ingest     *ingest.Service
	runID      string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	memory := store.NewMemory()
	policies := policy.NewDefault()
	sessions := session.New(memory, policies)
	analysisID, _ := uuid.NewV7()
	run, err := sessions.Create(context.Background(), session.CreateRequest{AnalysisID: analysisID.String(), PolicyID: model.DefaultPolicyID})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{service: conflict.New(memory, policies), correlator: correlation.New(memory), ingest: ingest.New(memory, nil), runID: run.ID}
}

func evidence(value string, source model.Source, status commonv1.EvidenceStatus, confidence float64) ingest.EvidenceInput {
	return ingest.EvidenceInput{
		PropertyKey: "child.mode", Value: structpb.NewStringValue(value), Source: source, Status: status,
		Confidence: confidence, ObservedAt: time.Now().UTC().Add(-time.Minute), ResourceType: "CHILD_SA",
		ResourceID: string(source), Metadata: map[string]string{
			"reqid":                "42",
			"esp_directional_wire": "esp|198.51.100.1|0x0000002a",
		},
	}
}

func seedConflict(t *testing.T, fixture fixture) {
	t.Helper()
	batch, err := fixture.ingest.AddBatch(context.Background(), ingest.AddBatchRequest{FusionRunID: fixture.runID, Evidence: []ingest.EvidenceInput{
		evidence("TUNNEL", model.SourcePacketParser, commonv1.EvidenceStatus_DERIVED, .72),
		evidence("TRANSPORT", model.SourceVICI, commonv1.EvidenceStatus_VERIFIED_GATEWAY, 1),
	}})
	if err != nil || batch.AcceptedCount != 2 {
		t.Fatalf("seed = %+v, %v", batch, err)
	}
	if _, err = fixture.correlator.Correlate(context.Background(), correlation.CorrelateRequest{FusionRunID: fixture.runID}); err != nil {
		t.Fatal(err)
	}
}

func TestDetectListGetAndResolve(t *testing.T) {
	fixture := newFixture(t)
	seedConflict(t, fixture)
	detected, err := fixture.service.Detect(context.Background(), conflict.DetectRequest{FusionRunID: fixture.runID})
	if err != nil || detected.ConflictsFound != 1 {
		t.Fatalf("Detect() = %+v, %v", detected, err)
	}
	listed, err := fixture.service.List(context.Background(), conflict.ListRequest{FusionRunID: fixture.runID, State: model.ConflictOpen})
	if err != nil || len(listed.Conflicts) != 1 {
		t.Fatalf("List() = %+v, %v", listed, err)
	}
	conflictID := listed.Conflicts[0].ID
	parsed, err := uuid.Parse(conflictID)
	if err != nil || parsed.Version() != 7 {
		t.Fatalf("conflict ID is not UUIDv7: %q, %v", conflictID, err)
	}
	detail, err := fixture.service.Get(context.Background(), conflict.GetRequest{FusionRunID: fixture.runID, ConflictID: conflictID})
	if err != nil || len(detail.Candidates) != 2 || detail.Conflict.PropertyKey != "child.mode" || detail.Candidates[0].Age < 0 {
		t.Fatalf("Get() = %+v, %v", detail, err)
	}
	resolved, err := fixture.service.Resolve(context.Background(), conflict.ResolveRequest{FusionRunID: fixture.runID, ConflictID: conflictID, Mode: model.ResolutionPolicy})
	if err != nil || resolved.WinningEvidence.Source != model.SourceVICI || resolved.WinningEvidence.Value.GetStringValue() != "TRANSPORT" || resolved.RationaleCode != "VERIFIED_OVERRIDES_DERIVED" || resolved.Conflict.State != model.ConflictResolved {
		t.Fatalf("Resolve() = %+v, %v", resolved, err)
	}
	again, err := fixture.service.Resolve(context.Background(), conflict.ResolveRequest{FusionRunID: fixture.runID, ConflictID: conflictID, Mode: model.ResolutionPolicy})
	if err != nil || again.Conflict.WinningEvidenceID != resolved.Conflict.WinningEvidenceID || again.Conflict.ResolvedAt != resolved.Conflict.ResolvedAt {
		t.Fatalf("idempotent Resolve() = %+v, %v", again, err)
	}
}

func TestReevaluateOpensChangedConflict(t *testing.T) {
	fixture := newFixture(t)
	seedConflict(t, fixture)
	if _, err := fixture.service.Detect(context.Background(), conflict.DetectRequest{FusionRunID: fixture.runID}); err != nil {
		t.Fatal(err)
	}
	listed, _ := fixture.service.List(context.Background(), conflict.ListRequest{FusionRunID: fixture.runID})
	if _, err := fixture.service.Resolve(context.Background(), conflict.ResolveRequest{FusionRunID: fixture.runID, ConflictID: listed.Conflicts[0].ID, Mode: model.ResolutionPolicy}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.ingest.Add(context.Background(), ingest.AddRequest{FusionRunID: fixture.runID, Evidence: evidence("TRANSPORT", model.SourceXFRM, commonv1.EvidenceStatus_VERIFIED_GATEWAY, 1)}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.correlator.Rebuild(context.Background(), fixture.runID); err != nil {
		t.Fatal(err)
	}
	response, err := fixture.service.Reevaluate(context.Background(), conflict.DetectRequest{FusionRunID: fixture.runID, AffectedProperties: []string{"child.mode"}})
	if err != nil || response.ConflictsFound != 1 {
		t.Fatalf("Reevaluate() = %+v, %v", response, err)
	}
	listed, _ = fixture.service.List(context.Background(), conflict.ListRequest{FusionRunID: fixture.runID})
	if listed.Conflicts[0].State != model.ConflictOpen || listed.Conflicts[0].WinningEvidenceID != "" {
		t.Fatalf("changed conflict was not reopened: %+v", listed.Conflicts[0])
	}
}

func TestManualResolutionAndUnknownConflictErrors(t *testing.T) {
	fixture := newFixture(t)
	seedConflict(t, fixture)
	if _, err := fixture.service.Detect(context.Background(), conflict.DetectRequest{FusionRunID: fixture.runID}); err != nil {
		t.Fatal(err)
	}
	listed, _ := fixture.service.List(context.Background(), conflict.ListRequest{FusionRunID: fixture.runID})
	_, err := fixture.service.Resolve(context.Background(), conflict.ResolveRequest{FusionRunID: fixture.runID, ConflictID: listed.Conflicts[0].ID, Mode: model.ResolutionManualOperator})
	assertKind(t, err, model.ErrorFailedPrecondition)
	unknown, _ := uuid.NewV7()
	_, err = fixture.service.Get(context.Background(), conflict.GetRequest{FusionRunID: fixture.runID, ConflictID: unknown.String()})
	assertKind(t, err, model.ErrorNotFound)
}

func TestAgreementDoesNotCreateConflict(t *testing.T) {
	fixture := newFixture(t)
	batch, err := fixture.ingest.AddBatch(context.Background(), ingest.AddBatchRequest{FusionRunID: fixture.runID, Evidence: []ingest.EvidenceInput{
		evidence("TUNNEL", model.SourcePacketParser, commonv1.EvidenceStatus_OBSERVED, 1),
		evidence("TUNNEL", model.SourceVICI, commonv1.EvidenceStatus_VERIFIED_GATEWAY, 1),
	}})
	if err != nil || batch.AcceptedCount != 2 {
		t.Fatal(err)
	}
	_, _ = fixture.correlator.Correlate(context.Background(), correlation.CorrelateRequest{FusionRunID: fixture.runID})
	detected, err := fixture.service.Detect(context.Background(), conflict.DetectRequest{FusionRunID: fixture.runID})
	if err != nil || detected.ConflictsFound != 0 {
		t.Fatalf("agreement created conflict: %+v, %v", detected, err)
	}
}

func assertKind(t *testing.T, err error, kind model.ErrorKind) {
	t.Helper()
	var fusionErr *model.Error
	if !errors.As(err, &fusionErr) || fusionErr.Kind != kind {
		t.Fatalf("error = %v, want %s", err, kind)
	}
}
