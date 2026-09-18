package engine_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/confidence"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/conflict"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/correlation"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/engine"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/ingest"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/session"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/store"
	"google.golang.org/protobuf/types/known/structpb"
)

type fixture struct {
	service    *engine.Service
	confidence *confidence.Service
	ingest     *ingest.Service
	runID      string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	memory := store.NewMemory()
	policies := policy.NewMemory(policy.Definition{
		ID: "test-policy", SchemaVersion: policy.SchemaVersion,
		RequiredSources:    []model.Source{model.SourcePacketParser, model.SourceFlowAnalyzer},
		RequiredProperties: []string{"child.mode", "traffic.class"},
		SourceTrust:        map[model.Source]float64{model.SourcePacketParser: .95, model.SourceVICI: 1, model.SourceMLClassifier: .75},
		FreshnessWindow:    24 * time.Hour,
		PropertyRules: map[string]policy.PropertyRule{
			"child.*":       {SourcePrecedence: []model.Source{model.SourceVICI, model.SourceXFRM, model.SourcePacketParser}},
			"traffic.class": {SourcePrecedence: []model.Source{model.SourceMLClassifier}},
		},
	})
	sessions := session.New(memory, policies)
	analysisID, _ := uuid.NewV7()
	run, err := sessions.Create(context.Background(), session.CreateRequest{AnalysisID: analysisID.String(), PolicyID: "test-policy"})
	if err != nil {
		t.Fatal(err)
	}
	correlator := correlation.New(memory)
	conflicts := conflict.New(memory, policies)
	calculator := confidence.New(memory, policies)
	service := engine.New(memory, correlator, conflicts, calculator, policies, nil)
	return fixture{service: service, confidence: calculator, ingest: ingest.New(memory, nil), runID: run.ID}
}

func evidence(property, value, resourceType, resourceID string, source model.Source, status commonv1.EvidenceStatus, confidence float64, metadata map[string]string) ingest.EvidenceInput {
	return ingest.EvidenceInput{
		PropertyKey: property, Value: structpb.NewStringValue(value), Source: source, Status: status,
		Confidence: confidence, ObservedAt: time.Now().UTC().Add(-time.Minute),
		ResourceType: resourceType, ResourceID: resourceID, Metadata: metadata,
	}
}

func seed(t *testing.T, fixture fixture) {
	t.Helper()
	batch, err := fixture.ingest.AddBatch(context.Background(), ingest.AddBatchRequest{FusionRunID: fixture.runID, Evidence: []ingest.EvidenceInput{
		evidence("child.mode", "TUNNEL", "CHILD_SA", "passive-child", model.SourcePacketParser, commonv1.EvidenceStatus_DERIVED, .72, map[string]string{"reqid": "42", "endpoint_pair": "192.0.2.1<>198.51.100.1", "esp_directional_wire": "esp|198.51.100.1|0x00000001"}),
		evidence("child.mode", "TRANSPORT", "VICI_CHILD_SA", "vici-child", model.SourceVICI, commonv1.EvidenceStatus_VERIFIED_GATEWAY, 1, map[string]string{"reqid": "42", "endpoint_pair": "192.0.2.1<>198.51.100.1", "esp_directional_wire_in": "esp|198.51.100.1|0x00000001"}),
		evidence("traffic.class", "VIDEO", "FLOW", "flow-1", model.SourceMLClassifier, commonv1.EvidenceStatus_INFERRED, .46, map[string]string{"endpoint_tuple": "a-b"}),
	}})
	if err != nil || batch.AcceptedCount != 3 {
		t.Fatalf("seed = %+v, %v", batch, err)
	}
}

func TestRunStatusSummaryAndConclusions(t *testing.T) {
	fixture := newFixture(t)
	seed(t, fixture)
	response, err := fixture.service.Run(context.Background(), engine.RunRequest{FusionRunID: fixture.runID, Incremental: true})
	if err != nil || response.State != model.FusionComplete || response.ConclusionsUpdated != 2 || response.ConflictsDetected != 1 {
		t.Fatalf("Run() = %+v, %v", response, err)
	}
	status, err := fixture.service.GetStatus(context.Background(), fixture.runID)
	if err != nil || status.Execution.State != model.FusionComplete || status.Counts.Evidence != 3 || status.Counts.Conclusions != 2 || status.Counts.Conflicts != 1 {
		t.Fatalf("GetStatus() = %+v, %v", status, err)
	}
	summary, err := fixture.service.GetSummary(context.Background(), fixture.runID)
	if err != nil || summary.State != model.FusionComplete || summary.UnresolvedConflicts != 0 || summary.SourceCoverage["passive"] {
		t.Fatalf("GetSummary() = %+v, %v", summary, err)
	}
	listed, err := fixture.service.ListConclusions(context.Background(), engine.ListConclusionsRequest{FusionRunID: fixture.runID, PageSize: 1})
	if err != nil || len(listed.Conclusions) != 1 || listed.NextPageToken == "" {
		t.Fatalf("ListConclusions() = %+v, %v", listed, err)
	}
	second, err := fixture.service.ListConclusions(context.Background(), engine.ListConclusionsRequest{FusionRunID: fixture.runID, PageSize: 1, PageToken: listed.NextPageToken})
	if err != nil || len(second.Conclusions) != 1 || second.NextPageToken != "" {
		t.Fatalf("ListConclusions(second) = %+v, %v", second, err)
	}
	all := append(listed.Conclusions, second.Conclusions...)
	var child, traffic model.FusedConclusion
	for _, conclusion := range all {
		switch conclusion.PropertyKey {
		case "child.mode":
			child = conclusion
		case "traffic.class":
			traffic = conclusion
		}
	}
	if child.Value.GetStringValue() != "TRANSPORT" || child.Status != commonv1.EvidenceStatus_VERIFIED_GATEWAY || !child.HasConflict || child.RationaleCode != "VERIFIED_OVERRIDES_DERIVED" || len(child.WinningSources) != 1 || child.WinningSources[0] != model.SourceVICI {
		t.Fatalf("incorrect child conclusion: %+v", child)
	}
	if traffic.Confidence > .46 || traffic.Status != commonv1.EvidenceStatus_INFERRED {
		t.Fatalf("ML confidence was transformed incorrectly: %+v", traffic)
	}
	parsed, err := uuid.Parse(child.ID)
	if err != nil || parsed.Version() != 7 {
		t.Fatalf("conclusion ID is not UUIDv7: %q, %v", child.ID, err)
	}
	got, err := fixture.service.GetConclusion(context.Background(), engine.GetConclusionRequest{FusionRunID: fixture.runID, ConclusionID: child.ID})
	if err != nil || got.ID != child.ID {
		t.Fatalf("GetConclusion() = %+v, %v", got, err)
	}
	breakdown, err := fixture.confidence.GetBreakdown(context.Background(), confidence.GetBreakdownRequest{FusionRunID: fixture.runID, ConclusionID: child.ID})
	if err != nil || breakdown.FinalConfidence != child.Confidence {
		t.Fatalf("GetBreakdown() = %+v, %v", breakdown, err)
	}
}

func TestRecomputeOnlyAffectedCorrelationProperties(t *testing.T) {
	fixture := newFixture(t)
	seed(t, fixture)
	if _, err := fixture.service.Run(context.Background(), engine.RunRequest{FusionRunID: fixture.runID}); err != nil {
		t.Fatal(err)
	}
	before, _ := fixture.service.ListConclusions(context.Background(), engine.ListConclusionsRequest{FusionRunID: fixture.runID})
	beforeByProperty := make(map[string]model.FusedConclusion)
	for _, item := range before.Conclusions {
		beforeByProperty[item.PropertyKey] = item
	}
	if _, err := fixture.ingest.Add(context.Background(), ingest.AddRequest{FusionRunID: fixture.runID, Evidence: evidence("child.integrity", "SHA256", "VICI_CHILD_SA", "vici-child", model.SourceVICI, commonv1.EvidenceStatus_VERIFIED_GATEWAY, 1, map[string]string{"reqid": "42", "endpoint_pair": "192.0.2.1<>198.51.100.1", "esp_directional_wire_in": "esp|198.51.100.1|0x00000001"})}); err != nil {
		t.Fatal(err)
	}
	response, err := fixture.service.Recompute(context.Background(), engine.RecomputeRequest{FusionRunID: fixture.runID, AffectedProperties: []string{"child.integrity"}})
	if err != nil || response.State != model.FusionComplete || response.ConclusionsUpdated != 2 || len(response.AffectedProperties) != 2 {
		t.Fatalf("Recompute() = %+v, %v", response, err)
	}
	after, _ := fixture.service.ListConclusions(context.Background(), engine.ListConclusionsRequest{FusionRunID: fixture.runID})
	afterByProperty := make(map[string]model.FusedConclusion)
	for _, item := range after.Conclusions {
		afterByProperty[item.PropertyKey] = item
	}
	if afterByProperty["traffic.class"].ID != beforeByProperty["traffic.class"].ID || !afterByProperty["traffic.class"].ComputedAt.Equal(beforeByProperty["traffic.class"].ComputedAt) {
		t.Fatal("unaffected traffic conclusion was recomputed")
	}
	if afterByProperty["child.mode"].ID != beforeByProperty["child.mode"].ID || afterByProperty["child.integrity"].ID == "" {
		t.Fatalf("affected conclusions were not updated correctly: %+v", afterByProperty)
	}
}

func TestCompletenessAndCoverage(t *testing.T) {
	fixture := newFixture(t)
	seed(t, fixture)
	if _, err := fixture.service.Run(context.Background(), engine.RunRequest{FusionRunID: fixture.runID}); err != nil {
		t.Fatal(err)
	}
	initial, err := fixture.service.GetCompleteness(context.Background(), fixture.runID)
	if err != nil || initial.Overall != 1 || initial.RequiredProperties != 2 || initial.ResolvedProperties != 2 || len(initial.MissingSources) != 2 {
		t.Fatalf("GetCompleteness(initial) = %+v, %v", initial, err)
	}
	if _, err := fixture.ingest.MarkSourceComplete(context.Background(), ingest.MarkSourceRequest{FusionRunID: fixture.runID, Source: model.SourcePacketParser}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.ingest.MarkSourceComplete(context.Background(), ingest.MarkSourceRequest{FusionRunID: fixture.runID, Source: model.SourceFlowAnalyzer}); err != nil {
		t.Fatal(err)
	}
	complete, err := fixture.service.GetCompleteness(context.Background(), fixture.runID)
	if err != nil || len(complete.MissingSources) != 0 {
		t.Fatalf("GetCompleteness(complete) = %+v, %v", complete, err)
	}
	summary, _ := fixture.service.GetSummary(context.Background(), fixture.runID)
	if !summary.SourceCoverage["passive"] {
		t.Fatalf("passive coverage remained false: %+v", summary.SourceCoverage)
	}
}

func TestConclusionFiltersAndValidation(t *testing.T) {
	fixture := newFixture(t)
	seed(t, fixture)
	if _, err := fixture.service.Run(context.Background(), engine.RunRequest{FusionRunID: fixture.runID}); err != nil {
		t.Fatal(err)
	}
	hasConflict := true
	filtered, err := fixture.service.ListConclusions(context.Background(), engine.ListConclusionsRequest{FusionRunID: fixture.runID, Filter: engine.ConclusionFilter{PropertyPrefix: "child.", HasConflict: &hasConflict, Status: commonv1.EvidenceStatus_VERIFIED_GATEWAY}})
	if err != nil || len(filtered.Conclusions) != 1 {
		t.Fatalf("filtered conclusions = %+v, %v", filtered, err)
	}
	_, err = fixture.service.Recompute(context.Background(), engine.RecomputeRequest{FusionRunID: fixture.runID})
	assertKind(t, err, model.ErrorInvalidArgument)
	unknown, _ := uuid.NewV7()
	_, err = fixture.service.GetConclusion(context.Background(), engine.GetConclusionRequest{FusionRunID: fixture.runID, ConclusionID: unknown.String()})
	assertKind(t, err, model.ErrorNotFound)
}

func TestConcurrentRecomputeIsSerializedWithoutDuplicateConclusions(t *testing.T) {
	fixture := newFixture(t)
	seed(t, fixture)
	if _, err := fixture.service.Run(context.Background(), engine.RunRequest{FusionRunID: fixture.runID}); err != nil {
		t.Fatal(err)
	}

	const callers = 8
	errorsByCaller := make(chan error, callers)
	var group sync.WaitGroup
	for range callers {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := fixture.service.Recompute(context.Background(), engine.RecomputeRequest{
				FusionRunID: fixture.runID, AffectedProperties: []string{"child.mode"},
			})
			errorsByCaller <- err
		}()
	}
	group.Wait()
	close(errorsByCaller)
	for err := range errorsByCaller {
		if err != nil {
			t.Fatalf("concurrent Recompute() failed: %v", err)
		}
	}

	conclusions, err := fixture.service.ListConclusions(context.Background(), engine.ListConclusionsRequest{FusionRunID: fixture.runID})
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]struct{}, len(conclusions.Conclusions))
	for _, conclusion := range conclusions.Conclusions {
		key := store.ConclusionKey(conclusion.PropertyKey, conclusion.ResourceType, conclusion.ResourceID)
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate conclusion key after concurrent recomputation: %q", key)
		}
		seen[key] = struct{}{}
	}
	status, err := fixture.service.GetStatus(context.Background(), fixture.runID)
	if err != nil || status.Execution.State != model.FusionComplete {
		t.Fatalf("GetStatus() = %+v, %v", status, err)
	}
}

func assertKind(t *testing.T, err error, kind model.ErrorKind) {
	t.Helper()
	var fusionErr *model.Error
	if !errors.As(err, &fusionErr) || fusionErr.Kind != kind {
		t.Fatalf("error = %v, want %s", err, kind)
	}
}
