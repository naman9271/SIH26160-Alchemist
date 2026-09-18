package provenance_test

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	rootfusion "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/engine"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/event"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/ingest"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/provenance"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/session"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestEvidenceChainExplanationContributionAndTimeline(t *testing.T) {
	runtime := rootfusion.NewRuntime(rootfusion.RuntimeOptions{})
	analysisID, _ := uuid.NewV7()
	run, err := runtime.Sessions.Create(context.Background(), session.CreateRequest{AnalysisID: analysisID.String(), PolicyID: model.DefaultPolicyID})
	if err != nil {
		t.Fatal(err)
	}
	streamCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	subscription, err := runtime.Events.Subscribe(streamCtx, event.SubscribeRequest{FusionRunID: run.ID})
	if err != nil {
		t.Fatal(err)
	}

	observedAt := time.Now().UTC().Add(-time.Minute)
	passive, err := runtime.Ingest.Add(context.Background(), ingest.AddRequest{FusionRunID: run.ID, Evidence: ingest.EvidenceInput{
		PropertyKey: "child.mode", Value: structpb.NewStringValue("TUNNEL"), Source: model.SourcePacketParser,
		Status: commonv1.EvidenceStatus_DERIVED, Confidence: .72, ObservedAt: observedAt,
		ResourceType: "CHILD_SA", ResourceID: "passive-child", SourceReference: "capture:packet-7", Metadata: map[string]string{"reqid": "42", "endpoint_pair": "192.0.2.1<>198.51.100.1", "esp_directional_wire": "esp|198.51.100.1|0x00000001"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := runtime.Ingest.Add(context.Background(), ingest.AddRequest{FusionRunID: run.ID, Evidence: ingest.EvidenceInput{
		PropertyKey: "child.mode", Value: structpb.NewStringValue("TRANSPORT"), Source: model.SourceVICI,
		Status: commonv1.EvidenceStatus_VERIFIED_GATEWAY, Confidence: 1, ObservedAt: observedAt.Add(time.Second),
		ResourceType: "VICI_CHILD_SA", ResourceID: "vici-child", SourceReference: "vici:child-sa-42", Metadata: map[string]string{"reqid": "42", "endpoint_pair": "192.0.2.1<>198.51.100.1", "esp_directional_wire_in": "esp|198.51.100.1|0x00000001"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := runtime.Fusion.ListConclusions(context.Background(), engine.ListConclusionsRequest{FusionRunID: run.ID})
	if err != nil || len(listed.Conclusions) != 1 {
		t.Fatalf("ListConclusions() = %+v, %v", listed, err)
	}
	conclusion := listed.Conclusions[0]
	request := provenance.ConclusionRequest{FusionRunID: run.ID, ConclusionID: conclusion.ID}
	chain, err := runtime.Provenance.GetEvidenceChain(context.Background(), request)
	if err != nil || len(chain.WinningEvidence) != 1 || chain.WinningEvidence[0].ID != verified.EvidenceID || len(chain.ConflictingEvidence) != 1 || chain.ConflictingEvidence[0].ID != passive.EvidenceID || len(chain.SourceReferences) != 2 {
		t.Fatalf("GetEvidenceChain() = %+v, %v", chain, err)
	}
	explanation, err := runtime.Provenance.ExplainDecision(context.Background(), request)
	if err != nil || explanation.RationaleCode != "VERIFIED_OVERRIDES_DERIVED" || len(explanation.WinningEvidenceIDs) != 1 || len(explanation.RejectedEvidenceIDs) != 1 {
		t.Fatalf("ExplainDecision() = %+v, %v", explanation, err)
	}
	contribution, err := runtime.Provenance.GetSourceContribution(context.Background(), request)
	if err != nil || len(contribution.Contributions) != 2 {
		t.Fatalf("GetSourceContribution() = %+v, %v", contribution, err)
	}
	var total float64
	for _, value := range contribution.Contributions {
		total += value
	}
	if math.Abs(total-1) > 1e-9 || contribution.Contributions[model.SourceVICI] <= contribution.Contributions[model.SourcePacketParser] {
		t.Fatalf("contributions are not normalized/descriptive: %+v", contribution.Contributions)
	}
	timeline, err := runtime.Provenance.GetTimeline(context.Background(), request)
	if err != nil || len(timeline.Entries) < 4 {
		t.Fatalf("GetTimeline() = %+v, %v", timeline, err)
	}
	created, updated := false, false
	for _, entry := range timeline.Entries {
		created = created || entry.Type == model.EventConclusionCreated
		updated = updated || entry.Type == model.EventConclusionUpdated
	}
	if !created || !updated {
		t.Fatalf("timeline did not preserve conclusion evolution: %+v", timeline.Entries)
	}
	if _, err = runtime.Ingest.MarkSourceComplete(context.Background(), ingest.MarkSourceRequest{FusionRunID: run.ID, Source: model.SourcePacketParser}); err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.Ingest.MarkSourceComplete(context.Background(), ingest.MarkSourceRequest{FusionRunID: run.ID, Source: model.SourceFlowAnalyzer}); err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.Sessions.Finalize(context.Background(), run.ID); err != nil {
		t.Fatal(err)
	}
	history, err := runtime.Events.History(context.Background(), event.HistoryRequest{FusionRunID: run.ID})
	if err != nil {
		t.Fatal(err)
	}
	seenTypes := make(map[model.EventType]bool)
	for _, item := range history {
		seenTypes[item.Type] = true
	}
	for _, required := range []model.EventType{model.EventFusionRunCreated, model.EventEvidenceAdded, model.EventCorrelationCreated,
		model.EventCorrelationChanged, model.EventConflictDetected, model.EventConflictResolved, model.EventConfidenceUpdated,
		model.EventConclusionCreated, model.EventConclusionUpdated, model.EventFusionCompletenessUpdated, model.EventSourceCompleted, model.EventFusionFinalized} {
		if !seenTypes[required] {
			t.Fatalf("runtime did not publish %s: %+v", required, seenTypes)
		}
	}

	seenCreated := false
	for !seenCreated {
		select {
		case item := <-subscription.Events:
			seenCreated = item.Type == model.EventFusionRunCreated
		case <-time.After(time.Second):
			t.Fatal("runtime event stream did not replay FUSION_RUN_CREATED")
		}
	}
}

func TestProvenanceValidationAndUnknownConclusion(t *testing.T) {
	runtime := rootfusion.NewRuntime(rootfusion.RuntimeOptions{})
	analysisID, _ := uuid.NewV7()
	run, _ := runtime.Sessions.Create(context.Background(), session.CreateRequest{AnalysisID: analysisID.String(), PolicyID: model.DefaultPolicyID})
	_, err := runtime.Provenance.GetEvidenceChain(context.Background(), provenance.ConclusionRequest{FusionRunID: run.ID, ConclusionID: "bad"})
	assertKind(t, err, model.ErrorInvalidArgument)
	unknown, _ := uuid.NewV7()
	_, err = runtime.Provenance.GetEvidenceChain(context.Background(), provenance.ConclusionRequest{FusionRunID: run.ID, ConclusionID: unknown.String()})
	assertKind(t, err, model.ErrorNotFound)
}

func assertKind(t *testing.T, err error, kind model.ErrorKind) {
	t.Helper()
	var fusionErr *model.Error
	if !errors.As(err, &fusionErr) || fusionErr.Kind != kind {
		t.Fatalf("error = %v, want %s", err, kind)
	}
}
