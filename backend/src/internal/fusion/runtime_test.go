package fusion

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/correlation"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/ingest"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/query"
	fusionsession "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/session"
	fusionsystem "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/system"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestRuntimeWiresSharedStoreAndReportsActualReadiness(t *testing.T) {
	runtime := NewRuntime(RuntimeOptions{})
	readiness, err := runtime.System.Readiness(context.Background())
	if err != nil || !readiness.Ready {
		t.Fatalf("Readiness() = %+v, %v", readiness, err)
	}
	capabilities, err := runtime.System.GetCapabilities(context.Background())
	if err != nil || !capabilities.IncrementalRecomputation {
		t.Fatalf("GetCapabilities() = %+v, %v", capabilities, err)
	}
	analysisID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	run, err := runtime.Sessions.Create(context.Background(), fusionsession.CreateRequest{
		AnalysisID: analysisID.String(), PolicyID: model.DefaultPolicyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.Store.SetSourceCoverage(context.Background(), run.ID, model.SourcePacketParser, model.SourceComplete, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.Store.SetSourceCoverage(context.Background(), run.ID, model.SourceFlowAnalyzer, model.SourceComplete, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.Sessions.Finalize(context.Background(), run.ID); err != nil {
		t.Fatalf("shared store did not drive session finalization: %v", err)
	}
}

func TestRuntimeReportsInjectedCorrelatorFailure(t *testing.T) {
	readiness, err := NewRuntime(RuntimeOptions{Correlator: fusionsystem.StaticProbe(false, "correlator policy invalid")}).System.Readiness(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if readiness.Ready || readiness.Correlator.Ready || readiness.Correlator.Reason != "correlator policy invalid" {
		t.Fatalf("unexpected default readiness: %+v", readiness)
	}
}

func TestRuntimeEvidenceCorrelationAndFinalizationWorkflow(t *testing.T) {
	runtime := NewRuntime(RuntimeOptions{})
	analysisID, _ := uuid.NewV7()
	run, err := runtime.Sessions.Create(context.Background(), fusionsession.CreateRequest{AnalysisID: analysisID.String(), PolicyID: model.DefaultPolicyID})
	if err != nil {
		t.Fatal(err)
	}
	observedAt := time.Now().UTC()
	batch, err := runtime.Ingest.AddBatch(context.Background(), ingest.AddBatchRequest{FusionRunID: run.ID, Evidence: []ingest.EvidenceInput{
		{PropertyKey: "ike.version", Value: structpb.NewStringValue("IKEv2"), Source: model.SourcePacketParser, Status: commonv1.EvidenceStatus_OBSERVED, Confidence: 1, ObservedAt: observedAt, ResourceType: "IKE_SA", ResourceID: "passive-1", Metadata: map[string]string{"ike_initiator_spi": "abc", "endpoint_pair": "192.0.2.1<>198.51.100.1"}},
		{PropertyKey: "ike.encryption", Value: structpb.NewStringValue("AES_GCM"), Source: model.SourceVICI, Status: commonv1.EvidenceStatus_VERIFIED_GATEWAY, Confidence: 1, ObservedAt: observedAt, ResourceType: "VICI_IKE_SA", ResourceID: "vici-1", Metadata: map[string]string{"ike_initiator_spi": "abc", "endpoint_pair": "192.0.2.1<>198.51.100.1"}},
	}})
	if err != nil || batch.AcceptedCount != 2 || !batch.RecomputeScheduled {
		t.Fatalf("AddBatch() = %+v, %v", batch, err)
	}
	evidence, err := runtime.Query.ListByProperty(context.Background(), query.ListByPropertyRequest{FusionRunID: run.ID, PropertyKey: "ike.version"})
	if err != nil || len(evidence.Evidence) != 1 {
		t.Fatalf("ListByProperty() = %+v, %v", evidence, err)
	}
	correlated, err := runtime.Correlations.Correlate(context.Background(), correlation.CorrelateRequest{FusionRunID: run.ID})
	if err != nil || correlated.TotalGroups != 1 || correlated.EvidenceItemsLinked != 2 {
		t.Fatalf("Correlate() = %+v, %v", correlated, err)
	}
	if _, err = runtime.Ingest.MarkSourceComplete(context.Background(), ingest.MarkSourceRequest{FusionRunID: run.ID, Source: model.SourcePacketParser}); err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.Ingest.MarkSourceComplete(context.Background(), ingest.MarkSourceRequest{FusionRunID: run.ID, Source: model.SourceFlowAnalyzer}); err != nil {
		t.Fatal(err)
	}
	finalized, err := runtime.Sessions.Finalize(context.Background(), run.ID)
	if err != nil || finalized.Summary.Counts.Evidence != 2 || finalized.Summary.State != model.RunStateFinalized {
		t.Fatalf("Finalize() = %+v, %v", finalized, err)
	}
	if _, err = runtime.Sessions.Reset(context.Background(), run.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.Query.List(context.Background(), query.ListRequest{FusionRunID: run.ID}); err == nil {
		t.Fatal("reset Fusion run remained queryable")
	}
}
