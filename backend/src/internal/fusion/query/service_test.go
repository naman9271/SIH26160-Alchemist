package query_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/ingest"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/query"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/session"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/store"
	"google.golang.org/protobuf/types/known/structpb"
)

type fixture struct {
	query  *query.Service
	ingest *ingest.Service
	runID  string
	ids    []string
	base   time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	memory := store.NewMemory()
	sessions := session.New(memory, policy.NewDefault())
	analysisID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	run, err := sessions.Create(context.Background(), session.CreateRequest{AnalysisID: analysisID.String(), PolicyID: model.DefaultPolicyID})
	if err != nil {
		t.Fatal(err)
	}
	ingester := ingest.New(memory, nil)
	base := time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	inputs := []ingest.EvidenceInput{
		evidence("ike.version", "IKEv2", model.SourcePacketParser, commonv1.EvidenceStatus_OBSERVED, "IKE_SA", "ike-1", base),
		evidence("child.mode", "TUNNEL", model.SourcePacketParser, commonv1.EvidenceStatus_DERIVED, "CHILD_SA", "child-1", base.Add(time.Second)),
		evidence("child.mode", "TRANSPORT", model.SourceVICI, commonv1.EvidenceStatus_VERIFIED_GATEWAY, "CHILD_SA", "child-1", base.Add(2*time.Second)),
		evidence("traffic.class", "video", model.SourceMLClassifier, commonv1.EvidenceStatus_INFERRED, "FLOW", "flow-1", base.Add(3*time.Second)),
	}
	batch, err := ingester.AddBatch(context.Background(), ingest.AddBatchRequest{FusionRunID: run.ID, Evidence: inputs})
	if err != nil || batch.AcceptedCount != 4 {
		t.Fatalf("seed evidence: %+v, %v", batch, err)
	}
	return fixture{query: query.New(memory), ingest: ingester, runID: run.ID, ids: batch.EvidenceIDs, base: base}
}

func evidence(property, value string, source model.Source, status commonv1.EvidenceStatus, resourceType, resourceID string, observed time.Time) ingest.EvidenceInput {
	return ingest.EvidenceInput{
		PropertyKey: property, Value: structpb.NewStringValue(value), Source: source, Status: status,
		Confidence: .9, ObservedAt: observed, ResourceType: resourceType, ResourceID: resourceID,
	}
}

func TestListAndCursorPagination(t *testing.T) {
	fixture := newFixture(t)
	first, err := fixture.query.List(context.Background(), query.ListRequest{FusionRunID: fixture.runID, PageSize: 2})
	if err != nil || len(first.Evidence) != 2 || first.NextPageToken == "" {
		t.Fatalf("first List() = %+v, %v", first, err)
	}
	second, err := fixture.query.List(context.Background(), query.ListRequest{FusionRunID: fixture.runID, PageSize: 2, PageToken: first.NextPageToken})
	if err != nil || len(second.Evidence) != 2 || second.NextPageToken != "" || second.Evidence[0].ID == first.Evidence[0].ID {
		t.Fatalf("second List() = %+v, %v", second, err)
	}
	_, err = fixture.query.List(context.Background(), query.ListRequest{FusionRunID: fixture.runID, PageToken: "invalid"})
	assertKind(t, err, model.ErrorInvalidArgument)
}

func TestListFilters(t *testing.T) {
	fixture := newFixture(t)
	tests := []struct {
		filter query.Filter
		want   int
	}{
		{query.Filter{Source: model.SourceVICI}, 1},
		{query.Filter{Status: commonv1.EvidenceStatus_DERIVED}, 1},
		{query.Filter{PropertyKey: "child.mode"}, 2},
		{query.Filter{ResourceType: "CHILD_SA", ResourceID: "child-1"}, 2},
		{query.Filter{ObservedFrom: fixture.base.Add(time.Second), ObservedTo: fixture.base.Add(2 * time.Second)}, 2},
	}
	for _, test := range tests {
		result, err := fixture.query.List(context.Background(), query.ListRequest{FusionRunID: fixture.runID, Filter: test.filter})
		if err != nil || len(result.Evidence) != test.want {
			t.Fatalf("List(%+v) count=%d err=%v", test.filter, len(result.Evidence), err)
		}
	}
}

func TestGetPropertyResourceAndCloneIsolation(t *testing.T) {
	fixture := newFixture(t)
	item, err := fixture.query.Get(context.Background(), query.GetRequest{FusionRunID: fixture.runID, EvidenceID: fixture.ids[0]})
	if err != nil || item.ID != fixture.ids[0] {
		t.Fatalf("Get() = %+v, %v", item, err)
	}
	item.Metadata["mutated"] = "yes"
	again, _ := fixture.query.Get(context.Background(), query.GetRequest{FusionRunID: fixture.runID, EvidenceID: fixture.ids[0]})
	if again.Metadata["mutated"] != "" {
		t.Fatal("query returned mutable store state")
	}
	properties, err := fixture.query.ListByProperty(context.Background(), query.ListByPropertyRequest{FusionRunID: fixture.runID, PropertyKey: "child.mode"})
	if err != nil || len(properties.Evidence) != 2 {
		t.Fatalf("ListByProperty() = %+v, %v", properties, err)
	}
	resources, err := fixture.query.ListByResource(context.Background(), query.ListByResourceRequest{FusionRunID: fixture.runID, ResourceType: "child_sa", ResourceID: "child-1"})
	if err != nil || len(resources.Evidence) != 2 {
		t.Fatalf("ListByResource() = %+v, %v", resources, err)
	}
}

func TestGetSourceCoverage(t *testing.T) {
	fixture := newFixture(t)
	if _, err := fixture.ingest.MarkSourceComplete(context.Background(), ingest.MarkSourceRequest{FusionRunID: fixture.runID, Source: model.SourcePacketParser}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.ingest.MarkSourceUnavailable(context.Background(), ingest.MarkSourceUnavailableRequest{FusionRunID: fixture.runID, Source: model.SourceXFRM, ReasonCode: "XFRM_UNAVAILABLE"}); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.query.GetSourceCoverage(context.Background(), fixture.runID)
	if err != nil || result.Coverage[model.SourcePacketParser].State != model.SourceComplete || result.Coverage[model.SourceXFRM].State != model.SourceUnavailable {
		t.Fatalf("GetSourceCoverage() = %+v, %v", result, err)
	}
}

func TestQueryValidationAndUnknownEvidence(t *testing.T) {
	fixture := newFixture(t)
	unknown, _ := uuid.NewV7()
	_, err := fixture.query.Get(context.Background(), query.GetRequest{FusionRunID: fixture.runID, EvidenceID: unknown.String()})
	assertKind(t, err, model.ErrorNotFound)
	_, err = fixture.query.List(context.Background(), query.ListRequest{FusionRunID: fixture.runID, PageSize: 1001})
	assertKind(t, err, model.ErrorInvalidArgument)
	_, err = fixture.query.List(context.Background(), query.ListRequest{FusionRunID: fixture.runID, Filter: query.Filter{ObservedFrom: time.Now(), ObservedTo: time.Now().Add(-time.Hour)}})
	assertKind(t, err, model.ErrorInvalidArgument)
	_, err = fixture.query.ListByResource(context.Background(), query.ListByResourceRequest{FusionRunID: fixture.runID, ResourceType: "FLOW"})
	assertKind(t, err, model.ErrorInvalidArgument)
}

func assertKind(t *testing.T, err error, kind model.ErrorKind) {
	t.Helper()
	var fusionErr *model.Error
	if !errors.As(err, &fusionErr) || fusionErr.Kind != kind {
		t.Fatalf("error = %v, want %s", err, kind)
	}
}
