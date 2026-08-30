package correlation_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/correlation"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/ingest"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/session"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/store"
	"google.golang.org/protobuf/types/known/structpb"
)

type fixture struct {
	service *correlation.Service
	ingest  *ingest.Service
	runID   string
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
	return fixture{service: correlation.New(memory), ingest: ingest.New(memory, nil), runID: run.ID}
}

func evidence(property, value, resourceType, resourceID string, source model.Source, status commonv1.EvidenceStatus, metadata map[string]string) ingest.EvidenceInput {
	return ingest.EvidenceInput{
		PropertyKey: property, Value: structpb.NewStringValue(value), Source: source, Status: status,
		Confidence: 1, ObservedAt: time.Now().UTC(), ResourceType: resourceType, ResourceID: resourceID, Metadata: metadata,
	}
}

func seed(t *testing.T, fixture fixture) []string {
	t.Helper()
	response, err := fixture.ingest.AddBatch(context.Background(), ingest.AddBatchRequest{FusionRunID: fixture.runID, Evidence: []ingest.EvidenceInput{
		evidence("ike.version", "IKEv2", "IKE_SA", "passive-ike", model.SourcePacketParser, commonv1.EvidenceStatus_OBSERVED, map[string]string{"ike_initiator_spi": "aabbcc"}),
		evidence("ike.encryption", "AES_GCM", "VICI_IKE_SA", "vici-42", model.SourceVICI, commonv1.EvidenceStatus_VERIFIED_GATEWAY, map[string]string{"ike_initiator_spi": "AABBCC"}),
		evidence("traffic.class", "video", "FLOW", "flow-1", model.SourceMLClassifier, commonv1.EvidenceStatus_INFERRED, map[string]string{"endpoint_tuple": "10.0.0.1:1-10.0.0.2:2"}),
		evidence("certificate.subject", "CN=test", "CERTIFICATE", "cert-1", model.SourcePacketParser, commonv1.EvidenceStatus_OBSERVED, nil),
	}})
	if err != nil || response.AcceptedCount != 4 {
		t.Fatalf("seed = %+v, %v", response, err)
	}
	return response.EvidenceIDs
}

func TestCorrelateGetAndList(t *testing.T) {
	fixture := newFixture(t)
	seed(t, fixture)
	response, err := fixture.service.Correlate(context.Background(), correlation.CorrelateRequest{FusionRunID: fixture.runID})
	if err != nil || response.CorrelationGroupsCreated != 2 || response.TotalGroups != 2 || response.EvidenceItemsLinked != 3 || response.AmbiguousItems != 1 {
		t.Fatalf("Correlate() = %+v, %v", response, err)
	}
	ikeGroups, err := fixture.service.ListCorrelations(context.Background(), correlation.ListRequest{FusionRunID: fixture.runID, ResourceType: "IKE_SA"})
	if err != nil || len(ikeGroups.Groups) != 1 || len(ikeGroups.Groups[0].EvidenceIDs) != 2 {
		t.Fatalf("ListCorrelations(IKE_SA) = %+v, %v", ikeGroups, err)
	}
	parsed, err := uuid.Parse(ikeGroups.Groups[0].ID)
	if err != nil || parsed.Version() != 7 {
		t.Fatalf("correlation ID is not UUIDv7: %q, %v", ikeGroups.Groups[0].ID, err)
	}
	detail, err := fixture.service.GetCorrelation(context.Background(), correlation.GetRequest{FusionRunID: fixture.runID, CorrelationID: ikeGroups.Groups[0].ID})
	if err != nil || len(detail.Evidence) != 2 || detail.Group.ResourceType != "IKE_SA" {
		t.Fatalf("GetCorrelation() = %+v, %v", detail, err)
	}
}

func TestListPaginationAndValidation(t *testing.T) {
	fixture := newFixture(t)
	seed(t, fixture)
	if _, err := fixture.service.Correlate(context.Background(), correlation.CorrelateRequest{FusionRunID: fixture.runID}); err != nil {
		t.Fatal(err)
	}
	first, err := fixture.service.ListCorrelations(context.Background(), correlation.ListRequest{FusionRunID: fixture.runID, PageSize: 1})
	if err != nil || len(first.Groups) != 1 || first.NextPageToken == "" {
		t.Fatalf("first page = %+v, %v", first, err)
	}
	second, err := fixture.service.ListCorrelations(context.Background(), correlation.ListRequest{FusionRunID: fixture.runID, PageSize: 1, PageToken: first.NextPageToken})
	if err != nil || len(second.Groups) != 1 || second.NextPageToken != "" || second.Groups[0].ID == first.Groups[0].ID {
		t.Fatalf("second page = %+v, %v", second, err)
	}
	_, err = fixture.service.ListCorrelations(context.Background(), correlation.ListRequest{FusionRunID: fixture.runID, ResourceType: "CERTIFICATE"})
	assertKind(t, err, model.ErrorInvalidArgument)
}

func TestRebuildLinksNewEvidenceAndPreservesGroupID(t *testing.T) {
	fixture := newFixture(t)
	seed(t, fixture)
	if _, err := fixture.service.Correlate(context.Background(), correlation.CorrelateRequest{FusionRunID: fixture.runID}); err != nil {
		t.Fatal(err)
	}
	before, _ := fixture.service.ListCorrelations(context.Background(), correlation.ListRequest{FusionRunID: fixture.runID, ResourceType: "IKE_SA"})
	added, err := fixture.ingest.Add(context.Background(), ingest.AddRequest{FusionRunID: fixture.runID, Evidence: evidence("ike.integrity", "SHA256", "IKE_SA", "parser-2", model.SourcePacketParser, commonv1.EvidenceStatus_DERIVED, map[string]string{"ike_initiator_spi": "aabbcc"})})
	if err != nil || !added.Accepted {
		t.Fatalf("Add() = %+v, %v", added, err)
	}
	rebuilt, err := fixture.service.Rebuild(context.Background(), fixture.runID)
	if err != nil || !rebuilt.Rebuilt || rebuilt.Result.TotalGroups != 2 || rebuilt.Result.CorrelationGroupsCreated != 0 {
		t.Fatalf("Rebuild() = %+v, %v", rebuilt, err)
	}
	after, _ := fixture.service.ListCorrelations(context.Background(), correlation.ListRequest{FusionRunID: fixture.runID, ResourceType: "IKE_SA"})
	if after.Groups[0].ID != before.Groups[0].ID || len(after.Groups[0].EvidenceIDs) != 3 {
		t.Fatalf("group identity changed: before=%+v after=%+v", before, after)
	}
}

func TestConcurrentCorrelationIsSerialized(t *testing.T) {
	fixture := newFixture(t)
	seed(t, fixture)
	const callers = 12
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := fixture.service.Correlate(context.Background(), correlation.CorrelateRequest{FusionRunID: fixture.runID})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	groups, err := fixture.service.ListCorrelations(context.Background(), correlation.ListRequest{FusionRunID: fixture.runID})
	if err != nil || len(groups.Groups) != 2 {
		t.Fatalf("groups after concurrent correlation = %+v, %v", groups, err)
	}
}

func TestUnknownCorrelation(t *testing.T) {
	fixture := newFixture(t)
	unknown, _ := uuid.NewV7()
	_, err := fixture.service.GetCorrelation(context.Background(), correlation.GetRequest{FusionRunID: fixture.runID, CorrelationID: unknown.String()})
	assertKind(t, err, model.ErrorNotFound)
}

func assertKind(t *testing.T, err error, kind model.ErrorKind) {
	t.Helper()
	var fusionErr *model.Error
	if !errors.As(err, &fusionErr) || fusionErr.Kind != kind {
		t.Fatalf("error = %v, want %s", err, kind)
	}
}
