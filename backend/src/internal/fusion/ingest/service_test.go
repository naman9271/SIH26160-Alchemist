package ingest

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/session"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/store"
	"google.golang.org/protobuf/types/known/structpb"
)

type scheduler struct {
	calls      int
	properties []string
	err        error
}

func (s *scheduler) Schedule(_ context.Context, _ string, properties []string) error {
	s.calls++
	s.properties = append([]string(nil), properties...)
	return s.err
}

func fixture(t *testing.T) (*Service, *store.Memory, string) {
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
	return New(memory, nil), memory, run.ID
}

func validInput(source model.Source, status commonv1.EvidenceStatus, property string) EvidenceInput {
	return EvidenceInput{
		PropertyKey: property, Value: structpb.NewStringValue("IKEv2"), Source: source,
		Status: status, Confidence: 1, ObservedAt: time.Now().UTC(),
		ResourceType: "IKE_SA", ResourceID: "ike-1", Metadata: map[string]string{"ike_initiator_spi": "abc"},
	}
}

func TestAddAndRemoveEvidence(t *testing.T) {
	service, memory, runID := fixture(t)
	recompute := &scheduler{}
	service.scheduler = recompute
	added, err := service.Add(context.Background(), AddRequest{FusionRunID: runID, Evidence: validInput(model.SourcePacketParser, commonv1.EvidenceStatus_OBSERVED, "ike.version")})
	if err != nil || !added.Accepted || !added.TriggeredRecompute || recompute.calls != 1 {
		t.Fatalf("Add() = %+v, scheduler=%+v, err=%v", added, recompute, err)
	}
	parsed, err := uuid.Parse(added.EvidenceID)
	if err != nil || parsed.Version() != 7 {
		t.Fatalf("evidence ID is not UUIDv7: %q, %v", added.EvidenceID, err)
	}
	run, err := memory.Get(context.Background(), runID)
	if err != nil || run.Counts.Evidence != 1 || run.EvidenceByID[added.EvidenceID].ObservedAt.Location() != time.UTC {
		t.Fatalf("stored run = %+v, %v", run, err)
	}
	removed, err := service.Remove(context.Background(), RemoveRequest{FusionRunID: runID, EvidenceID: added.EvidenceID})
	if err != nil || !removed.Removed || !removed.TriggeredRecompute || recompute.calls != 2 {
		t.Fatalf("Remove() = %+v, scheduler=%+v, err=%v", removed, recompute, err)
	}
	run, _ = memory.Get(context.Background(), runID)
	if run.Counts.Evidence != 0 || len(run.EvidenceByProperty) != 0 || len(run.EvidenceByResource) != 0 {
		t.Fatalf("evidence indexes were not cleared: %+v", run)
	}
}

func TestAddBatchPartiallyAcceptsValidationFailures(t *testing.T) {
	service, _, runID := fixture(t)
	recompute := &scheduler{}
	service.scheduler = recompute
	invalid := validInput(model.SourceMLClassifier, commonv1.EvidenceStatus_OBSERVED, "traffic.class")
	validML := validInput(model.SourceMLClassifier, commonv1.EvidenceStatus_INFERRED, "traffic.class")
	validPassive := validInput(model.SourcePacketParser, commonv1.EvidenceStatus_DERIVED, "child.mode")
	response, err := service.AddBatch(context.Background(), AddBatchRequest{FusionRunID: runID, Evidence: []EvidenceInput{validML, invalid, validPassive}})
	if err != nil {
		t.Fatal(err)
	}
	if response.AcceptedCount != 2 || response.RejectedCount != 1 || len(response.EvidenceIDs) != 2 || len(response.ValidationErrors) != 1 || response.ValidationErrors[0].Index != 1 || !response.RecomputeScheduled {
		t.Fatalf("AddBatch() = %+v", response)
	}
	if recompute.calls != 1 || !reflect.DeepEqual(recompute.properties, []string{"child.mode", "traffic.class"}) {
		t.Fatalf("scheduler = %+v", recompute)
	}
}

func TestEvidenceValidation(t *testing.T) {
	service, _, runID := fixture(t)
	tests := []EvidenceInput{
		{},
		validInput(model.SourceVICI, commonv1.EvidenceStatus_OBSERVED, "ike.version"),
		validInput(model.SourceMLClassifier, commonv1.EvidenceStatus_VERIFIED_GATEWAY, "traffic.class"),
		func() EvidenceInput {
			item := validInput(model.SourcePacketParser, commonv1.EvidenceStatus_OBSERVED, "ike.version")
			item.Confidence = 1.1
			return item
		}(),
		func() EvidenceInput {
			item := validInput(model.SourcePacketParser, commonv1.EvidenceStatus_OBSERVED, "Bad Key")
			return item
		}(),
		func() EvidenceInput {
			item := validInput(model.SourcePacketParser, commonv1.EvidenceStatus_OBSERVED, "ike.version")
			item.ObservedAt = time.Time{}
			return item
		}(),
		func() EvidenceInput {
			item := validInput(model.SourcePacketParser, commonv1.EvidenceStatus_OBSERVED, "ike.private_key")
			return item
		}(),
		func() EvidenceInput {
			item := validInput(model.SourcePacketParser, commonv1.EvidenceStatus_OBSERVED, "ike.version")
			item.Metadata = map[string]string{"key_bytes": "secret"}
			return item
		}(),
	}
	for index, input := range tests {
		if _, err := service.Add(context.Background(), AddRequest{FusionRunID: runID, Evidence: input}); err == nil {
			t.Fatalf("validation case %d unexpectedly succeeded", index)
		}
	}
}

func TestSourceCoverageLifecycle(t *testing.T) {
	service, _, runID := fixture(t)
	completed, err := service.MarkSourceComplete(context.Background(), MarkSourceRequest{FusionRunID: runID, Source: model.SourcePacketParser})
	if err != nil || completed.Coverage.State != model.SourceComplete {
		t.Fatalf("MarkSourceComplete() = %+v, %v", completed, err)
	}
	if _, err = service.MarkSourceComplete(context.Background(), MarkSourceRequest{FusionRunID: runID, Source: model.SourcePacketParser}); err != nil {
		t.Fatalf("idempotent complete failed: %v", err)
	}
	_, err = service.Add(context.Background(), AddRequest{FusionRunID: runID, Evidence: validInput(model.SourcePacketParser, commonv1.EvidenceStatus_OBSERVED, "ike.version")})
	assertKind(t, err, model.ErrorFailedPrecondition)
	unavailable, err := service.MarkSourceUnavailable(context.Background(), MarkSourceUnavailableRequest{FusionRunID: runID, Source: model.SourceXFRM, ReasonCode: "XFRM_NOT_AVAILABLE"})
	if err != nil || unavailable.Coverage.State != model.SourceUnavailable || unavailable.Coverage.ReasonCode != "XFRM_NOT_AVAILABLE" {
		t.Fatalf("MarkSourceUnavailable() = %+v, %v", unavailable, err)
	}
	_, err = service.MarkSourceComplete(context.Background(), MarkSourceRequest{FusionRunID: runID, Source: model.SourceXFRM})
	assertKind(t, err, model.ErrorFailedPrecondition)
	_, err = service.MarkSourceUnavailable(context.Background(), MarkSourceUnavailableRequest{FusionRunID: runID, Source: model.SourceVICI})
	assertKind(t, err, model.ErrorInvalidArgument)
}

func TestSecurityReferencesDoNotSchedulePrimaryRecompute(t *testing.T) {
	service, _, runID := fixture(t)
	recompute := &scheduler{}
	service.scheduler = recompute
	item := validInput(model.SourceSecurityRule, commonv1.EvidenceStatus_DERIVED, "security.rule.IPSEC_PFS_001")
	response, err := service.Add(context.Background(), AddRequest{FusionRunID: runID, Evidence: item})
	if err != nil || response.TriggeredRecompute || recompute.calls != 0 {
		t.Fatalf("security reference scheduled primary fusion: %+v, %+v, %v", response, recompute, err)
	}
}

func TestSchedulerFailureDoesNotLoseAcceptedEvidence(t *testing.T) {
	service, memory, runID := fixture(t)
	service.scheduler = &scheduler{err: errors.New("queue unavailable")}
	response, err := service.Add(context.Background(), AddRequest{FusionRunID: runID, Evidence: validInput(model.SourcePacketParser, commonv1.EvidenceStatus_OBSERVED, "ike.version")})
	assertKind(t, err, model.ErrorUnavailable)
	if !response.Accepted || response.TriggeredRecompute {
		t.Fatalf("unexpected response: %+v", response)
	}
	run, _ := memory.Get(context.Background(), runID)
	if run.Counts.Evidence != 1 {
		t.Fatal("accepted evidence was rolled back after scheduler failure")
	}
}

func assertKind(t *testing.T, err error, kind model.ErrorKind) {
	t.Helper()
	var fusionErr *model.Error
	if !errors.As(err, &fusionErr) || fusionErr.Kind != kind {
		t.Fatalf("error = %v, want %s", err, kind)
	}
}
