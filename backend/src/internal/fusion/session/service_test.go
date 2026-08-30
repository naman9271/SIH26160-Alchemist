package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/store"
)

func newFixture(t *testing.T) (*Service, *store.Memory, string) {
	t.Helper()
	memory := store.NewMemory()
	policies := policy.NewMemory(policy.Definition{
		ID: "test-policy", RequiredSources: []model.Source{model.SourcePacketParser, model.SourceVICI},
	})
	analysisID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return New(memory, policies), memory, analysisID.String()
}

func TestCreateGetAndUUIDv7(t *testing.T) {
	service, _, analysisID := newFixture(t)
	before := time.Now().UTC()
	run, err := service.Create(context.Background(), CreateRequest{AnalysisID: analysisID, PolicyID: "test-policy"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := uuid.Parse(run.ID)
	if err != nil || parsed.Version() != 7 {
		t.Fatalf("fusion_run_id %q is not UUIDv7: %v", run.ID, err)
	}
	if run.State != model.RunStateActive || run.AnalysisID != analysisID || run.PolicyID != "test-policy" || run.CreatedAt.Location() != time.UTC || run.CreatedAt.Before(before) {
		t.Fatalf("unexpected run: %+v", run)
	}
	if len(run.SourceCoverage) != 2 || run.SourceCoverage[model.SourceVICI].State != model.SourcePending {
		t.Fatalf("required coverage was not initialized: %+v", run.SourceCoverage)
	}
	got, err := service.Get(context.Background(), run.ID)
	if err != nil || got.ID != run.ID {
		t.Fatalf("Get() = %+v, %v", got, err)
	}
}

func TestCreateValidationAndDuplicateAnalysis(t *testing.T) {
	service, _, analysisID := newFixture(t)
	tests := []CreateRequest{
		{},
		{AnalysisID: "not-a-uuid", PolicyID: "test-policy"},
		{AnalysisID: uuid.NewString(), PolicyID: "test-policy"},
		{AnalysisID: analysisID},
		{AnalysisID: analysisID, PolicyID: "missing"},
	}
	for _, request := range tests {
		if _, err := service.Create(context.Background(), request); err == nil {
			t.Fatalf("Create(%+v) unexpectedly succeeded", request)
		}
	}
	if _, err := service.Create(context.Background(), CreateRequest{AnalysisID: analysisID, PolicyID: "test-policy"}); err != nil {
		t.Fatal(err)
	}
	_, err := service.Create(context.Background(), CreateRequest{AnalysisID: analysisID, PolicyID: "test-policy"})
	assertErrorKind(t, err, model.ErrorAlreadyExists)
}

func TestFinalizeRequiresTerminalSourcesAndPreservesUnknownCoverage(t *testing.T) {
	service, memory, analysisID := newFixture(t)
	run, err := service.Create(context.Background(), CreateRequest{AnalysisID: analysisID, PolicyID: "test-policy"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Finalize(context.Background(), run.ID)
	assertErrorKind(t, err, model.ErrorFailedPrecondition)
	if _, err = memory.SetCounts(context.Background(), run.ID, model.Counts{Evidence: 9, Conclusions: 3, Conflicts: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err = memory.SetSourceCoverage(context.Background(), run.ID, model.SourcePacketParser, model.SourceComplete, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = memory.SetSourceCoverage(context.Background(), run.ID, model.SourceVICI, model.SourceUnavailable, "VICI_UNAVAILABLE"); err != nil {
		t.Fatal(err)
	}
	response, err := service.Finalize(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if response.Summary.State != model.RunStateFinalized || response.Summary.Counts.Evidence != 0 || response.Summary.Counts.Conclusions != 3 || response.Summary.Counts.Conflicts != 1 || response.Summary.CompletedSources != 1 || len(response.Summary.Unavailable) != 1 || response.Summary.Unavailable[0] != model.SourceVICI || response.Summary.FinalizedAt.IsZero() {
		t.Fatalf("unexpected summary: %+v", response.Summary)
	}
	again, err := service.Finalize(context.Background(), run.ID)
	if err != nil || again.Summary.FinalizedAt != response.Summary.FinalizedAt {
		t.Fatalf("idempotent Finalize() = %+v, %v", again, err)
	}
}

func TestCancelIsIdempotentAndCannotFinalize(t *testing.T) {
	service, _, analysisID := newFixture(t)
	run, err := service.Create(context.Background(), CreateRequest{AnalysisID: analysisID, PolicyID: "test-policy"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.Cancel(context.Background(), run.ID)
	if err != nil || first.Run.State != model.RunStateCancelled || first.Run.CancelledAt.IsZero() {
		t.Fatalf("Cancel() = %+v, %v", first, err)
	}
	second, err := service.Cancel(context.Background(), run.ID)
	if err != nil || second.Run.CancelledAt != first.Run.CancelledAt {
		t.Fatalf("second Cancel() = %+v, %v", second, err)
	}
	_, err = service.Finalize(context.Background(), run.ID)
	assertErrorKind(t, err, model.ErrorFailedPrecondition)
}

func TestResetClearsRunAndAllowsAnalysisReuse(t *testing.T) {
	service, _, analysisID := newFixture(t)
	run, err := service.Create(context.Background(), CreateRequest{AnalysisID: analysisID, PolicyID: "test-policy"})
	if err != nil {
		t.Fatal(err)
	}
	reset, err := service.Reset(context.Background(), run.ID)
	if err != nil || !reset.Reset || reset.FusionRunID != run.ID {
		t.Fatalf("Reset() = %+v, %v", reset, err)
	}
	_, err = service.Get(context.Background(), run.ID)
	assertErrorKind(t, err, model.ErrorNotFound)
	if _, err = service.Create(context.Background(), CreateRequest{AnalysisID: analysisID, PolicyID: "test-policy"}); err != nil {
		t.Fatalf("analysis ID was not released by reset: %v", err)
	}
}

func TestConcurrentCreateHasSingleWinner(t *testing.T) {
	service, _, analysisID := newFixture(t)
	const callers = 16
	var wg sync.WaitGroup
	results := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := service.Create(context.Background(), CreateRequest{AnalysisID: analysisID, PolicyID: "test-policy"})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	var successes, duplicates int
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		var fusionErr *model.Error
		if errors.As(err, &fusionErr) && fusionErr.Kind == model.ErrorAlreadyExists {
			duplicates++
			continue
		}
		t.Fatalf("unexpected concurrent Create error: %v", err)
	}
	if successes != 1 || duplicates != callers-1 {
		t.Fatalf("successes=%d duplicates=%d", successes, duplicates)
	}
}

func TestSessionMethodsHonorCancellation(t *testing.T) {
	service, _, analysisID := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := service.Create(ctx, CreateRequest{AnalysisID: analysisID, PolicyID: "test-policy"})
	assertErrorKind(t, err, model.ErrorCancelled)
}

func assertErrorKind(t *testing.T, err error, kind model.ErrorKind) {
	t.Helper()
	var fusionErr *model.Error
	if !errors.As(err, &fusionErr) || fusionErr.Kind != kind {
		t.Fatalf("error = %v, want kind %s", err, kind)
	}
}
