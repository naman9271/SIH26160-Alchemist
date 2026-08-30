// Package session implements the internal FusionSessionService lifecycle.
package session

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
)

type Store interface {
	Create(context.Context, model.Run) (model.Run, error)
	Get(context.Context, string) (model.Run, error)
	Update(context.Context, string, func(*model.Run) error) (model.Run, error)
	Delete(context.Context, string) (model.Run, error)
}
type EventPublisher interface {
	Publish(context.Context, model.FusionEvent) error
}

type CreateRequest struct {
	AnalysisID string
	PolicyID   string
}

type FinalizeResponse struct{ Summary model.FinalSummary }
type CancelResponse struct{ Run model.Run }
type ResetResponse struct {
	FusionRunID string
	Reset       bool
}

type Service struct {
	store    Store
	policies policy.Provider
	now      func() time.Time
	newID    func() (string, error)
	events   EventPublisher
}

func New(store Store, policies policy.Provider, publishers ...EventPublisher) *Service {
	service := &Service{store: store, policies: policies, now: func() time.Time { return time.Now().UTC() }, newID: model.NewFusionRunID}
	if len(publishers) > 0 {
		service.events = publishers[0]
	}
	return service
}

func (s *Service) Create(ctx context.Context, request CreateRequest) (model.Run, error) {
	if err := model.ContextError(ctx); err != nil {
		return model.Run{}, err
	}
	if s == nil || s.store == nil || s.policies == nil {
		return model.Run{}, model.NewError(model.ErrorInternal, "Fusion session dependencies are not configured")
	}
	request.AnalysisID = strings.TrimSpace(request.AnalysisID)
	request.PolicyID = strings.TrimSpace(request.PolicyID)
	if err := model.ValidateAnalysisID(request.AnalysisID); err != nil {
		return model.Run{}, err
	}
	definition, err := s.policies.Resolve(ctx, request.PolicyID)
	if err != nil {
		return model.Run{}, err
	}
	required, err := validateRequiredSources(definition.RequiredSources)
	if err != nil {
		return model.Run{}, err
	}
	id, err := s.newID()
	if err != nil {
		return model.Run{}, &model.Error{Kind: model.ErrorInternal, Message: "could not generate Fusion run ID", Cause: err}
	}
	now := s.now().UTC()
	run := model.Run{
		ID: id, AnalysisID: request.AnalysisID, PolicyID: definition.ID, State: model.RunStateActive,
		RequiredSources: required, SourceCoverage: make(map[model.Source]model.SourceCoverage, len(required)),
		EvidenceByID: make(map[string]model.EvidenceItem), EvidenceByProperty: make(map[string][]string),
		EvidenceByResource: make(map[string][]string), Correlations: make(map[string]model.CorrelationGroup),
		Conflicts: make(map[string]model.EvidenceConflict), Conclusions: make(map[string]model.FusedConclusion),
		ConclusionByKey: make(map[string]string), Fusion: model.FusionExecution{State: model.FusionIdle},
		CreatedAt: now, UpdatedAt: now,
	}
	for _, source := range required {
		run.SourceCoverage[source] = model.SourceCoverage{Source: source, State: model.SourcePending, UpdatedAt: now}
	}
	created, err := s.store.Create(ctx, run)
	if err != nil {
		return model.Run{}, err
	}
	if err = s.publish(ctx, created, model.EventFusionRunCreated); err != nil {
		return model.Run{}, err
	}
	return created, nil
}

func (s *Service) Get(ctx context.Context, fusionRunID string) (model.Run, error) {
	if err := model.ContextError(ctx); err != nil {
		return model.Run{}, err
	}
	if s == nil || s.store == nil {
		return model.Run{}, model.NewError(model.ErrorInternal, "Fusion session store is not configured")
	}
	if err := model.ValidateRunID(fusionRunID); err != nil {
		return model.Run{}, err
	}
	return s.store.Get(ctx, strings.TrimSpace(fusionRunID))
}

func (s *Service) Finalize(ctx context.Context, fusionRunID string) (FinalizeResponse, error) {
	if err := model.ContextError(ctx); err != nil {
		return FinalizeResponse{}, err
	}
	if err := model.ValidateRunID(fusionRunID); err != nil {
		return FinalizeResponse{}, err
	}
	if s == nil || s.store == nil {
		return FinalizeResponse{}, model.NewError(model.ErrorInternal, "Fusion session store is not configured")
	}
	changed := false
	run, err := s.store.Update(ctx, strings.TrimSpace(fusionRunID), func(run *model.Run) error {
		if run.State == model.RunStateFinalized {
			return nil
		}
		if run.State != model.RunStateActive {
			return model.NewError(model.ErrorFailedPrecondition, "only an active Fusion run can be finalized")
		}
		for _, source := range run.RequiredSources {
			coverage, exists := run.SourceCoverage[source]
			if !exists || !coverage.State.Terminal() {
				return model.NewError(model.ErrorFailedPrecondition, "required evidence sources are still pending")
			}
		}
		now := s.now().UTC()
		run.State, run.FinalizedAt = model.RunStateFinalized, now
		changed = true
		return nil
	})
	if err != nil {
		return FinalizeResponse{}, err
	}
	if changed {
		if err = s.publish(ctx, run, model.EventFusionFinalized); err != nil {
			return FinalizeResponse{}, err
		}
	}
	return FinalizeResponse{Summary: finalSummary(run)}, nil
}

func (s *Service) publish(ctx context.Context, run model.Run, eventType model.EventType) error {
	if s.events == nil {
		return nil
	}
	if err := s.events.Publish(ctx, model.FusionEvent{FusionRunID: run.ID, AnalysisID: run.AnalysisID, Type: eventType, OccurredAt: s.now().UTC()}); err != nil {
		return &model.Error{Kind: model.ErrorUnavailable, Message: "Fusion session changed but its event could not be emitted", Cause: err}
	}
	return nil
}

func (s *Service) Cancel(ctx context.Context, fusionRunID string) (CancelResponse, error) {
	if err := model.ContextError(ctx); err != nil {
		return CancelResponse{}, err
	}
	if err := model.ValidateRunID(fusionRunID); err != nil {
		return CancelResponse{}, err
	}
	if s == nil || s.store == nil {
		return CancelResponse{}, model.NewError(model.ErrorInternal, "Fusion session store is not configured")
	}
	run, err := s.store.Update(ctx, strings.TrimSpace(fusionRunID), func(run *model.Run) error {
		if run.State == model.RunStateCancelled {
			return nil
		}
		if run.State != model.RunStateActive {
			return model.NewError(model.ErrorFailedPrecondition, "only an active Fusion run can be cancelled")
		}
		now := s.now().UTC()
		run.State, run.CancelledAt = model.RunStateCancelled, now
		return nil
	})
	if err != nil {
		return CancelResponse{}, err
	}
	return CancelResponse{Run: run}, nil
}

func (s *Service) Reset(ctx context.Context, fusionRunID string) (ResetResponse, error) {
	if err := model.ContextError(ctx); err != nil {
		return ResetResponse{}, err
	}
	if err := model.ValidateRunID(fusionRunID); err != nil {
		return ResetResponse{}, err
	}
	if s == nil || s.store == nil {
		return ResetResponse{}, model.NewError(model.ErrorInternal, "Fusion session store is not configured")
	}
	run, err := s.store.Delete(ctx, strings.TrimSpace(fusionRunID))
	if err != nil {
		return ResetResponse{}, err
	}
	return ResetResponse{FusionRunID: run.ID, Reset: true}, nil
}

func validateRequiredSources(sources []model.Source) ([]model.Source, error) {
	unique := make(map[model.Source]struct{}, len(sources))
	for _, source := range sources {
		if !source.Valid() {
			return nil, model.NewError(model.ErrorInternal, "Fusion policy contains an invalid required source")
		}
		unique[source] = struct{}{}
	}
	result := make([]model.Source, 0, len(unique))
	for source := range unique {
		result = append(result, source)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}

func finalSummary(run model.Run) model.FinalSummary {
	result := model.FinalSummary{FusionRunID: run.ID, State: run.State, Counts: run.Counts, FinalizedAt: run.FinalizedAt}
	for _, source := range run.RequiredSources {
		switch run.SourceCoverage[source].State {
		case model.SourceComplete:
			result.CompletedSources++
		case model.SourceFailed:
			result.FailedSources++
		case model.SourceTimedOut:
			result.TimedOutSources++
		case model.SourceUnavailable:
			result.Unavailable = append(result.Unavailable, source)
		}
	}
	sort.Slice(result.Unavailable, func(i, j int) bool { return result.Unavailable[i] < result.Unavailable[j] })
	return result
}
