// Package conflict implements conflict detection and policy resolution.
package conflict

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/decision"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/store"
)

type Store interface {
	Get(context.Context, string) (model.Run, error)
	ReplaceConflicts(context.Context, string, []model.EvidenceConflict, []string, bool) (model.Run, error)
	UpdateConflict(context.Context, string, string, func(*model.EvidenceConflict) error) (model.EvidenceConflict, model.Run, error)
}
type EventPublisher interface {
	Publish(context.Context, model.FusionEvent) error
}

type DetectRequest struct {
	FusionRunID        string
	AffectedProperties []string
}

type DetectResponse struct {
	ConflictsFound      uint64
	AffectedConclusions uint64
}

type ListRequest struct {
	FusionRunID    string
	PropertyPrefix string
	ResourceType   string
	ResourceID     string
	State          model.ConflictState
	PageSize       uint32
	PageToken      string
}

type ListResponse struct {
	Conflicts     []model.EvidenceConflict
	NextPageToken string
}

type GetRequest struct {
	FusionRunID string
	ConflictID  string
}

type Candidate struct {
	Evidence model.EvidenceItem
	Age      time.Duration
}

type Detail struct {
	Conflict   model.EvidenceConflict
	Candidates []Candidate
}

type ResolveRequest struct {
	FusionRunID string
	ConflictID  string
	Mode        model.ResolutionMode
}

type ResolveResponse struct {
	Conflict        model.EvidenceConflict
	WinningEvidence model.EvidenceItem
	RationaleCode   string
}

type ReevaluateResponse struct{ DetectResponse }

type Service struct {
	store    Store
	policies policy.Provider
	mu       sync.Mutex
	now      func() time.Time
	newID    func() (string, error)
	events   EventPublisher
}

func New(store Store, policies policy.Provider, publishers ...EventPublisher) *Service {
	service := &Service{store: store, policies: policies, now: func() time.Time { return time.Now().UTC() }, newID: model.NewConflictID}
	if len(publishers) > 0 {
		service.events = publishers[0]
	}
	return service
}

func (s *Service) Ready(ctx context.Context) (bool, string) {
	if err := model.ContextError(ctx); err != nil {
		return false, err.Error()
	}
	if s == nil || s.store == nil || s.policies == nil {
		return false, "conflict store or policy provider is not configured"
	}
	return s.policies.Ready(ctx)
}

func (s *Service) Detect(ctx context.Context, request DetectRequest) (DetectResponse, error) {
	if err := s.ready(ctx, request.FusionRunID); err != nil {
		return DetectResponse{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run, err := s.store.Get(ctx, strings.TrimSpace(request.FusionRunID))
	if err != nil {
		return DetectResponse{}, err
	}
	if run.State != model.RunStateActive {
		return DetectResponse{}, model.NewError(model.ErrorFailedPrecondition, "conflict detection requires an active Fusion run")
	}
	affected := normalizeProperties(request.AffectedProperties)
	groups := decision.GroupEvidence(run, affected)
	existing := make(map[string]model.EvidenceConflict)
	for _, conflict := range run.Conflicts {
		existing[store.ConclusionKey(conflict.PropertyKey, conflict.ResourceType, conflict.ResourceID)] = conflict
	}
	now := s.now().UTC()
	conflicts := make([]model.EvidenceConflict, 0)
	detectedEvents := make([]model.EvidenceConflict, 0)
	for _, group := range groups {
		if len(decision.DistinctKnownValues(group.Evidence)) < 2 {
			continue
		}
		ids := make([]string, 0, len(group.Evidence))
		for _, item := range group.Evidence {
			ids = append(ids, item.ID)
		}
		sort.Strings(ids)
		key := store.ConclusionKey(group.PropertyKey, group.ResourceType, group.ResourceID)
		conflict, reuse := existing[key]
		if !reuse {
			id, idErr := s.newID()
			if idErr != nil {
				return DetectResponse{}, &model.Error{Kind: model.ErrorInternal, Message: "could not generate conflict ID", Cause: idErr}
			}
			conflict = model.EvidenceConflict{ID: id, CreatedAt: now}
		}
		candidatesChanged := !equalIDs(conflict.CandidateEvidenceIDs, ids)
		if candidatesChanged {
			conflict.State, conflict.WinningEvidenceID, conflict.ResolutionMode, conflict.RationaleCode, conflict.ResolvedAt = model.ConflictOpen, "", "", "", time.Time{}
		}
		conflict.PropertyKey, conflict.ResourceType, conflict.ResourceID = group.PropertyKey, group.ResourceType, group.ResourceID
		conflict.CandidateEvidenceIDs, conflict.UpdatedAt = ids, now
		if conflict.State == "" {
			conflict.State = model.ConflictOpen
		}
		conflicts = append(conflicts, conflict)
		if !reuse || candidatesChanged {
			detectedEvents = append(detectedEvents, conflict)
		}
	}
	full := len(affected) == 0
	properties := setKeys(affected)
	updated, err := s.store.ReplaceConflicts(ctx, run.ID, conflicts, properties, full)
	if err != nil {
		return DetectResponse{}, err
	}
	if s.events != nil {
		for _, item := range detectedEvents {
			if err = s.events.Publish(ctx, model.FusionEvent{FusionRunID: run.ID, AnalysisID: run.AnalysisID, Type: model.EventConflictDetected,
				OccurredAt: now, PropertyKey: item.PropertyKey, ConflictID: item.ID}); err != nil {
				return DetectResponse{}, &model.Error{Kind: model.ErrorUnavailable, Message: "conflicts changed but their events could not be emitted", Cause: err}
			}
		}
	}
	conflictKeys := make(map[string]struct{}, len(conflicts))
	for _, item := range conflicts {
		conflictKeys[store.ConclusionKey(item.PropertyKey, item.ResourceType, item.ResourceID)] = struct{}{}
	}
	var affectedConclusions uint64
	for _, conclusion := range updated.Conclusions {
		if _, ok := conflictKeys[store.ConclusionKey(conclusion.PropertyKey, conclusion.ResourceType, conclusion.ResourceID)]; ok {
			affectedConclusions++
		}
	}
	return DetectResponse{ConflictsFound: uint64(len(conflicts)), AffectedConclusions: affectedConclusions}, nil
}

func (s *Service) List(ctx context.Context, request ListRequest) (ListResponse, error) {
	if err := s.ready(ctx, request.FusionRunID); err != nil {
		return ListResponse{}, err
	}
	request.PropertyPrefix = strings.TrimSpace(request.PropertyPrefix)
	request.ResourceType = strings.ToUpper(strings.TrimSpace(request.ResourceType))
	request.ResourceID = strings.TrimSpace(request.ResourceID)
	if (request.ResourceType == "") != (request.ResourceID == "") {
		return ListResponse{}, model.NewError(model.ErrorInvalidArgument, "resource_type and resource_id filters must be provided together")
	}
	if request.State != "" && request.State != model.ConflictOpen && request.State != model.ConflictResolved {
		return ListResponse{}, model.NewError(model.ErrorInvalidArgument, "conflict state filter is invalid")
	}
	pageSize := int(request.PageSize)
	if pageSize == 0 {
		pageSize = 100
	}
	if pageSize > 1000 {
		return ListResponse{}, model.NewError(model.ErrorInvalidArgument, "page_size must not exceed 1000")
	}
	if request.PageToken != "" && model.ValidateConflictID(request.PageToken) != nil {
		return ListResponse{}, model.NewError(model.ErrorInvalidArgument, "page_token is invalid")
	}
	run, err := s.store.Get(ctx, strings.TrimSpace(request.FusionRunID))
	if err != nil {
		return ListResponse{}, err
	}
	items := make([]model.EvidenceConflict, 0)
	for _, item := range store.SortedConflicts(run) {
		if request.PropertyPrefix != "" && !strings.HasPrefix(item.PropertyKey, request.PropertyPrefix) {
			continue
		}
		if request.ResourceType != "" && (item.ResourceType != request.ResourceType || item.ResourceID != request.ResourceID) {
			continue
		}
		if request.State != "" && item.State != request.State {
			continue
		}
		items = append(items, item)
	}
	start, err := pageStartConflict(items, request.PageToken)
	if err != nil {
		return ListResponse{}, err
	}
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	next := ""
	if end < len(items) {
		next = items[end-1].ID
	}
	return ListResponse{Conflicts: items[start:end], NextPageToken: next}, nil
}

func (s *Service) Get(ctx context.Context, request GetRequest) (Detail, error) {
	if err := s.ready(ctx, request.FusionRunID); err != nil {
		return Detail{}, err
	}
	if err := model.ValidateConflictID(request.ConflictID); err != nil {
		return Detail{}, err
	}
	run, err := s.store.Get(ctx, strings.TrimSpace(request.FusionRunID))
	if err != nil {
		return Detail{}, err
	}
	conflict, exists := run.Conflicts[strings.TrimSpace(request.ConflictID)]
	if !exists {
		return Detail{}, model.NewError(model.ErrorNotFound, "evidence conflict was not found")
	}
	now := s.now()
	candidates := make([]Candidate, 0, len(conflict.CandidateEvidenceIDs))
	for _, id := range conflict.CandidateEvidenceIDs {
		if item, ok := run.EvidenceByID[id]; ok {
			age := now.Sub(item.ObservedAt)
			if age < 0 {
				age = 0
			}
			candidates = append(candidates, Candidate{Evidence: item.Clone(), Age: age})
		}
	}
	return Detail{Conflict: conflict.Clone(), Candidates: candidates}, nil
}

func (s *Service) Resolve(ctx context.Context, request ResolveRequest) (ResolveResponse, error) {
	if err := s.ready(ctx, request.FusionRunID); err != nil {
		return ResolveResponse{}, err
	}
	if err := model.ValidateConflictID(request.ConflictID); err != nil {
		return ResolveResponse{}, err
	}
	if request.Mode == "" {
		request.Mode = model.ResolutionPolicy
	}
	if request.Mode == model.ResolutionManualOperator {
		return ResolveResponse{}, model.NewError(model.ErrorFailedPrecondition, "manual operator conflict resolution is not supported in Fusion v1")
	}
	if request.Mode != model.ResolutionPolicy {
		return ResolveResponse{}, model.NewError(model.ErrorInvalidArgument, "resolution mode is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run, err := s.store.Get(ctx, strings.TrimSpace(request.FusionRunID))
	if err != nil {
		return ResolveResponse{}, err
	}
	conflict, exists := run.Conflicts[strings.TrimSpace(request.ConflictID)]
	if !exists {
		return ResolveResponse{}, model.NewError(model.ErrorNotFound, "evidence conflict was not found")
	}
	definition, err := s.policies.Resolve(ctx, run.PolicyID)
	if err != nil {
		return ResolveResponse{}, err
	}
	candidates := make([]model.EvidenceItem, 0, len(conflict.CandidateEvidenceIDs))
	for _, id := range conflict.CandidateEvidenceIDs {
		if item, ok := run.EvidenceByID[id]; ok {
			candidates = append(candidates, item)
		}
	}
	selected, err := decision.Select(conflict.PropertyKey, candidates, definition)
	if err != nil {
		return ResolveResponse{}, err
	}
	resolved, _, err := s.store.UpdateConflict(ctx, run.ID, conflict.ID, func(value *model.EvidenceConflict) error {
		if value.State == model.ConflictResolved && value.WinningEvidenceID == selected.Winner.ID && value.ResolutionMode == model.ResolutionPolicy {
			return nil
		}
		value.State, value.WinningEvidenceID, value.ResolutionMode = model.ConflictResolved, selected.Winner.ID, model.ResolutionPolicy
		value.RationaleCode, value.ResolvedAt = selected.Rationale, s.now().UTC()
		return nil
	})
	if err != nil {
		return ResolveResponse{}, err
	}
	if s.events != nil && (conflict.State != model.ConflictResolved || conflict.WinningEvidenceID != selected.Winner.ID) {
		if err = s.events.Publish(ctx, model.FusionEvent{FusionRunID: run.ID, AnalysisID: run.AnalysisID, Type: model.EventConflictResolved,
			OccurredAt: s.now().UTC(), PropertyKey: conflict.PropertyKey, ConflictID: conflict.ID, EvidenceID: selected.Winner.ID,
			ReasonCode: selected.Rationale}); err != nil {
			return ResolveResponse{}, &model.Error{Kind: model.ErrorUnavailable, Message: "conflict was resolved but its event could not be emitted", Cause: err}
		}
	}
	return ResolveResponse{Conflict: resolved, WinningEvidence: selected.Winner, RationaleCode: selected.Rationale}, nil
}

func (s *Service) Reevaluate(ctx context.Context, request DetectRequest) (ReevaluateResponse, error) {
	response, err := s.Detect(ctx, request)
	return ReevaluateResponse{DetectResponse: response}, err
}

func (s *Service) ready(ctx context.Context, runID string) error {
	if err := model.ContextError(ctx); err != nil {
		return err
	}
	if s == nil || s.store == nil || s.policies == nil {
		return model.NewError(model.ErrorInternal, "conflict dependencies are not configured")
	}
	return model.ValidateRunID(runID)
}

func normalizeProperties(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result[value] = struct{}{}
		}
	}
	return result
}

func setKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func equalIDs(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func pageStartConflict(items []model.EvidenceConflict, token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	for index, item := range items {
		if item.ID == token {
			return index + 1, nil
		}
	}
	return 0, model.NewError(model.ErrorInvalidArgument, "page_token does not belong to this result set")
}
