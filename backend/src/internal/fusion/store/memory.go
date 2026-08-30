// Package store owns the concurrency-safe in-memory state for Fusion v1.
package store

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
)

type Memory struct {
	mu         sync.RWMutex
	runs       map[string]model.Run
	byAnalysis map[string]string
}

func NewMemory() *Memory {
	return &Memory{runs: make(map[string]model.Run), byAnalysis: make(map[string]string)}
}

func (s *Memory) Ready(context.Context) (bool, string) {
	if s == nil {
		return false, "in-memory evidence store is not configured"
	}
	return true, ""
}

func (s *Memory) Create(ctx context.Context, run model.Run) (model.Run, error) {
	if err := model.ContextError(ctx); err != nil {
		return model.Run{}, err
	}
	if s == nil {
		return model.Run{}, model.NewError(model.ErrorInternal, "in-memory Fusion store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byAnalysis[run.AnalysisID]; exists {
		return model.Run{}, model.NewError(model.ErrorAlreadyExists, "a Fusion run already exists for this analysis")
	}
	if _, exists := s.runs[run.ID]; exists {
		return model.Run{}, model.NewError(model.ErrorAlreadyExists, "Fusion run already exists")
	}
	s.runs[run.ID] = run.Clone()
	s.byAnalysis[run.AnalysisID] = run.ID
	return run.Clone(), nil
}

func (s *Memory) Get(ctx context.Context, id string) (model.Run, error) {
	if err := model.ContextError(ctx); err != nil {
		return model.Run{}, err
	}
	if s == nil {
		return model.Run{}, model.NewError(model.ErrorInternal, "in-memory Fusion store is not configured")
	}
	s.mu.RLock()
	run, exists := s.runs[id]
	s.mu.RUnlock()
	if !exists {
		return model.Run{}, model.NewError(model.ErrorNotFound, "Fusion run was not found")
	}
	return run.Clone(), nil
}

func (s *Memory) Update(ctx context.Context, id string, mutate func(*model.Run) error) (model.Run, error) {
	if err := model.ContextError(ctx); err != nil {
		return model.Run{}, err
	}
	if s == nil {
		return model.Run{}, model.NewError(model.ErrorInternal, "in-memory Fusion store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run, exists := s.runs[id]
	if !exists {
		return model.Run{}, model.NewError(model.ErrorNotFound, "Fusion run was not found")
	}
	if err := mutate(&run); err != nil {
		return model.Run{}, err
	}
	run.UpdatedAt = time.Now().UTC()
	s.runs[id] = run.Clone()
	return run.Clone(), nil
}

func (s *Memory) Delete(ctx context.Context, id string) (model.Run, error) {
	if err := model.ContextError(ctx); err != nil {
		return model.Run{}, err
	}
	if s == nil {
		return model.Run{}, model.NewError(model.ErrorInternal, "in-memory Fusion store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run, exists := s.runs[id]
	if !exists {
		return model.Run{}, model.NewError(model.ErrorNotFound, "Fusion run was not found")
	}
	delete(s.runs, id)
	delete(s.byAnalysis, run.AnalysisID)
	return run.Clone(), nil
}

// SetSourceCoverage is the mutation seam used by the future EvidenceIngestService.
func (s *Memory) SetSourceCoverage(ctx context.Context, id string, source model.Source, state model.SourceState, reason string) (model.Run, error) {
	if !source.Valid() {
		return model.Run{}, model.NewError(model.ErrorInvalidArgument, "evidence source is invalid")
	}
	if state != model.SourcePending && !state.Terminal() {
		return model.Run{}, model.NewError(model.ErrorInvalidArgument, "source state is invalid")
	}
	return s.Update(ctx, id, func(run *model.Run) error {
		if run.State != model.RunStateActive {
			return model.NewError(model.ErrorFailedPrecondition, "source coverage can only change on an active Fusion run")
		}
		if run.SourceCoverage == nil {
			run.SourceCoverage = make(map[model.Source]model.SourceCoverage)
		}
		reason = strings.TrimSpace(reason)
		if state == model.SourceUnavailable && reason == "" {
			return model.NewError(model.ErrorInvalidArgument, "reason_code is required when a source is unavailable")
		}
		if existing, ok := run.SourceCoverage[source]; ok && existing.State.Terminal() {
			if existing.State == state && existing.ReasonCode == reason {
				return nil
			}
			return model.NewError(model.ErrorFailedPrecondition, "terminal source coverage cannot be changed")
		}
		run.SourceCoverage[source] = model.SourceCoverage{Source: source, State: state, ReasonCode: reason, UpdatedAt: time.Now().UTC()}
		return nil
	})
}

func (s *Memory) AddEvidence(ctx context.Context, id string, items []model.EvidenceItem) (model.Run, error) {
	if len(items) == 0 {
		return model.Run{}, model.NewError(model.ErrorInvalidArgument, "at least one evidence item is required")
	}
	return s.Update(ctx, id, func(run *model.Run) error {
		if run.State != model.RunStateActive {
			return model.NewError(model.ErrorFailedPrecondition, "evidence can only be added to an active Fusion run")
		}
		if run.EvidenceByID == nil {
			run.EvidenceByID = make(map[string]model.EvidenceItem)
		}
		if run.EvidenceByProperty == nil {
			run.EvidenceByProperty = make(map[string][]string)
		}
		if run.EvidenceByResource == nil {
			run.EvidenceByResource = make(map[string][]string)
		}
		if run.SourceCoverage == nil {
			run.SourceCoverage = make(map[model.Source]model.SourceCoverage)
		}
		for _, item := range items {
			if item.AnalysisID != run.AnalysisID {
				return model.NewError(model.ErrorFailedPrecondition, "evidence belongs to a different analysis")
			}
			if err := model.ValidateEvidenceID(item.ID); err != nil {
				return err
			}
			if coverage, exists := run.SourceCoverage[item.Source]; exists && coverage.State.Terminal() {
				return model.NewError(model.ErrorFailedPrecondition, "evidence source has already reached a terminal state")
			}
			if _, exists := run.EvidenceByID[item.ID]; exists {
				return model.NewError(model.ErrorAlreadyExists, "evidence ID already exists")
			}
		}
		for _, item := range items {
			run.EvidenceByID[item.ID] = item.Clone()
			run.EvidenceByProperty[item.PropertyKey] = append(run.EvidenceByProperty[item.PropertyKey], item.ID)
			resourceKey := ResourceKey(item.ResourceType, item.ResourceID)
			run.EvidenceByResource[resourceKey] = append(run.EvidenceByResource[resourceKey], item.ID)
			if _, exists := run.SourceCoverage[item.Source]; !exists {
				run.SourceCoverage[item.Source] = model.SourceCoverage{Source: item.Source, State: model.SourcePending, UpdatedAt: time.Now().UTC()}
			}
		}
		run.Counts.Evidence = uint64(len(run.EvidenceByID))
		run.Fusion = model.FusionExecution{State: model.FusionIdle}
		return nil
	})
}

func (s *Memory) RemoveEvidence(ctx context.Context, runID, evidenceID string) (model.EvidenceItem, model.Run, error) {
	var removed model.EvidenceItem
	run, err := s.Update(ctx, runID, func(run *model.Run) error {
		if run.State != model.RunStateActive {
			return model.NewError(model.ErrorFailedPrecondition, "evidence can only be removed from an active Fusion run")
		}
		item, exists := run.EvidenceByID[evidenceID]
		if !exists {
			return model.NewError(model.ErrorNotFound, "evidence item was not found")
		}
		removed = item.Clone()
		delete(run.EvidenceByID, evidenceID)
		run.EvidenceByProperty[item.PropertyKey] = removeID(run.EvidenceByProperty[item.PropertyKey], evidenceID)
		if len(run.EvidenceByProperty[item.PropertyKey]) == 0 {
			delete(run.EvidenceByProperty, item.PropertyKey)
		}
		resourceKey := ResourceKey(item.ResourceType, item.ResourceID)
		run.EvidenceByResource[resourceKey] = removeID(run.EvidenceByResource[resourceKey], evidenceID)
		if len(run.EvidenceByResource[resourceKey]) == 0 {
			delete(run.EvidenceByResource, resourceKey)
		}
		for groupID, group := range run.Correlations {
			for _, memberID := range group.EvidenceIDs {
				if memberID == evidenceID {
					delete(run.Correlations, groupID)
					break
				}
			}
		}
		for conflictID, conflict := range run.Conflicts {
			if containsID(conflict.CandidateEvidenceIDs, evidenceID) {
				delete(run.Conflicts, conflictID)
			}
		}
		for conclusionID, conclusion := range run.Conclusions {
			if containsID(conclusion.EvidenceIDs, evidenceID) {
				delete(run.Conclusions, conclusionID)
				delete(run.ConclusionByKey, ConclusionKey(conclusion.PropertyKey, conclusion.ResourceType, conclusion.ResourceID))
			}
		}
		run.Counts.Evidence = uint64(len(run.EvidenceByID))
		run.Counts.Conflicts = uint64(len(run.Conflicts))
		run.Counts.Conclusions = uint64(len(run.Conclusions))
		run.Fusion = model.FusionExecution{State: model.FusionIdle}
		return nil
	})
	return removed, run, err
}

func (s *Memory) ReplaceConflicts(ctx context.Context, runID string, conflicts []model.EvidenceConflict, affectedProperties []string, full bool) (model.Run, error) {
	return s.Update(ctx, runID, func(run *model.Run) error {
		if run.State != model.RunStateActive {
			return model.NewError(model.ErrorFailedPrecondition, "conflicts can only change on an active Fusion run")
		}
		if full || run.Conflicts == nil {
			run.Conflicts = make(map[string]model.EvidenceConflict)
		} else {
			affected := stringSet(affectedProperties)
			for id, conflict := range run.Conflicts {
				if _, replace := affected[conflict.PropertyKey]; replace {
					delete(run.Conflicts, id)
				}
			}
		}
		for _, conflict := range conflicts {
			if err := model.ValidateConflictID(conflict.ID); err != nil {
				return err
			}
			for _, evidenceID := range conflict.CandidateEvidenceIDs {
				if _, exists := run.EvidenceByID[evidenceID]; !exists {
					return model.NewError(model.ErrorFailedPrecondition, "evidence changed while conflicts were being computed")
				}
			}
			run.Conflicts[conflict.ID] = conflict.Clone()
		}
		run.Counts.Conflicts = uint64(len(run.Conflicts))
		return nil
	})
}

func (s *Memory) UpdateConflict(ctx context.Context, runID, conflictID string, mutate func(*model.EvidenceConflict) error) (model.EvidenceConflict, model.Run, error) {
	var result model.EvidenceConflict
	run, err := s.Update(ctx, runID, func(run *model.Run) error {
		if run.State != model.RunStateActive {
			return model.NewError(model.ErrorFailedPrecondition, "conflicts can only change on an active Fusion run")
		}
		conflict, exists := run.Conflicts[conflictID]
		if !exists {
			return model.NewError(model.ErrorNotFound, "evidence conflict was not found")
		}
		if err := mutate(&conflict); err != nil {
			return err
		}
		conflict.UpdatedAt = time.Now().UTC()
		run.Conflicts[conflictID] = conflict.Clone()
		result = conflict.Clone()
		return nil
	})
	return result, run, err
}

func (s *Memory) ApplyConclusions(ctx context.Context, runID string, conclusions []model.FusedConclusion, affectedProperties []string, full bool) (model.Run, error) {
	return s.Update(ctx, runID, func(run *model.Run) error {
		if run.State != model.RunStateActive {
			return model.NewError(model.ErrorFailedPrecondition, "conclusions can only change on an active Fusion run")
		}
		if full || run.Conclusions == nil {
			run.Conclusions = make(map[string]model.FusedConclusion)
			run.ConclusionByKey = make(map[string]string)
		} else {
			affected := stringSet(affectedProperties)
			for id, conclusion := range run.Conclusions {
				if _, replace := affected[conclusion.PropertyKey]; replace {
					delete(run.Conclusions, id)
					delete(run.ConclusionByKey, ConclusionKey(conclusion.PropertyKey, conclusion.ResourceType, conclusion.ResourceID))
				}
			}
		}
		for _, conclusion := range conclusions {
			if err := model.ValidateConclusionID(conclusion.ID); err != nil {
				return err
			}
			for _, evidenceID := range conclusion.EvidenceIDs {
				if _, exists := run.EvidenceByID[evidenceID]; !exists {
					return model.NewError(model.ErrorFailedPrecondition, "evidence changed while conclusions were being computed")
				}
			}
			if conclusion.ConflictID != "" {
				if _, exists := run.Conflicts[conclusion.ConflictID]; !exists {
					return model.NewError(model.ErrorFailedPrecondition, "conclusion references an unknown conflict")
				}
			}
			key := ConclusionKey(conclusion.PropertyKey, conclusion.ResourceType, conclusion.ResourceID)
			if existingID, exists := run.ConclusionByKey[key]; exists && existingID != conclusion.ID {
				return model.NewError(model.ErrorAlreadyExists, "duplicate conclusion key")
			}
			run.Conclusions[conclusion.ID] = conclusion.Clone()
			run.ConclusionByKey[key] = conclusion.ID
		}
		run.Counts.Conclusions = uint64(len(run.Conclusions))
		return nil
	})
}

func (s *Memory) SetFusionExecution(ctx context.Context, runID string, execution model.FusionExecution) (model.Run, error) {
	return s.Update(ctx, runID, func(run *model.Run) error {
		if run.State != model.RunStateActive {
			return model.NewError(model.ErrorFailedPrecondition, "Fusion execution requires an active run")
		}
		run.Fusion = execution.Clone()
		return nil
	})
}

func (s *Memory) ReplaceCorrelations(ctx context.Context, runID string, groups []model.CorrelationGroup) (model.Run, error) {
	return s.Update(ctx, runID, func(run *model.Run) error {
		if run.State != model.RunStateActive {
			return model.NewError(model.ErrorFailedPrecondition, "correlations can only change on an active Fusion run")
		}
		run.Correlations = make(map[string]model.CorrelationGroup, len(groups))
		members := make(map[string]struct{})
		for _, group := range groups {
			if err := model.ValidateCorrelationID(group.ID); err != nil {
				return err
			}
			if _, exists := run.Correlations[group.ID]; exists {
				return model.NewError(model.ErrorAlreadyExists, "duplicate correlation group ID")
			}
			for _, evidenceID := range group.EvidenceIDs {
				if _, exists := run.EvidenceByID[evidenceID]; !exists {
					return model.NewError(model.ErrorFailedPrecondition, "evidence changed while correlations were being computed")
				}
				if _, exists := members[evidenceID]; exists {
					return model.NewError(model.ErrorInternal, "evidence item appears in multiple correlation groups")
				}
				members[evidenceID] = struct{}{}
			}
			run.Correlations[group.ID] = group.Clone()
		}
		return nil
	})
}

func ResourceKey(resourceType, resourceID string) string {
	return strings.ToUpper(strings.TrimSpace(resourceType)) + "\x00" + strings.TrimSpace(resourceID)
}

func removeID(ids []string, target string) []string {
	result := ids[:0]
	for _, id := range ids {
		if id != target {
			result = append(result, id)
		}
	}
	return result
}

func containsID(ids []string, target string) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func ConclusionKey(property, resourceType, resourceID string) string {
	return property + "\x00" + strings.ToUpper(resourceType) + "\x00" + resourceID
}

func SortedEvidence(run model.Run) []model.EvidenceItem {
	items := make([]model.EvidenceItem, 0, len(run.EvidenceByID))
	for _, item := range run.EvidenceByID {
		items = append(items, item.Clone())
	}
	sort.Slice(items, func(i, j int) bool {
		if !items[i].ObservedAt.Equal(items[j].ObservedAt) {
			return items[i].ObservedAt.Before(items[j].ObservedAt)
		}
		return items[i].ID < items[j].ID
	})
	return items
}

func SortedConflicts(run model.Run) []model.EvidenceConflict {
	items := make([]model.EvidenceConflict, 0, len(run.Conflicts))
	for _, item := range run.Conflicts {
		items = append(items, item.Clone())
	}
	sort.Slice(items, func(i, j int) bool {
		left := ConclusionKey(items[i].PropertyKey, items[i].ResourceType, items[i].ResourceID) + "\x00" + items[i].ID
		right := ConclusionKey(items[j].PropertyKey, items[j].ResourceType, items[j].ResourceID) + "\x00" + items[j].ID
		return left < right
	})
	return items
}

func SortedConclusions(run model.Run) []model.FusedConclusion {
	items := make([]model.FusedConclusion, 0, len(run.Conclusions))
	for _, item := range run.Conclusions {
		items = append(items, item.Clone())
	}
	sort.Slice(items, func(i, j int) bool {
		left := ConclusionKey(items[i].PropertyKey, items[i].ResourceType, items[i].ResourceID) + "\x00" + items[i].ID
		right := ConclusionKey(items[j].PropertyKey, items[j].ResourceType, items[j].ResourceID) + "\x00" + items[j].ID
		return left < right
	})
	return items
}

// SetCounts lets later evidence/conflict/conclusion modules publish their
// authoritative counts without the session service maintaining shadow state.
func (s *Memory) SetCounts(ctx context.Context, id string, counts model.Counts) (model.Run, error) {
	return s.Update(ctx, id, func(run *model.Run) error {
		if run.State != model.RunStateActive {
			return model.NewError(model.ErrorFailedPrecondition, "counts can only change on an active Fusion run")
		}
		counts.Evidence = uint64(len(run.EvidenceByID))
		run.Counts = counts
		return nil
	})
}
