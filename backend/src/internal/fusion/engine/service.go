// Package engine implements the internal FusionService orchestration contract.
package engine

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/confidence"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/conflict"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/correlation"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/decision"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/store"
)

type Store interface {
	Get(context.Context, string) (model.Run, error)
	ApplyConclusions(context.Context, string, []model.FusedConclusion, []string, bool) (model.Run, error)
	SetFusionExecution(context.Context, string, model.FusionExecution) (model.Run, error)
}

type Correlator interface {
	Rebuild(context.Context, string) (correlation.RebuildResponse, error)
}

type ConflictResolver interface {
	Detect(context.Context, conflict.DetectRequest) (conflict.DetectResponse, error)
	Resolve(context.Context, conflict.ResolveRequest) (conflict.ResolveResponse, error)
}

type ConfidenceCalculator interface {
	Calculate(context.Context, confidence.CalculateRequest) (confidence.Result, error)
}

type EventSink interface {
	ConclusionsUpdated(context.Context, string, []model.FusedConclusion) error
}
type EventPublisher interface {
	Publish(context.Context, model.FusionEvent) error
}

type RunRequest struct {
	FusionRunID string
	Incremental bool
}

type RunResponse struct {
	State              model.FusionState
	ConclusionsUpdated uint64
	ConflictsDetected  uint64
}

type RecomputeRequest struct {
	FusionRunID        string
	AffectedProperties []string
}

type RecomputeResponse struct {
	State              model.FusionState
	AffectedProperties []string
	ConclusionsUpdated uint64
}

type Status struct {
	FusionRunID string
	Execution   model.FusionExecution
	Counts      model.Counts
}

type Summary struct {
	State               model.FusionState
	EvidenceCount       uint64
	ConclusionCount     uint64
	ConflictCount       uint64
	UnresolvedConflicts uint64
	SourceCoverage      map[string]bool
}

type ConclusionFilter struct {
	PropertyPrefix    string
	ResourceType      string
	ResourceID        string
	Status            commonv1.EvidenceStatus
	HasConflict       *bool
	MinimumConfidence float64
}

type ListConclusionsRequest struct {
	FusionRunID string
	Filter      ConclusionFilter
	PageSize    uint32
	PageToken   string
}

type ListConclusionsResponse struct {
	Conclusions   []model.FusedConclusion
	NextPageToken string
}

type GetConclusionRequest struct {
	FusionRunID  string
	ConclusionID string
}

type Completeness struct {
	Overall            float64
	RequiredProperties uint64
	ResolvedProperties uint64
	UnknownProperties  uint64
	MissingSources     []model.Source
}

type Service struct {
	store      Store
	correlator Correlator
	conflicts  ConflictResolver
	confidence ConfidenceCalculator
	policies   policy.Provider
	events     EventSink
	publisher  EventPublisher
	mu         sync.Mutex
	now        func() time.Time
	newID      func() (string, error)
}

func New(store Store, correlator Correlator, conflicts ConflictResolver, calculator ConfidenceCalculator, policies policy.Provider, events EventSink, publishers ...EventPublisher) *Service {
	service := &Service{
		store: store, correlator: correlator, conflicts: conflicts, confidence: calculator,
		policies: policies, events: events, now: func() time.Time { return time.Now().UTC() }, newID: model.NewConclusionID,
	}
	if len(publishers) > 0 {
		service.publisher = publishers[0]
	}
	return service
}

func (s *Service) Ready(ctx context.Context) (bool, string) {
	if err := model.ContextError(ctx); err != nil {
		return false, err.Error()
	}
	if s == nil || s.store == nil || s.correlator == nil || s.conflicts == nil || s.confidence == nil || s.policies == nil {
		return false, "Fusion execution dependencies are not configured"
	}
	return s.policies.Ready(ctx)
}

func (s *Service) Run(ctx context.Context, request RunRequest) (RunResponse, error) {
	properties, conclusions, conflicts, err := s.process(ctx, request.FusionRunID, nil, true, request.Incremental)
	_ = properties
	return RunResponse{State: stateFor(err), ConclusionsUpdated: conclusions, ConflictsDetected: conflicts}, err
}

func (s *Service) Recompute(ctx context.Context, request RecomputeRequest) (RecomputeResponse, error) {
	properties := normalizeProperties(request.AffectedProperties)
	if len(properties) == 0 {
		return RecomputeResponse{}, model.NewError(model.ErrorInvalidArgument, "affected_properties is required")
	}
	processed, conclusions, _, err := s.process(ctx, request.FusionRunID, properties, false, true)
	return RecomputeResponse{State: stateFor(err), AffectedProperties: processed, ConclusionsUpdated: conclusions}, err
}

// Schedule makes FusionService the real recomputation target used by evidence ingestion.
func (s *Service) Schedule(ctx context.Context, fusionRunID string, properties []string) error {
	_, err := s.Recompute(ctx, RecomputeRequest{FusionRunID: fusionRunID, AffectedProperties: properties})
	return err
}

func (s *Service) GetStatus(ctx context.Context, fusionRunID string) (Status, error) {
	run, err := s.get(ctx, fusionRunID)
	if err != nil {
		return Status{}, err
	}
	return Status{FusionRunID: run.ID, Execution: run.Fusion.Clone(), Counts: run.Counts}, nil
}

func (s *Service) GetSummary(ctx context.Context, fusionRunID string) (Summary, error) {
	run, err := s.get(ctx, fusionRunID)
	if err != nil {
		return Summary{}, err
	}
	var unresolved uint64
	for _, item := range run.Conflicts {
		if item.State != model.ConflictResolved {
			unresolved++
		}
	}
	coverage := map[string]bool{
		"passive": sourceComplete(run, model.SourcePacketParser) && sourceComplete(run, model.SourceFlowAnalyzer),
		"vici":    sourceComplete(run, model.SourceVICI), "xfrm": sourceComplete(run, model.SourceXFRM),
		"ml": sourceComplete(run, model.SourceMLClassifier), "security_rules": sourceComplete(run, model.SourceSecurityRule),
	}
	return Summary{
		State: run.Fusion.State, EvidenceCount: run.Counts.Evidence, ConclusionCount: run.Counts.Conclusions,
		ConflictCount: run.Counts.Conflicts, UnresolvedConflicts: unresolved, SourceCoverage: coverage,
	}, nil
}

func (s *Service) ListConclusions(ctx context.Context, request ListConclusionsRequest) (ListConclusionsResponse, error) {
	run, err := s.get(ctx, request.FusionRunID)
	if err != nil {
		return ListConclusionsResponse{}, err
	}
	request.Filter.PropertyPrefix = strings.TrimSpace(request.Filter.PropertyPrefix)
	request.Filter.ResourceType = strings.ToUpper(strings.TrimSpace(request.Filter.ResourceType))
	request.Filter.ResourceID = strings.TrimSpace(request.Filter.ResourceID)
	if (request.Filter.ResourceType == "") != (request.Filter.ResourceID == "") {
		return ListConclusionsResponse{}, model.NewError(model.ErrorInvalidArgument, "resource_type and resource_id filters must be provided together")
	}
	if request.Filter.MinimumConfidence < 0 || request.Filter.MinimumConfidence > 1 {
		return ListConclusionsResponse{}, model.NewError(model.ErrorInvalidArgument, "minimum_confidence must be within [0,1]")
	}
	if request.Filter.Status < commonv1.EvidenceStatus_EVIDENCE_STATUS_UNSPECIFIED || request.Filter.Status > commonv1.EvidenceStatus_UNKNOWN {
		return ListConclusionsResponse{}, model.NewError(model.ErrorInvalidArgument, "evidence status filter is invalid")
	}
	pageSize := int(request.PageSize)
	if pageSize == 0 {
		pageSize = 100
	}
	if pageSize > 1000 {
		return ListConclusionsResponse{}, model.NewError(model.ErrorInvalidArgument, "page_size must not exceed 1000")
	}
	if request.PageToken != "" && model.ValidateConclusionID(request.PageToken) != nil {
		return ListConclusionsResponse{}, model.NewError(model.ErrorInvalidArgument, "page_token is invalid")
	}
	items := make([]model.FusedConclusion, 0)
	for _, item := range store.SortedConclusions(run) {
		if request.Filter.PropertyPrefix != "" && !strings.HasPrefix(item.PropertyKey, request.Filter.PropertyPrefix) {
			continue
		}
		if request.Filter.ResourceType != "" && (item.ResourceType != request.Filter.ResourceType || item.ResourceID != request.Filter.ResourceID) {
			continue
		}
		if request.Filter.Status != commonv1.EvidenceStatus_EVIDENCE_STATUS_UNSPECIFIED && item.Status != request.Filter.Status {
			continue
		}
		if request.Filter.HasConflict != nil && item.HasConflict != *request.Filter.HasConflict {
			continue
		}
		if item.Confidence < request.Filter.MinimumConfidence {
			continue
		}
		items = append(items, item)
	}
	start, err := conclusionPageStart(items, request.PageToken)
	if err != nil {
		return ListConclusionsResponse{}, err
	}
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	next := ""
	if end < len(items) {
		next = items[end-1].ID
	}
	return ListConclusionsResponse{Conclusions: items[start:end], NextPageToken: next}, nil
}

func (s *Service) GetConclusion(ctx context.Context, request GetConclusionRequest) (model.FusedConclusion, error) {
	run, err := s.get(ctx, request.FusionRunID)
	if err != nil {
		return model.FusedConclusion{}, err
	}
	if err := model.ValidateConclusionID(request.ConclusionID); err != nil {
		return model.FusedConclusion{}, err
	}
	conclusion, exists := run.Conclusions[strings.TrimSpace(request.ConclusionID)]
	if !exists {
		return model.FusedConclusion{}, model.NewError(model.ErrorNotFound, "fused conclusion was not found")
	}
	return conclusion.Clone(), nil
}

func (s *Service) GetCompleteness(ctx context.Context, fusionRunID string) (Completeness, error) {
	run, err := s.get(ctx, fusionRunID)
	if err != nil {
		return Completeness{}, err
	}
	definition, err := s.policies.Resolve(ctx, run.PolicyID)
	if err != nil {
		return Completeness{}, err
	}
	resolvedProperties := make(map[string]bool)
	for _, conclusion := range run.Conclusions {
		minimum := definition.Rule(conclusion.PropertyKey).MinimumConfidence
		if minimum == 0 {
			minimum = definition.MinimumConfidence
		}
		if conclusion.Status != commonv1.EvidenceStatus_UNKNOWN && conclusion.Confidence >= minimum {
			resolvedProperties[conclusion.PropertyKey] = true
		}
	}
	var resolved uint64
	for _, property := range definition.RequiredProperties {
		if resolvedProperties[property] {
			resolved++
		}
	}
	required := uint64(len(definition.RequiredProperties))
	overall := 1.0
	if required > 0 {
		overall = float64(resolved) / float64(required)
	}
	missingSources := make([]model.Source, 0)
	for _, source := range definition.RequiredSources {
		if !sourceComplete(run, source) {
			missingSources = append(missingSources, source)
		}
	}
	sort.Slice(missingSources, func(i, j int) bool { return missingSources[i] < missingSources[j] })
	return Completeness{
		Overall: overall, RequiredProperties: required, ResolvedProperties: resolved,
		UnknownProperties: required - resolved, MissingSources: missingSources,
	}, nil
}

func (s *Service) process(ctx context.Context, runID string, affected []string, full, incremental bool) ([]string, uint64, uint64, error) {
	if err := s.ready(ctx, runID); err != nil {
		return nil, 0, 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	properties := normalizeProperties(affected)
	started := s.now().UTC()
	execution := model.FusionExecution{State: model.FusionRunning, Incremental: incremental, StartedAt: started, LastRecomputedProperties: properties}
	if _, err := s.store.SetFusionExecution(ctx, strings.TrimSpace(runID), execution); err != nil {
		return properties, 0, 0, err
	}
	processed, conclusionCount, conflictCount, err := s.compute(ctx, strings.TrimSpace(runID), properties, full)
	if err != nil {
		execution.State, execution.LastError, execution.CompletedAt = model.FusionFailed, publicMessage(err), s.now().UTC()
		_, _ = s.store.SetFusionExecution(context.Background(), strings.TrimSpace(runID), execution)
		s.publishFailure(strings.TrimSpace(runID), execution.LastError)
		return processed, conclusionCount, conflictCount, err
	}
	execution.LastRecomputedProperties = processed
	execution.State, execution.CompletedAt = model.FusionComplete, s.now().UTC()
	if _, err = s.store.SetFusionExecution(ctx, strings.TrimSpace(runID), execution); err != nil {
		execution.State, execution.LastError, execution.CompletedAt = model.FusionFailed, publicMessage(err), s.now().UTC()
		_, _ = s.store.SetFusionExecution(context.Background(), strings.TrimSpace(runID), execution)
		s.publishFailure(strings.TrimSpace(runID), execution.LastError)
		return processed, conclusionCount, conflictCount, err
	}
	return processed, conclusionCount, conflictCount, nil
}

func (s *Service) compute(ctx context.Context, runID string, properties []string, full bool) ([]string, uint64, uint64, error) {
	if _, err := s.correlator.Rebuild(ctx, runID); err != nil {
		return properties, 0, 0, err
	}
	if !full {
		run, err := s.store.Get(ctx, runID)
		if err != nil {
			return properties, 0, 0, err
		}
		properties = expandAffectedProperties(run, properties)
	}
	detected, err := s.conflicts.Detect(ctx, conflict.DetectRequest{FusionRunID: runID, AffectedProperties: properties})
	if err != nil {
		return properties, 0, 0, err
	}
	run, err := s.store.Get(ctx, runID)
	if err != nil {
		return properties, 0, detected.ConflictsFound, err
	}
	affectedSet := make(map[string]struct{}, len(properties))
	for _, property := range properties {
		affectedSet[property] = struct{}{}
	}
	for _, item := range run.Conflicts {
		if len(affectedSet) > 0 {
			if _, included := affectedSet[item.PropertyKey]; !included {
				continue
			}
		}
		if _, err = s.conflicts.Resolve(ctx, conflict.ResolveRequest{FusionRunID: runID, ConflictID: item.ID, Mode: model.ResolutionPolicy}); err != nil {
			return properties, 0, detected.ConflictsFound, err
		}
	}
	run, err = s.store.Get(ctx, runID)
	if err != nil {
		return properties, 0, detected.ConflictsFound, err
	}
	definition, err := s.policies.Resolve(ctx, run.PolicyID)
	if err != nil {
		return properties, 0, detected.ConflictsFound, err
	}
	conflictsByKey := make(map[string]model.EvidenceConflict)
	for _, item := range run.Conflicts {
		conflictsByKey[store.ConclusionKey(item.PropertyKey, item.ResourceType, item.ResourceID)] = item
	}
	groups := decision.GroupEvidence(run, affectedSet)
	conclusions := make([]model.FusedConclusion, 0, len(groups))
	for _, group := range groups {
		selected, selectErr := decision.Select(group.PropertyKey, group.Evidence, definition)
		if selectErr != nil {
			return properties, 0, detected.ConflictsFound, selectErr
		}
		quality := correlationQuality(run, group)
		calculated, calculateErr := s.confidence.Calculate(ctx, confidence.CalculateRequest{
			PolicyID: run.PolicyID, PropertyKey: group.PropertyKey, Candidates: group.Evidence,
			WinningEvidenceID: selected.Winner.ID, CorrelationQuality: &quality,
		})
		if calculateErr != nil {
			return properties, 0, detected.ConflictsFound, calculateErr
		}
		key := store.ConclusionKey(group.PropertyKey, group.ResourceType, group.ResourceID)
		id := run.ConclusionByKey[key]
		if id == "" {
			id = overlappingConclusionID(run, group)
		}
		if id == "" {
			id, err = s.newID()
			if err != nil {
				return properties, 0, detected.ConflictsFound, &model.Error{Kind: model.ErrorInternal, Message: "could not generate conclusion ID", Cause: err}
			}
		}
		evidenceIDs := make([]string, 0, len(group.Evidence))
		for _, item := range group.Evidence {
			evidenceIDs = append(evidenceIDs, item.ID)
		}
		sort.Strings(evidenceIDs)
		winningSources := uniqueSources(selected.Supporting)
		supportingEvidenceIDs := make([]string, 0, len(selected.Supporting))
		for _, item := range selected.Supporting {
			if item.ID != selected.Winner.ID {
				supportingEvidenceIDs = append(supportingEvidenceIDs, item.ID)
			}
		}
		sort.Strings(supportingEvidenceIDs)
		conflictItem, hasConflict := conflictsByKey[key]
		rationale := selected.Rationale
		if hasConflict && conflictItem.RationaleCode != "" {
			rationale = conflictItem.RationaleCode
		}
		conclusions = append(conclusions, model.FusedConclusion{
			ID: id, AnalysisID: run.AnalysisID, PropertyKey: group.PropertyKey, ResourceType: group.ResourceType, ResourceID: group.ResourceID,
			Value: selected.Winner.Value, Confidence: calculated.Confidence, Band: calculated.Band, Status: selected.Winner.Status,
			EvidenceIDs: evidenceIDs, WinningEvidenceID: selected.Winner.ID, SupportingEvidenceIDs: supportingEvidenceIDs,
			WinningSources: winningSources, HasConflict: hasConflict,
			ConflictID: conflictItem.ID, RationaleCode: rationale, Breakdown: calculated.Breakdown, ComputedAt: s.now().UTC(),
		})
	}
	updated, err := s.store.ApplyConclusions(ctx, run.ID, conclusions, properties, full)
	if err != nil {
		return properties, 0, detected.ConflictsFound, err
	}
	if s.events != nil {
		if err = s.events.ConclusionsUpdated(ctx, run.ID, conclusions); err != nil {
			return properties, uint64(len(conclusions)), detected.ConflictsFound, &model.Error{Kind: model.ErrorUnavailable, Message: "conclusions were stored but update events could not be emitted", Cause: err}
		}
	}
	if s.publisher != nil {
		for _, conclusion := range conclusions {
			eventType := model.EventConclusionCreated
			if _, exists := run.Conclusions[conclusion.ID]; exists {
				eventType = model.EventConclusionUpdated
			}
			copy := conclusion.Clone()
			for _, updateType := range []model.EventType{model.EventConfidenceUpdated, eventType} {
				if err = s.publisher.Publish(ctx, model.FusionEvent{FusionRunID: run.ID, AnalysisID: run.AnalysisID, Type: updateType,
					OccurredAt: conclusion.ComputedAt, PropertyKey: conclusion.PropertyKey, ConclusionID: conclusion.ID, ConflictID: conclusion.ConflictID,
					ReasonCode: conclusion.RationaleCode, Conclusion: &copy}); err != nil {
					return properties, uint64(len(conclusions)), detected.ConflictsFound, &model.Error{Kind: model.ErrorUnavailable, Message: "conclusions were stored but provenance events could not be emitted", Cause: err}
				}
			}
		}
		if err = s.publisher.Publish(ctx, model.FusionEvent{FusionRunID: run.ID, AnalysisID: run.AnalysisID,
			Type: model.EventFusionCompletenessUpdated, OccurredAt: s.now().UTC()}); err != nil {
			return properties, uint64(len(conclusions)), detected.ConflictsFound, &model.Error{Kind: model.ErrorUnavailable, Message: "Fusion completeness event could not be emitted", Cause: err}
		}
	}
	_ = updated
	return properties, uint64(len(conclusions)), detected.ConflictsFound, nil
}

func overlappingConclusionID(run model.Run, group decision.EvidenceGroup) string {
	evidence := make(map[string]struct{}, len(group.Evidence))
	for _, item := range group.Evidence {
		evidence[item.ID] = struct{}{}
	}
	match := ""
	for id, conclusion := range run.Conclusions {
		if conclusion.PropertyKey != group.PropertyKey {
			continue
		}
		overlaps := false
		for _, evidenceID := range conclusion.EvidenceIDs {
			if _, exists := evidence[evidenceID]; exists {
				overlaps = true
				break
			}
		}
		if !overlaps {
			continue
		}
		if match != "" {
			return ""
		}
		match = id
	}
	return match
}

func (s *Service) publishFailure(runID, reason string) {
	if s.publisher == nil {
		return
	}
	run, err := s.store.Get(context.Background(), runID)
	if err != nil {
		return
	}
	_ = s.publisher.Publish(context.Background(), model.FusionEvent{FusionRunID: run.ID, AnalysisID: run.AnalysisID,
		Type: model.EventFusionFailed, OccurredAt: s.now().UTC(), ReasonCode: reason})
}

func (s *Service) get(ctx context.Context, runID string) (model.Run, error) {
	if err := s.ready(ctx, runID); err != nil {
		return model.Run{}, err
	}
	return s.store.Get(ctx, strings.TrimSpace(runID))
}

func (s *Service) ready(ctx context.Context, runID string) error {
	if err := model.ContextError(ctx); err != nil {
		return err
	}
	if s == nil || s.store == nil || s.correlator == nil || s.conflicts == nil || s.confidence == nil || s.policies == nil {
		return model.NewError(model.ErrorInternal, "Fusion execution dependencies are not configured")
	}
	return model.ValidateRunID(runID)
}

func normalizeProperties(properties []string) []string {
	set := make(map[string]struct{}, len(properties))
	for _, property := range properties {
		if property = strings.TrimSpace(property); property != "" {
			set[property] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for property := range set {
		result = append(result, property)
	}
	sort.Strings(result)
	return result
}

// expandAffectedProperties includes properties sharing a correlation group
// with newly changed evidence. This prevents a new gateway observation from
// silently moving a resource while leaving an older conclusion on the former
// resource identity.
func expandAffectedProperties(run model.Run, properties []string) []string {
	affected := make(map[string]struct{}, len(properties))
	for _, property := range properties {
		affected[property] = struct{}{}
	}
	for _, group := range run.Correlations {
		groupAffected := false
		for _, evidenceID := range group.EvidenceIDs {
			if item, exists := run.EvidenceByID[evidenceID]; exists {
				if _, changed := affected[item.PropertyKey]; changed {
					groupAffected = true
					break
				}
			}
		}
		if !groupAffected {
			continue
		}
		for _, evidenceID := range group.EvidenceIDs {
			if item, exists := run.EvidenceByID[evidenceID]; exists {
				affected[item.PropertyKey] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(affected))
	for property := range affected {
		result = append(result, property)
	}
	sort.Strings(result)
	return result
}

func stateFor(err error) model.FusionState {
	if err != nil {
		return model.FusionFailed
	}
	return model.FusionComplete
}

func publicMessage(err error) string {
	if fusionErr, ok := err.(*model.Error); ok {
		return fusionErr.Message
	}
	return "Fusion execution failed"
}

func sourceComplete(run model.Run, source model.Source) bool {
	coverage, exists := run.SourceCoverage[source]
	return exists && coverage.State == model.SourceComplete
}

func uniqueSources(evidence []model.EvidenceItem) []model.Source {
	set := make(map[model.Source]struct{})
	for _, item := range evidence {
		set[item.Source] = struct{}{}
	}
	result := make([]model.Source, 0, len(set))
	for source := range set {
		result = append(result, source)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func correlationQuality(run model.Run, group decision.EvidenceGroup) float64 {
	for _, correlation := range run.Correlations {
		if correlation.ResourceType == group.ResourceType && correlation.ResourceID == group.ResourceID {
			if len(correlation.EvidenceIDs) > 1 {
				return 1
			}
			return .85
		}
	}
	return .70
}

func conclusionPageStart(items []model.FusedConclusion, token string) (int, error) {
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
