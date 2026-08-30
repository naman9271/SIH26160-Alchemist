// Package provenance implements deterministic explanation and lineage queries.
package provenance

import (
	"context"
	"sort"
	"strings"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/decision"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/event"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
)

type Store interface {
	Get(context.Context, string) (model.Run, error)
}
type TimelineStore interface {
	History(context.Context, event.HistoryRequest) ([]model.FusionEvent, error)
}

type ConclusionRequest struct{ FusionRunID, ConclusionID string }

type SourceReference struct {
	EvidenceID string
	Source     model.Source
	Reference  string
}
type EvidenceChain struct {
	Conclusion          model.FusedConclusion
	WinningEvidence     []model.EvidenceItem
	SupportingEvidence  []model.EvidenceItem
	ConflictingEvidence []model.EvidenceItem
	SourceReferences    []SourceReference
}
type DecisionExplanation struct {
	RationaleCode       string
	Summary             string
	WinningEvidenceIDs  []string
	RejectedEvidenceIDs []string
}
type SourceContribution struct {
	ConclusionID  string
	Contributions map[model.Source]float64
}
type TimelineEntry struct {
	Sequence    uint64
	OccurredAt  time.Time
	Type        model.EventType
	PropertyKey string
	EvidenceID  string
	Conclusion  *model.FusedConclusion
}
type FusionTimeline struct {
	ConclusionID string
	Entries      []TimelineEntry
}

type Service struct {
	store    Store
	policies policy.Provider
	timeline TimelineStore
}

func New(store Store, policies policy.Provider, timeline TimelineStore) *Service {
	return &Service{store: store, policies: policies, timeline: timeline}
}

func (s *Service) GetEvidenceChain(ctx context.Context, request ConclusionRequest) (EvidenceChain, error) {
	run, conclusion, err := s.get(ctx, request)
	if err != nil {
		return EvidenceChain{}, err
	}
	winningID := conclusion.WinningEvidenceID
	if conclusion.ConflictID != "" {
		if conflict, exists := run.Conflicts[conclusion.ConflictID]; exists && winningID == "" {
			winningID = conflict.WinningEvidenceID
		}
	}
	matching := make([]model.EvidenceItem, 0)
	conflicting := make([]model.EvidenceItem, 0)
	references := make([]SourceReference, 0)
	for _, id := range conclusion.EvidenceIDs {
		item, exists := run.EvidenceByID[id]
		if !exists {
			continue
		}
		if item.SourceReference != "" {
			references = append(references, SourceReference{EvidenceID: item.ID, Source: item.Source, Reference: item.SourceReference})
		}
		if item.Status != commonv1.EvidenceStatus_UNKNOWN && decision.CanonicalValue(item) == canonicalConclusion(conclusion) {
			matching = append(matching, item.Clone())
		} else {
			conflicting = append(conflicting, item.Clone())
		}
	}
	sortEvidence(matching)
	sortEvidence(conflicting)
	if winningID == "" && len(matching) > 0 {
		winningID = matching[0].ID
	}
	winners, supporting := make([]model.EvidenceItem, 0, 1), make([]model.EvidenceItem, 0)
	for _, item := range matching {
		if item.ID == winningID {
			winners = append(winners, item)
		} else {
			supporting = append(supporting, item)
		}
	}
	if len(winners) == 0 && len(matching) > 0 {
		winners, supporting = matching[:1], matching[1:]
	}
	sort.Slice(references, func(i, j int) bool { return references[i].EvidenceID < references[j].EvidenceID })
	return EvidenceChain{Conclusion: conclusion, WinningEvidence: winners, SupportingEvidence: supporting, ConflictingEvidence: conflicting, SourceReferences: references}, nil
}

func (s *Service) ExplainDecision(ctx context.Context, request ConclusionRequest) (DecisionExplanation, error) {
	chain, err := s.GetEvidenceChain(ctx, request)
	if err != nil {
		return DecisionExplanation{}, err
	}
	winning := ids(chain.WinningEvidence, chain.SupportingEvidence)
	rejected := ids(chain.ConflictingEvidence)
	return DecisionExplanation{RationaleCode: chain.Conclusion.RationaleCode, Summary: rationaleSummary(chain.Conclusion.RationaleCode), WinningEvidenceIDs: winning, RejectedEvidenceIDs: rejected}, nil
}

func (s *Service) GetSourceContribution(ctx context.Context, request ConclusionRequest) (SourceContribution, error) {
	run, conclusion, err := s.get(ctx, request)
	if err != nil {
		return SourceContribution{}, err
	}
	definition, err := s.policies.Resolve(ctx, run.PolicyID)
	if err != nil {
		return SourceContribution{}, err
	}
	raw := make(map[model.Source]float64)
	var total float64
	for _, id := range conclusion.EvidenceIDs {
		item, exists := run.EvidenceByID[id]
		if !exists {
			continue
		}
		trust, exists := definition.SourceTrust[item.Source]
		if !exists {
			trust = .5
		}
		weight := trust * item.Confidence * statusWeight(item.Status)
		raw[item.Source] += weight
		total += weight
	}
	if total > 0 {
		for source, value := range raw {
			raw[source] = value / total
		}
	}
	return SourceContribution{ConclusionID: conclusion.ID, Contributions: raw}, nil
}

func (s *Service) GetTimeline(ctx context.Context, request ConclusionRequest) (FusionTimeline, error) {
	_, conclusion, err := s.get(ctx, request)
	if err != nil {
		return FusionTimeline{}, err
	}
	if s.timeline == nil {
		return FusionTimeline{}, model.NewError(model.ErrorUnavailable, "Fusion timeline store is not configured")
	}
	events, err := s.timeline.History(ctx, event.HistoryRequest{FusionRunID: request.FusionRunID, PropertyKey: conclusion.PropertyKey})
	if err != nil {
		return FusionTimeline{}, err
	}
	entries := make([]TimelineEntry, 0, len(events))
	for _, item := range events {
		if item.ConclusionID != "" && item.ConclusionID != conclusion.ID {
			continue
		}
		entry := TimelineEntry{Sequence: item.Sequence, OccurredAt: item.OccurredAt, Type: item.Type, PropertyKey: item.PropertyKey, EvidenceID: item.EvidenceID}
		if item.Conclusion != nil {
			value := item.Conclusion.Clone()
			entry.Conclusion = &value
		}
		entries = append(entries, entry)
	}
	return FusionTimeline{ConclusionID: conclusion.ID, Entries: entries}, nil
}

func (s *Service) get(ctx context.Context, request ConclusionRequest) (model.Run, model.FusedConclusion, error) {
	if err := model.ContextError(ctx); err != nil {
		return model.Run{}, model.FusedConclusion{}, err
	}
	if s == nil || s.store == nil || s.policies == nil {
		return model.Run{}, model.FusedConclusion{}, model.NewError(model.ErrorInternal, "provenance dependencies are not configured")
	}
	if err := model.ValidateRunID(request.FusionRunID); err != nil {
		return model.Run{}, model.FusedConclusion{}, err
	}
	if err := model.ValidateConclusionID(request.ConclusionID); err != nil {
		return model.Run{}, model.FusedConclusion{}, err
	}
	run, err := s.store.Get(ctx, strings.TrimSpace(request.FusionRunID))
	if err != nil {
		return model.Run{}, model.FusedConclusion{}, err
	}
	conclusion, exists := run.Conclusions[strings.TrimSpace(request.ConclusionID)]
	if !exists {
		return model.Run{}, model.FusedConclusion{}, model.NewError(model.ErrorNotFound, "fused conclusion was not found")
	}
	return run, conclusion.Clone(), nil
}

func canonicalConclusion(conclusion model.FusedConclusion) string {
	return decision.CanonicalValue(model.EvidenceItem{Value: conclusion.Value})
}
func sortEvidence(items []model.EvidenceItem) {
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
}
func ids(groups ...[]model.EvidenceItem) []string {
	result := make([]string, 0)
	for _, group := range groups {
		for _, item := range group {
			result = append(result, item.ID)
		}
	}
	sort.Strings(result)
	return result
}
func statusWeight(status commonv1.EvidenceStatus) float64 {
	switch status {
	case commonv1.EvidenceStatus_VERIFIED_GATEWAY:
		return 1
	case commonv1.EvidenceStatus_OBSERVED:
		return .85
	case commonv1.EvidenceStatus_DERIVED:
		return .65
	case commonv1.EvidenceStatus_INFERRED:
		return .5
	default:
		return .1
	}
}
func rationaleSummary(code string) string {
	switch code {
	case "VERIFIED_OVERRIDES_DERIVED":
		return "Gateway-verified evidence was selected over a passive derived value."
	case "VERIFIED_GATEWAY_PRECEDENCE":
		return "Gateway-verified evidence was selected over lower-status evidence."
	case "PROPERTY_SOURCE_PRECEDENCE":
		return "The property-specific source precedence selected the winning evidence."
	case "BEST_SUPPORTED_EVIDENCE":
		return "The best-supported eligible evidence was selected deterministically."
	default:
		return "The configured Fusion policy selected the winning evidence deterministically."
	}
}
