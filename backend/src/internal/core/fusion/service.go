// Package fusion is a thin Core facade over the internal Fusion runtime.
package fusion

import (
	"context"
	"fmt"
	"strings"

	fusionv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/fusion"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/protocolread"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	engine "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/engine"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/ingest"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/provenance"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Service struct {
	resolver   protocolread.RunResolver
	engine     *engine.Service
	provenance *provenance.Service
	ingest     *ingest.Service
}

func New(resolver protocolread.RunResolver, engineService *engine.Service, provenanceService *provenance.Service, evidence *ingest.Service) *Service {
	return &Service{resolver: resolver, engine: engineService, provenance: provenanceService, ingest: evidence}
}
func (s *Service) runID(ctx context.Context, analysisID string) (string, error) {
	if s == nil || s.resolver == nil || s.engine == nil || s.provenance == nil {
		return "", shared.NewError(shared.Internal, "", "fusion orchestration service is not configured")
	}
	if strings.TrimSpace(analysisID) == "" {
		return "", shared.NewError(shared.InvalidArgument, "", "analysis_id is required")
	}
	return s.resolver.FusionRunID(ctx, analysisID)
}
func (s *Service) Run(ctx context.Context, analysisID string, options *fusionv1.RunFusionRequest) (*fusionv1.RunFusionResponse, error) {
	id, err := s.runID(ctx, analysisID)
	if err != nil {
		return nil, err
	}
	if options == nil {
		return nil, shared.NewError(shared.InvalidArgument, "", "request is required")
	}
	if s.ingest == nil {
		return nil, shared.NewError(shared.Internal, "", "fusion evidence service is not configured")
	}
	for source, enabled := range map[model.Source]bool{model.SourcePacketParser: options.GetIncludePassive(), model.SourceFlowAnalyzer: options.GetIncludePassive(), model.SourceVICI: options.GetIncludeVici(), model.SourceXFRM: options.GetIncludeXfrm(), model.SourceMLClassifier: options.GetIncludeMl(), model.SourceSecurityRule: options.GetIncludeSecurityRules()} {
		if !enabled {
			if _, err := s.ingest.MarkSourceUnavailable(ctx, ingest.MarkSourceUnavailableRequest{FusionRunID: id, Source: source, ReasonCode: "DISABLED_BY_REQUEST"}); err != nil {
				return nil, err
			}
		}
	}
	value, err := s.engine.Run(ctx, engine.RunRequest{FusionRunID: id})
	return &fusionv1.RunFusionResponse{FusionRunId: id, State: string(value.State)}, err
}
func (s *Service) Status(ctx context.Context, analysisID string) (*fusionv1.FusionStatus, error) {
	id, err := s.runID(ctx, analysisID)
	if err != nil {
		return nil, err
	}
	value, err := s.engine.GetStatus(ctx, id)
	if err != nil {
		return nil, err
	}
	return &fusionv1.FusionStatus{FusionRunId: id, State: string(value.Execution.State), EvidenceCount: value.Counts.Evidence, ConclusionCount: value.Counts.Conclusions, ConflictCount: value.Counts.Conflicts, FailureReason: value.Execution.LastError}, nil
}
func (s *Service) Summary(ctx context.Context, analysisID string) (*fusionv1.FusionSummary, error) {
	id, err := s.runID(ctx, analysisID)
	if err != nil {
		return nil, err
	}
	value, err := s.engine.GetSummary(ctx, id)
	if err != nil {
		return nil, err
	}
	out := &fusionv1.FusionSummary{FusionRunId: id, State: string(value.State), EvidenceCount: value.EvidenceCount, ConclusionCount: value.ConclusionCount, UnresolvedConflicts: value.UnresolvedConflicts}
	for source, complete := range value.SourceCoverage {
		if !complete {
			out.UnavailableSources = append(out.UnavailableSources, source)
		}
	}
	return out, nil
}
func (s *Service) List(ctx context.Context, analysisID string, request *fusionv1.ListFusedConclusionsRequest) ([]*fusionv1.FusedConclusion, string, error) {
	id, err := s.runID(ctx, analysisID)
	if err != nil {
		return nil, "", err
	}
	value, err := s.engine.ListConclusions(ctx, engine.ListConclusionsRequest{FusionRunID: id, Filter: engine.ConclusionFilter{PropertyPrefix: request.GetPropertyKey(), ResourceType: request.GetResourceType(), ResourceID: request.GetResourceId()}, PageSize: request.GetPageSize(), PageToken: request.GetPageToken()})
	if err != nil {
		return nil, "", err
	}
	out := make([]*fusionv1.FusedConclusion, 0, len(value.Conclusions))
	for _, item := range value.Conclusions {
		out = append(out, view(item))
	}
	return out, value.NextPageToken, nil
}
func (s *Service) Get(ctx context.Context, analysisID, conclusionID string) (*fusionv1.FusedConclusion, error) {
	id, err := s.runID(ctx, analysisID)
	if err != nil {
		return nil, err
	}
	value, err := s.engine.GetConclusion(ctx, engine.GetConclusionRequest{FusionRunID: id, ConclusionID: conclusionID})
	if err != nil {
		return nil, err
	}
	return view(value), nil
}
func (s *Service) Chain(ctx context.Context, analysisID, conclusionID string) (*fusionv1.EvidenceChain, error) {
	id, err := s.runID(ctx, analysisID)
	if err != nil {
		return nil, err
	}
	value, err := s.provenance.GetEvidenceChain(ctx, provenance.ConclusionRequest{FusionRunID: id, ConclusionID: conclusionID})
	if err != nil {
		return nil, err
	}
	return &fusionv1.EvidenceChain{Conclusion: view(value.Conclusion), WinningEvidence: evidenceViews(value.WinningEvidence), SupportingEvidence: evidenceViews(value.SupportingEvidence), ConflictingEvidence: evidenceViews(value.ConflictingEvidence)}, nil
}
func (s *Service) Recompute(ctx context.Context, analysisID string, properties []string) (*fusionv1.RecomputeFusionResponse, error) {
	id, err := s.runID(ctx, analysisID)
	if err != nil {
		return nil, err
	}
	value, err := s.engine.Recompute(ctx, engine.RecomputeRequest{FusionRunID: id, AffectedProperties: properties})
	return &fusionv1.RecomputeFusionResponse{FusionRunId: id, State: string(value.State), ConclusionsUpdated: value.ConclusionsUpdated, AffectedProperties: value.AffectedProperties}, err
}
func view(value model.FusedConclusion) *fusionv1.FusedConclusion {
	out := &fusionv1.FusedConclusion{ConclusionId: value.ID, PropertyKey: value.PropertyKey, ResourceType: value.ResourceType, ResourceId: value.ResourceID, Confidence: value.Confidence, EvidenceStatus: value.Status, ConflictId: value.ConflictID, RationaleCode: value.RationaleCode, ComputedAt: timestamppb.New(value.ComputedAt)}
	if value.Value != nil {
		out.Value = fmt.Sprint(value.Value.AsInterface())
	}
	for _, source := range value.WinningSources {
		out.WinningSources = append(out.WinningSources, string(source))
	}
	return out
}
func evidenceViews(values []model.EvidenceItem) []*fusionv1.EvidenceReference {
	out := make([]*fusionv1.EvidenceReference, 0, len(values))
	for _, v := range values {
		out = append(out, &fusionv1.EvidenceReference{EvidenceId: v.ID, Source: string(v.Source), PropertyKey: v.PropertyKey, Value: fmt.Sprint(v.Value.AsInterface()), EvidenceStatus: v.Status, Confidence: v.Confidence})
	}
	return out
}
