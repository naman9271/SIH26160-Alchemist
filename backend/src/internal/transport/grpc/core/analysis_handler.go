package core

import (
	"context"
	analysisv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/analysis"
	coreanalysis "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/analysis"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type AnalysisHandler struct {
	analysisv1.UnimplementedAnalysisServiceServer
	service *coreanalysis.Service
}

func NewAnalysisHandler(service *coreanalysis.Service) *AnalysisHandler {
	return &AnalysisHandler{service: service}
}
func (h *AnalysisHandler) valid() error {
	if h == nil || h.service == nil {
		return shared.NewError(shared.Internal, "", "analysis service is not configured")
	}
	return nil
}
func (h *AnalysisHandler) Start(ctx context.Context, r *analysisv1.StartAnalysisRequest) (*analysisv1.StartAnalysisResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Start(ctx, r.GetSourceId(), r.GetMode(), r.GetPolicyId(), r.GetOptions())
	return &analysisv1.StartAnalysisResponse{AnalysisId: v.ID, State: v.State}, shared.ToGRPC(e)
}
func (h *AnalysisHandler) Cancel(ctx context.Context, r *analysisv1.CancelAnalysisRequest) (*analysisv1.CancelAnalysisResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Cancel(ctx, r.GetAnalysisId())
	return &analysisv1.CancelAnalysisResponse{AnalysisId: v.ID, State: v.State}, shared.ToGRPC(e)
}
func (h *AnalysisHandler) Get(ctx context.Context, r *analysisv1.GetAnalysisRequest) (*analysisv1.Analysis, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Get(ctx, r.GetAnalysisId())
	return analysis(v), shared.ToGRPC(e)
}
func (h *AnalysisHandler) GetProgress(ctx context.Context, r *analysisv1.GetAnalysisProgressRequest) (*analysisv1.AnalysisProgress, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Progress(ctx, r.GetAnalysisId())
	return &analysisv1.AnalysisProgress{AnalysisId: v.ID, Stage: v.Stage, Percent: progress(v.Stage)}, shared.ToGRPC(e)
}
func (h *AnalysisHandler) GetSummary(ctx context.Context, r *analysisv1.GetAnalysisSummaryRequest) (*analysisv1.AnalysisSummary, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Get(ctx, r.GetAnalysisId())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	state := analysisv1.AvailabilityState_UNAVAILABLE
	if v.State == analysisv1.AnalysisState_ANALYSIS_STATE_COMPLETED {
		state = analysisv1.AvailabilityState_AVAILABLE
	}
	return &analysisv1.AnalysisSummary{AnalysisId: v.ID, Mode: v.Mode, Traffic: &analysisv1.TrafficSummary{State: state}, Security: &analysisv1.SecuritySummary{State: state}, FusionState: state}, nil
}
func (h *AnalysisHandler) Retry(ctx context.Context, r *analysisv1.RetryAnalysisRequest) (*analysisv1.RetryAnalysisResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Retry(ctx, r.GetAnalysisId())
	return &analysisv1.RetryAnalysisResponse{AnalysisId: v.ID, State: v.State}, shared.ToGRPC(e)
}
func analysis(v coreanalysis.Record) *analysisv1.Analysis {
	return &analysisv1.Analysis{AnalysisId: v.ID, SourceId: v.SourceID, Mode: v.Mode, PolicyId: v.PolicyID, Options: v.Options, State: v.State, FailureReason: v.Failure, CreatedAt: timestamppb.New(v.CreatedAt), UpdatedAt: timestamppb.New(v.UpdatedAt)}
}
func progress(stage analysisv1.AnalysisStage) uint32 {
	switch stage {
	case analysisv1.AnalysisStage_INITIALIZING:
		return 5
	case analysisv1.AnalysisStage_COMPLETED:
		return 100
	default:
		return 0
	}
}
