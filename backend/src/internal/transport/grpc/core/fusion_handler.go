package core

import (
	"context"

	fusionv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/fusion"
	corefusion "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/fusion"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

type FusionHandler struct {
	fusionv1.UnimplementedFusionOrchestrationServiceServer
	service *corefusion.Service
}

func NewFusionHandler(service *corefusion.Service) *FusionHandler {
	return &FusionHandler{service: service}
}
func (h *FusionHandler) valid() error {
	if h == nil || h.service == nil {
		return shared.NewError(shared.Internal, "", "fusion orchestration service is not configured")
	}
	return nil
}
func (h *FusionHandler) Run(ctx context.Context, r *fusionv1.RunFusionRequest) (*fusionv1.RunFusionResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Run(ctx, r.GetAnalysisId(), r)
	return v, shared.ToGRPC(e)
}
func (h *FusionHandler) GetStatus(ctx context.Context, r *fusionv1.GetFusionStatusRequest) (*fusionv1.FusionStatus, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Status(ctx, r.GetAnalysisId())
	return v, shared.ToGRPC(e)
}
func (h *FusionHandler) GetSummary(ctx context.Context, r *fusionv1.GetFusionSummaryRequest) (*fusionv1.FusionSummary, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Summary(ctx, r.GetAnalysisId())
	return v, shared.ToGRPC(e)
}
func (h *FusionHandler) ListConclusions(ctx context.Context, r *fusionv1.ListFusedConclusionsRequest) (*fusionv1.ListFusedConclusionsResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, n, e := h.service.List(ctx, r.GetAnalysisId(), r)
	return &fusionv1.ListFusedConclusionsResponse{Conclusions: v, NextPageToken: n}, shared.ToGRPC(e)
}
func (h *FusionHandler) GetConclusion(ctx context.Context, r *fusionv1.GetFusedConclusionRequest) (*fusionv1.FusedConclusion, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Get(ctx, r.GetAnalysisId(), r.GetConclusionId())
	return v, shared.ToGRPC(e)
}
func (h *FusionHandler) GetEvidenceChain(ctx context.Context, r *fusionv1.GetEvidenceChainRequest) (*fusionv1.EvidenceChain, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Chain(ctx, r.GetAnalysisId(), r.GetConclusionId())
	return v, shared.ToGRPC(e)
}
func (h *FusionHandler) Recompute(ctx context.Context, r *fusionv1.RecomputeFusionRequest) (*fusionv1.RecomputeFusionResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Recompute(ctx, r.GetAnalysisId(), r.GetPropertyKeys())
	return v, shared.ToGRPC(e)
}
