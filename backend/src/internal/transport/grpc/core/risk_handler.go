package core

import (
	"context"
	riskv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/risk"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/risk"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

type RiskHandler struct {
	riskv1.UnimplementedRiskServiceServer
	service *risk.Service
}

func NewRiskHandler(service *risk.Service) *RiskHandler { return &RiskHandler{service: service} }
func (h *RiskHandler) valid() error {
	if h == nil || h.service == nil {
		return shared.NewError(shared.Internal, "", "risk service is not configured")
	}
	return nil
}
func (h *RiskHandler) Calculate(ctx context.Context, r *riskv1.CalculateRiskRequest) (*riskv1.CalculateRiskResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Score(ctx, r.GetAssessmentId())
	return &riskv1.CalculateRiskResponse{Score: v}, shared.ToGRPC(e)
}
func (h *RiskHandler) GetScore(ctx context.Context, r *riskv1.GetRiskScoreRequest) (*riskv1.SecurityScore, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Score(ctx, r.GetAssessmentId())
	return v, shared.ToGRPC(e)
}
func (h *RiskHandler) GetBreakdown(ctx context.Context, r *riskv1.GetRiskBreakdownRequest) (*riskv1.RiskBreakdown, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Breakdown(ctx, r.GetAssessmentId())
	return v, shared.ToGRPC(e)
}
func (h *RiskHandler) GetCriticalOverrides(ctx context.Context, r *riskv1.GetCriticalOverridesRequest) (*riskv1.CriticalOverridesResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Overrides(ctx, r.GetAssessmentId())
	return v, shared.ToGRPC(e)
}
