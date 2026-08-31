package core

import (
	"context"

	mlv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/ml"
	coreml "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/ml"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

type MLHandler struct {
	mlv1.UnimplementedMLOrchestrationServiceServer
	service *coreml.Service
}

func NewMLHandler(service *coreml.Service) *MLHandler { return &MLHandler{service: service} }
func (h *MLHandler) valid() error {
	if h == nil || h.service == nil {
		return shared.NewError(shared.Internal, "", "ML orchestration service is not configured")
	}
	return nil
}
func (h *MLHandler) GetWorkerStatus(ctx context.Context, _ *mlv1.GetMLWorkerStatusRequest) (*mlv1.MLWorkerStatus, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.WorkerStatus(ctx)
	return v, shared.ToGRPC(e)
}
func (h *MLHandler) GetModelInfo(ctx context.Context, _ *mlv1.GetModelInfoRequest) (*mlv1.ModelInfo, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.ModelInfo(ctx)
	return v, shared.ToGRPC(e)
}
func (h *MLHandler) RunInference(ctx context.Context, r *mlv1.RunInferenceRequest) (*mlv1.RunInferenceResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Start(ctx, r.GetAnalysisId(), r.GetUseSequenceModel(), r.GetEnableShap())
	return v, shared.ToGRPC(e)
}
func (h *MLHandler) GetInferenceStatus(ctx context.Context, r *mlv1.GetInferenceStatusRequest) (*mlv1.InferenceStatus, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Status(ctx, r.GetInferenceId())
	return v, shared.ToGRPC(e)
}
func (h *MLHandler) ListPredictions(ctx context.Context, r *mlv1.ListPredictionsRequest) (*mlv1.ListPredictionsResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, n, e := h.service.Predictions(ctx, r.GetInferenceId(), r.GetPageSize(), r.GetPageToken())
	return &mlv1.ListPredictionsResponse{Predictions: v, NextPageToken: n}, shared.ToGRPC(e)
}
func (h *MLHandler) GetPrediction(ctx context.Context, r *mlv1.GetPredictionRequest) (*mlv1.TrafficPrediction, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Prediction(ctx, r.GetInferenceId(), r.GetPredictionId())
	return v, shared.ToGRPC(e)
}
func (h *MLHandler) GetExplanation(ctx context.Context, r *mlv1.GetPredictionExplanationRequest) (*mlv1.PredictionExplanation, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Explanation(ctx, r.GetInferenceId(), r.GetPredictionId())
	return v, shared.ToGRPC(e)
}
func (h *MLHandler) CancelInference(ctx context.Context, r *mlv1.CancelInferenceRequest) (*mlv1.CancelInferenceResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Cancel(ctx, r.GetInferenceId())
	return v, shared.ToGRPC(e)
}
