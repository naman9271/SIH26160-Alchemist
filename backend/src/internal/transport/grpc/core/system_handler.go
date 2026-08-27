package core

import (
	"context"
	"reflect"

	coresystemv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/system"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/system"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

type SystemHandler struct {
	coresystemv1.UnimplementedCoreSystemServiceServer
	service system.Service
}

func NewSystemHandler(service system.Service) *SystemHandler { return &SystemHandler{service: service} }
func (h *SystemHandler) Health(ctx context.Context, request *coresystemv1.HealthRequest) (*coresystemv1.HealthResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	at, err := h.service.Health(ctx)
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return &coresystemv1.HealthResponse{Status: coresystemv1.HealthStatus_HEALTHY, Time: shared.Timestamp(at)}, nil
}
func (h *SystemHandler) Readiness(ctx context.Context, request *coresystemv1.ReadinessRequest) (*coresystemv1.ReadinessResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	dependency, err := h.service.Readiness(ctx)
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	ready := dependency.InMemoryStore == coresystemv1.DependencyState_READY && dependency.TempStorage == coresystemv1.DependencyState_READY && dependency.Sensor == coresystemv1.DependencyState_READY && dependency.FusionEngine == coresystemv1.DependencyState_READY
	return &coresystemv1.ReadinessResponse{Ready: ready, InMemoryStore: dependency.InMemoryStore, TempStorage: dependency.TempStorage, Sensor: dependency.Sensor, MlWorker: dependency.MLWorker, FusionEngine: dependency.FusionEngine}, nil
}
func (h *SystemHandler) GetVersion(ctx context.Context, request *coresystemv1.GetVersionRequest) (*coresystemv1.GetVersionResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	version, err := h.service.Version(ctx)
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return &coresystemv1.GetVersionResponse{CoreVersion: version.CoreVersion, ApiVersion: system.APIVersion, SensorContract: system.SensorContract, MlContract: system.MLContract, FusionContract: system.FusionContract, BuildCommit: version.BuildCommit}, nil
}
func (h *SystemHandler) GetCapabilities(ctx context.Context, request *coresystemv1.GetCapabilitiesRequest) (*coresystemv1.GetCapabilitiesResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	value, err := h.service.Capabilities(ctx)
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return &coresystemv1.GetCapabilitiesResponse{PassiveLive: value.PassiveLive, PassivePcap: value.PassivePCAP, DeepAssessment: value.DeepAssessment, SecurityAssessment: value.SecurityAssessment, RiskScoring: value.RiskScoring, ThreatMatrix: value.ThreatMatrix, MlClassification: value.MLClassification, Shap: value.SHAP, MetadataExposure: value.MetadataExposure, ExecutiveReport: value.ExecutiveReport, TechnicalReport: value.TechnicalReport}, nil
}
func (h *SystemHandler) GetRuntimeStats(ctx context.Context, request *coresystemv1.GetRuntimeStatsRequest) (*coresystemv1.GetRuntimeStatsResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	value, err := h.service.RuntimeStats(ctx)
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return &coresystemv1.GetRuntimeStatsResponse{UptimeSeconds: value.UptimeSeconds, CpuPercent: value.CPUPercent, RssBytes: value.RSSBytes, Goroutines: value.Goroutines, EventSubscribers: value.EventSubscribers, CurrentWorkspaceState: value.CurrentWorkspaceState, SensorQueueDepth: value.SensorQueueDepth, MlRoundTripMs: value.MLRoundTripMS, FusionRecomputeMs: value.FusionRecomputeMS}, nil
}
func (h *SystemHandler) validate(request any) error {
	if h.service == nil {
		return shared.NewError(shared.Internal, "", "core system service is not configured")
	}
	if request == nil || (reflect.ValueOf(request).Kind() == reflect.Ptr && reflect.ValueOf(request).IsNil()) {
		return shared.NewError(shared.InvalidArgument, "", "request is required")
	}
	return nil
}
