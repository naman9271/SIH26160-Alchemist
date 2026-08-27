// Package sensor provides the protobuf/gRPC adapter for Sensor services.
package sensor

import (
	"context"
	"reflect"
	"runtime"

	sensorv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1"
	sharedsensor "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/system"
)

type SystemHandler struct {
	sensorv1.UnimplementedSensorSystemServiceServer
	service system.Service
}

func NewSystemHandler(service system.Service) *SystemHandler {
	return &SystemHandler{service: service}
}

func (h *SystemHandler) Health(ctx context.Context, request *sensorv1.HealthRequest) (*sensorv1.HealthResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, sharedsensor.ToGRPC(err)
	}
	timestamp, err := h.service.Health(ctx)
	if err != nil {
		return nil, sharedsensor.ToGRPC(err)
	}
	return &sensorv1.HealthResponse{Status: sensorv1.HealthStatus_HEALTHY, Time: sharedsensor.Timestamp(timestamp)}, nil
}

func (h *SystemHandler) Readiness(ctx context.Context, request *sensorv1.ReadinessRequest) (*sensorv1.ReadinessResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, sharedsensor.ToGRPC(err)
	}
	readiness, err := h.service.Readiness(ctx)
	if err != nil {
		return nil, sharedsensor.ToGRPC(err)
	}
	return &sensorv1.ReadinessResponse{
		Ready:          readiness.PassiveReady(),
		CaptureEngine:  componentState(readiness.CaptureEngine),
		TempStorage:    componentState(readiness.TempStorage),
		ProtocolEngine: componentState(readiness.ProtocolEngine),
		Vici:           componentState(readiness.VICI),
		Xfrm:           componentState(readiness.XFRM),
	}, nil
}

func (h *SystemHandler) GetVersion(ctx context.Context, request *sensorv1.GetVersionRequest) (*sensorv1.GetVersionResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, sharedsensor.ToGRPC(err)
	}
	version, err := h.service.Version(ctx)
	if err != nil {
		return nil, sharedsensor.ToGRPC(err)
	}
	return &sensorv1.GetVersionResponse{
		SensorVersion: version.SensorVersion,
		ApiVersion:    system.APIVersion,
		BuildCommit:   version.BuildCommit,
		GoVersion:     runtime.Version(),
		Os:            runtime.GOOS,
		Architecture:  runtime.GOARCH,
	}, nil
}

func (h *SystemHandler) GetCapabilities(ctx context.Context, request *sensorv1.GetCapabilitiesRequest) (*sensorv1.GetCapabilitiesResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, sharedsensor.ToGRPC(err)
	}
	capabilities, err := h.service.Capabilities(ctx)
	if err != nil {
		return nil, sharedsensor.ToGRPC(err)
	}
	return &sensorv1.GetCapabilitiesResponse{
		PassiveLive: capabilities.PassiveLive, PassivePcap: capabilities.PassivePCAP,
		DeepAssessment: capabilities.DeepAssessment, Ipv4: capabilities.IPv4, Ipv6: capabilities.IPv6,
		Ikev1: capabilities.IKEv1, Ikev2: capabilities.IKEv2, Esp: capabilities.ESP, Ah: capabilities.AH,
		NatT: capabilities.NATT, Vici: capabilities.VICI, Xfrm: capabilities.XFRM,
		FeatureWindows: capabilities.FeatureWindows, SequenceSketches: capabilities.SequenceSketches,
	}, nil
}

func (h *SystemHandler) GetRuntimeStats(ctx context.Context, request *sensorv1.GetRuntimeStatsRequest) (*sensorv1.GetRuntimeStatsResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, sharedsensor.ToGRPC(err)
	}
	stats, err := h.service.RuntimeStats(ctx)
	if err != nil {
		return nil, sharedsensor.ToGRPC(err)
	}
	return &sensorv1.GetRuntimeStatsResponse{
		UptimeSeconds: stats.UptimeSeconds, CpuPercent: stats.CPUPercent, RssBytes: stats.RSSBytes,
		Goroutines: stats.Goroutines, ActiveFlows: stats.ActiveFlows, PacketQueueDepth: stats.PacketQueueDepth,
		FeatureQueueDepth: stats.FeatureQueueDepth, TemporaryDiskBytes: stats.TemporaryDiskBytes,
	}, nil
}

func (h *SystemHandler) validate(request any) error {
	if h.service == nil {
		return sharedsensor.NewError(sharedsensor.Internal, "", "sensor system service is not configured")
	}
	if request == nil || (reflect.ValueOf(request).Kind() == reflect.Ptr && reflect.ValueOf(request).IsNil()) {
		return sharedsensor.NewError(sharedsensor.InvalidArgument, "", "request is required")
	}
	return nil
}

func componentState(state system.ComponentState) sensorv1.ReadinessComponentState {
	switch state {
	case system.ComponentReady:
		return sensorv1.ReadinessComponentState_READY
	case system.ComponentDegraded:
		return sensorv1.ReadinessComponentState_READINESS_DEGRADED
	default:
		return sensorv1.ReadinessComponentState_UNAVAILABLE
	}
}
