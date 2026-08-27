package sensor

import (
	"context"
	"reflect"
	"time"

	capturev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/capture"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/capture"
)

type CaptureHandler struct {
	capturev1.UnimplementedPassiveCaptureServiceServer
	service *capture.Service
}

func NewCaptureHandler(service *capture.Service) *CaptureHandler {
	return &CaptureHandler{service: service}
}
func (h *CaptureHandler) StartCapture(ctx context.Context, request *capturev1.StartCaptureRequest) (*capturev1.StartCaptureResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	item, err := h.service.Start(ctx, request.GetSensorSessionId(), request.GetInterfaceName(), request.GetFilterMode(), request.GetCustomBpf(), request.GetPromiscuousMode(), request.GetSavePcap(), request.GetMaxDurationSeconds(), request.GetMaxCaptureBytes())
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return &capturev1.StartCaptureResponse{CaptureId: item.CaptureID(), State: capture.StateStarting, StartedAt: shared.Timestamp(item.StartedAt())}, nil
}
func (h *CaptureHandler) StopCapture(ctx context.Context, request *capturev1.StopCaptureRequest) (*capturev1.StopCaptureResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	item, err := h.service.Stop(ctx, request.GetCaptureId())
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	counters, _, _, _, err := h.service.Stats(ctx, item.CaptureID())
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return &capturev1.StopCaptureResponse{CaptureId: item.CaptureID(), State: item.State(), PacketsTotal: counters.PacketsTotal, BytesTotal: counters.BytesTotal, EndedAt: shared.Timestamp(item.EndedAt())}, nil
}
func (h *CaptureHandler) GetCaptureStatus(ctx context.Context, request *capturev1.GetCaptureStatusRequest) (*capturev1.CaptureStatus, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	item, err := h.service.Status(ctx, request.GetCaptureId())
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	counters, _, _, elapsed, err := h.service.Stats(ctx, item.CaptureID())
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return &capturev1.CaptureStatus{State: item.State(), InterfaceName: item.InterfaceName(), StartedAt: shared.Timestamp(item.StartedAt()), DurationSeconds: uint64(elapsed.Seconds()), PacketDrops: counters.PacketDrops}, nil
}
func (h *CaptureHandler) GetCaptureStats(ctx context.Context, request *capturev1.GetCaptureStatsRequest) (*capturev1.CaptureStats, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	return h.stats(ctx, request.GetCaptureId())
}
func (h *CaptureHandler) StreamCaptureStats(request *capturev1.StreamCaptureStatsRequest, stream capturev1.PassiveCaptureService_StreamCaptureStatsServer) error {
	if err := h.validate(request); err != nil {
		return shared.ToGRPC(err)
	}
	if request.GetIntervalMs() < 10 || request.GetIntervalMs() > 60_000 {
		return shared.ToGRPC(shared.NewError(shared.InvalidArgument, "", "interval_ms must be between 10 and 60000"))
	}
	if _, err := h.service.Status(stream.Context(), request.GetCaptureId()); err != nil {
		return shared.ToGRPC(err)
	}
	ticker := time.NewTicker(time.Duration(request.GetIntervalMs()) * time.Millisecond)
	defer ticker.Stop()
	for {
		stats, err := h.stats(stream.Context(), request.GetCaptureId())
		if err != nil {
			return nil
		}
		if err := stream.Send(stats); err != nil {
			return err
		}
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-ticker.C:
			item, err := h.service.Status(stream.Context(), request.GetCaptureId())
			if err != nil || item.State() != capture.StateCapturing {
				return nil
			}
		}
	}
}
func (h *CaptureHandler) UpdateCaptureFilter(ctx context.Context, request *capturev1.UpdateCaptureFilterRequest) (*capturev1.UpdateCaptureFilterResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	filter, err := h.service.UpdateFilter(ctx, request.GetCaptureId(), request.GetFilterMode(), request.GetCustomBpf())
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return &capturev1.UpdateCaptureFilterResponse{Updated: true, ActiveFilter: filter}, nil
}
func (h *CaptureHandler) stats(ctx context.Context, id string) (*capturev1.CaptureStats, error) {
	counters, flows, vpns, elapsed, err := h.service.Stats(ctx, id)
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	result := &capturev1.CaptureStats{PacketsTotal: counters.PacketsTotal, BytesTotal: counters.BytesTotal, IkePackets: counters.IKEPackets, EspPackets: counters.ESPPackets, AhPackets: counters.AHPackets, NatTPackets: counters.NATTPackets, ActiveFlows: flows, ActiveVpnSessions: vpns, PacketDrops: counters.PacketDrops}
	if elapsed > 0 {
		result.PacketsPerSecond = float64(counters.PacketsTotal) / elapsed.Seconds()
		result.BytesPerSecond = float64(counters.BytesTotal) / elapsed.Seconds()
	}
	return result, nil
}
func (h *CaptureHandler) validate(request any) error {
	if h.service == nil {
		return shared.NewError(shared.Internal, "", "capture service is not configured")
	}
	if request == nil || (reflect.ValueOf(request).Kind() == reflect.Ptr && reflect.ValueOf(request).IsNil()) {
		return shared.NewError(shared.InvalidArgument, "", "request is required")
	}
	return nil
}
