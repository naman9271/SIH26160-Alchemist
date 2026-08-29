package sensor

import (
	"context"
	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/flow"
	"reflect"
)

type FlowHandler struct {
	flowv1.UnimplementedFlowTelemetryServiceServer
	service *flow.Service
}

func NewFlowHandler(s *flow.Service) *FlowHandler { return &FlowHandler{service: s} }
func (h *FlowHandler) valid(r any) error {
	if h.service == nil {
		return shared.NewError(shared.Internal, "", "flow service is not configured")
	}
	if r == nil || (reflect.ValueOf(r).Kind() == reflect.Ptr && reflect.ValueOf(r).IsNil()) {
		return shared.NewError(shared.InvalidArgument, "", "request is required")
	}
	return nil
}
func (h *FlowHandler) ListFlows(ctx context.Context, r *flowv1.ListFlowsRequest) (*flowv1.ListFlowsResponse, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, next, e := h.service.List(ctx, r)
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	out := &flowv1.ListFlowsResponse{NextPageToken: next}
	for _, v := range x {
		out.Flows = append(out.Flows, flow.ToProto(v))
	}
	return out, nil
}
func (h *FlowHandler) GetFlow(ctx context.Context, r *flowv1.GetFlowRequest) (*flowv1.Flow, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := h.service.Flow(ctx, r.GetFlowId())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	return flow.ToProto(x), nil
}
func (h *FlowHandler) GetFlowStats(ctx context.Context, r *flowv1.GetFlowStatsRequest) (*flowv1.FlowStats, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := h.service.Flow(ctx, r.GetFlowId())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	return flow.Stats(x), nil
}
func (h *FlowHandler) ListFeatureWindows(ctx context.Context, r *flowv1.ListFeatureWindowsRequest) (*flowv1.ListFeatureWindowsResponse, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, next, e := h.service.Windows(ctx, r.GetFlowId(), r.GetPageSize(), r.GetPageToken())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	out := &flowv1.ListFeatureWindowsResponse{NextPageToken: next}
	for _, w := range x {
		f := flow.ToFeature(w)
		out.Windows = append(out.Windows, &flowv1.FeatureWindowSummary{WindowId: f.WindowId, FlowId: f.FlowId, SessionId: f.SessionId, WindowStart: f.WindowStart, WindowEnd: f.WindowEnd, FeatureSchemaVersion: f.FeatureSchemaVersion, SequenceSchemaVersion: f.SequenceSchemaVersion, PacketCount: f.PacketCount, Finalized: f.Finalized, EvictionReason: f.EvictionReason})
	}
	return out, nil
}
func (h *FlowHandler) GetFeatureWindow(ctx context.Context, r *flowv1.GetFeatureWindowRequest) (*flowv1.FeatureWindow, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	w, e := h.service.Window(ctx, r.GetWindowId())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	return flow.ToFeature(w), nil
}
func (h *FlowHandler) GetSequenceSketch(ctx context.Context, r *flowv1.GetSequenceSketchRequest) (*flowv1.SequenceSketch, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	w, e := h.service.Window(ctx, r.GetWindowId())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	return flow.ToSequence(w), nil
}
func (h *FlowHandler) StreamFeatureWindows(r *flowv1.StreamFeatureWindowsRequest, stream flowv1.FlowTelemetryService_StreamFeatureWindowsServer) error {
	if e := h.valid(r); e != nil {
		return shared.ToGRPC(e)
	}
	ch, cancel, e := h.service.Subscribe(stream.Context(), r.GetSensorSessionId(), r.GetBackpressurePolicy(), r.GetBufferSize())
	if e != nil {
		return shared.ToGRPC(e)
	}
	defer cancel()
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case id, ok := <-ch:
			if !ok {
				return nil
			}
			w, e := h.service.Window(stream.Context(), id)
			if e != nil {
				continue
			}
			if w.IsMLReady() {
				if e = stream.Send(flow.ToFeature(w)); e != nil {
					return e
				}
			}
		}
	}
}
