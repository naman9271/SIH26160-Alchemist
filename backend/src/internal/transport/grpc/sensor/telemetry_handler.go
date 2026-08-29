package sensor

import (
	"context"
	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
	telemetryv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/telemetry"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/flow"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/session"
	"reflect"
	"time"
)

type TelemetryHandler struct {
	telemetryv1.UnimplementedSensorTelemetryServiceServer
	sessions *session.Service
	flows    *flow.Service
}

func NewTelemetryHandler(s *session.Service, f *flow.Service) *TelemetryHandler {
	return &TelemetryHandler{sessions: s, flows: f}
}
func (h *TelemetryHandler) v(r any) error {
	if h.sessions == nil || h.flows == nil {
		return shared.NewError(shared.Internal, "", "telemetry dependencies are not configured")
	}
	if r == nil || (reflect.ValueOf(r).Kind() == reflect.Ptr && reflect.ValueOf(r).IsNil()) {
		return shared.NewError(shared.InvalidArgument, "", "request is required")
	}
	return nil
}
func (h *TelemetryHandler) GetSnapshot(c context.Context, r *telemetryv1.GetSensorSnapshotRequest) (*telemetryv1.SensorSnapshot, error) {
	if e := h.v(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	s, e := h.sessions.Get(c, r.GetSensorSessionId())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	out := &telemetryv1.SensorSnapshot{SensorSessionId: s.ID, SessionState: s.State, GeneratedAt: shared.Timestamp(time.Now())}
	if r.GetInclude().GetFlows() {
		all, _, e := h.flows.List(c, &flowv1.ListFlowsRequest{SensorSessionId: s.ID, PageSize: 1000})
		if e != nil {
			return nil, shared.ToGRPC(e)
		}
		out.ActiveFlowCount = uint64(len(all))
		for _, v := range all {
			x := flow.Stats(v)
			out.FlowPacketCount += x.GetPacketCount()
			out.FlowByteCount += x.GetByteCount()
		}
	}
	return out, nil
}
func (h *TelemetryHandler) StreamObservations(r *telemetryv1.StreamObservationsRequest, st telemetryv1.SensorTelemetryService_StreamObservationsServer) error {
	if e := h.v(r); e != nil {
		return shared.ToGRPC(e)
	}
	if _, e := h.sessions.Get(st.Context(), r.GetSensorSessionId()); e != nil {
		return shared.ToGRPC(e)
	}
	<-st.Context().Done()
	return st.Context().Err()
}
func (h *TelemetryHandler) StreamFeatureWindows(r *telemetryv1.StreamSensorFeatureWindowsRequest, st telemetryv1.SensorTelemetryService_StreamFeatureWindowsServer) error {
	if e := h.v(r); e != nil {
		return shared.ToGRPC(e)
	}
	ch, cancel, e := h.flows.Subscribe(st.Context(), r.GetSensorSessionId(), flowv1.FeatureBackpressurePolicy_BLOCK_CAPTURE, r.GetBufferSize())
	if e != nil {
		return shared.ToGRPC(e)
	}
	defer cancel()
	for {
		id, ok := <-ch
		if !ok {
			return nil
		}
		w, e := h.flows.Window(st.Context(), id)
		if e == nil {
			if e = st.Send(flow.ToFeature(w)); e != nil {
				return e
			}
		}
	}
}
func (h *TelemetryHandler) AcknowledgeCheckpoint(c context.Context, r *telemetryv1.AcknowledgeCheckpointRequest) (*telemetryv1.AcknowledgeCheckpointResponse, error) {
	if e := h.v(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	if _, e := h.sessions.Get(c, r.GetSensorSessionId()); e != nil {
		return nil, shared.ToGRPC(e)
	}
	return &telemetryv1.AcknowledgeCheckpointResponse{Acknowledged: true}, nil
}
