package sensor

import (
	"context"
	"reflect"

	sensorv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1"
	sessionv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/session"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/session"
)

type SessionHandler struct {
	sessionv1.UnimplementedSensorSessionServiceServer
	service *session.Service
}

func NewSessionHandler(service *session.Service) *SessionHandler {
	return &SessionHandler{service: service}
}
func (h *SessionHandler) CreateSession(ctx context.Context, request *sessionv1.CreateSensorSessionRequest) (*sessionv1.SensorSession, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	var options *session.DeepOptions
	if request.GetDeepOptions() != nil {
		options = &session.DeepOptions{EnableVICI: request.GetDeepOptions().GetEnableVici(), EnableXFRM: request.GetDeepOptions().GetEnableXfrm()}
	}
	item, err := h.service.Create(ctx, request.GetMode(), request.GetName(), options)
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return sessionResponse(item), nil
}
func (h *SessionHandler) GetSession(ctx context.Context, request *sessionv1.GetSensorSessionRequest) (*sessionv1.SensorSession, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	item, err := h.service.Get(ctx, request.GetSensorSessionId())
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return sessionResponse(item), nil
}
func (h *SessionHandler) StopSession(ctx context.Context, request *sessionv1.StopSensorSessionRequest) (*sessionv1.StopSensorSessionResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	item, err := h.service.Stop(ctx, request.GetSensorSessionId())
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return &sessionv1.StopSensorSessionResponse{SensorSessionId: item.ID, State: item.State, EndedAt: shared.Timestamp(item.EndedAt)}, nil
}
func (h *SessionHandler) ResetSession(ctx context.Context, request *sessionv1.ResetSensorSessionRequest) (*sessionv1.ResetSensorSessionResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	item, err := h.service.Reset(ctx, request.GetSensorSessionId(), request.GetDeleteTemporaryFiles())
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return &sessionv1.ResetSensorSessionResponse{Reset_: true, State: item.State}, nil
}
func (h *SessionHandler) validate(request any) error {
	if h.service == nil {
		return shared.NewError(shared.Internal, "", "session service is not configured")
	}
	if request == nil || (reflect.ValueOf(request).Kind() == reflect.Ptr && reflect.ValueOf(request).IsNil()) {
		return shared.NewError(shared.InvalidArgument, "", "request is required")
	}
	return nil
}
func sessionResponse(item session.Session) *sessionv1.SensorSession {
	response := &sessionv1.SensorSession{SensorSessionId: item.ID, Name: item.Name, Mode: item.Mode, State: item.State, CaptureId: item.CaptureID, CreatedAt: shared.Timestamp(item.CreatedAt), LastActivityAt: shared.Timestamp(item.LastActivityAt)}
	if !item.StartedAt.IsZero() {
		response.StartedAt = shared.Timestamp(item.StartedAt)
	}
	if !item.EndedAt.IsZero() {
		response.EndedAt = shared.Timestamp(item.EndedAt)
	}
	return response
}

var _ = sensorv1.SensorMode_PASSIVE_LIVE
