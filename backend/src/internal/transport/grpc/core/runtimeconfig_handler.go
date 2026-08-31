package core

import (
	"context"
	runtimeconfigv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/runtimeconfig"
	coreconfig "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/runtimeconfig"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

type RuntimeConfigHandler struct {
	runtimeconfigv1.UnimplementedRuntimeConfigServiceServer
	service *coreconfig.Service
}

func NewRuntimeConfigHandler(s *coreconfig.Service) *RuntimeConfigHandler {
	return &RuntimeConfigHandler{service: s}
}
func (h *RuntimeConfigHandler) valid() error {
	if h == nil || h.service == nil {
		return shared.NewError(shared.Internal, "", "runtime configuration service is not configured")
	}
	return nil
}
func (h *RuntimeConfigHandler) Get(ctx context.Context, _ *runtimeconfigv1.GetRuntimeConfigRequest) (*runtimeconfigv1.RuntimeConfig, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Get(ctx)
	return v, shared.ToGRPC(e)
}
func (h *RuntimeConfigHandler) Update(ctx context.Context, r *runtimeconfigv1.UpdateRuntimeConfigRequest) (*runtimeconfigv1.RuntimeConfig, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Update(ctx, r.GetConfig(), r.GetUpdateMask().GetPaths())
	return v, shared.ToGRPC(e)
}
func (h *RuntimeConfigHandler) RestoreDefaults(ctx context.Context, _ *runtimeconfigv1.RestoreDefaultsRequest) (*runtimeconfigv1.RuntimeConfig, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.RestoreDefaults(ctx)
	return v, shared.ToGRPC(e)
}
