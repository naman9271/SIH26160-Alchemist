package core

import (
	"context"
	"reflect"

	workspacev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/workspace"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

type WorkspaceHandler struct {
	workspacev1.UnimplementedWorkspaceServiceServer
	service *workspace.Service
}

func NewWorkspaceHandler(service *workspace.Service) *WorkspaceHandler {
	return &WorkspaceHandler{service: service}
}
func (h *WorkspaceHandler) Create(ctx context.Context, request *workspacev1.CreateWorkspaceRequest) (*workspacev1.Workspace, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	item, err := h.service.Create(ctx, request.GetDisplayName(), workspace.IdempotencyKey(ctx))
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return mapWorkspace(item), nil
}
func (h *WorkspaceHandler) Get(ctx context.Context, request *workspacev1.GetWorkspaceRequest) (*workspacev1.Workspace, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	item, err := h.service.Get(ctx, request.GetWorkspaceId())
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return mapWorkspace(item), nil
}
func (h *WorkspaceHandler) GetState(ctx context.Context, request *workspacev1.GetWorkspaceStateRequest) (*workspacev1.WorkspaceStateResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	item, err := h.service.GetState(ctx, request.GetWorkspaceId())
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return &workspacev1.WorkspaceStateResponse{State: item.State, Mode: item.Mode, HasSource: item.HasSource, HasAnalysis: item.HasAnalysis, HasMlResult: item.HasMLResult, HasFusedResult: item.HasFusedResult, HasReport: item.HasReport}, nil
}
func (h *WorkspaceHandler) Reset(ctx context.Context, request *workspacev1.ResetWorkspaceRequest) (*workspacev1.ResetWorkspaceResponse, error) {
	if err := h.validate(request); err != nil {
		return nil, shared.ToGRPC(err)
	}
	item, err := h.service.Reset(ctx, request.GetForce(), request.GetDeleteTemporaryFiles(), workspace.IdempotencyKey(ctx))
	if err != nil {
		return nil, shared.ToGRPC(err)
	}
	return &workspacev1.ResetWorkspaceResponse{WorkspaceId: item.ID, State: item.State}, nil
}
func (h *WorkspaceHandler) validate(request any) error {
	if h.service == nil {
		return shared.NewError(shared.Internal, "", "workspace service is not configured")
	}
	if request == nil || (reflect.ValueOf(request).Kind() == reflect.Ptr && reflect.ValueOf(request).IsNil()) {
		return shared.NewError(shared.InvalidArgument, "", "request is required")
	}
	return nil
}
func mapWorkspace(item workspace.Record) *workspacev1.Workspace {
	return &workspacev1.Workspace{WorkspaceId: item.ID, DisplayName: item.DisplayName, State: item.State, Mode: item.Mode, SensorSessionId: item.SensorSessionID, SourceId: item.SourceID, CaptureId: item.CaptureID, AnalysisId: item.AnalysisID, AssessmentId: item.AssessmentID, FusionRunId: item.FusionRunID, HasReport: item.ReportID != "", ReportStatus: item.ReportStatus, CreatedAt: shared.Timestamp(item.CreatedAt), UpdatedAt: shared.Timestamp(item.UpdatedAt)}
}
