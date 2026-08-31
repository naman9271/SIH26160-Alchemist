package core

import (
	"context"

	inputv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/input"
	workspacev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/workspace"
	coreinput "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/input"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// InputHandler only maps Core input requests; all acquisition stays in Sensor.
type InputHandler struct {
	inputv1.UnimplementedInputServiceServer
	service   *coreinput.Service
	workspace *workspace.Service
}

func NewInputHandler(service *coreinput.Service, state *workspace.Service) *InputHandler {
	return &InputHandler{service: service, workspace: state}
}
func (h *InputHandler) valid() error {
	if h == nil || h.service == nil {
		return shared.NewError(shared.Internal, "", "input service is not configured")
	}
	return nil
}
func (h *InputHandler) ListInterfaces(ctx context.Context, r *inputv1.ListInterfacesRequest) (*inputv1.ListInterfacesResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	items, e := h.service.ListInterfaces(ctx)
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	out := &inputv1.ListInterfacesResponse{}
	for i := range items {
		out.Interfaces = append(out.Interfaces, &items[i])
	}
	return out, nil
}
func (h *InputHandler) StartLive(ctx context.Context, r *inputv1.StartLiveInputRequest) (*inputv1.StartLiveInputResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	item, e := h.service.StartLive(ctx, r)
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	h.bindSource(ctx, item)
	return &inputv1.StartLiveInputResponse{SourceId: item.ID, CaptureId: item.CaptureID, SensorSessionId: item.SessionID, State: item.State}, nil
}
func (h *InputHandler) StopLive(ctx context.Context, r *inputv1.StopLiveInputRequest) (*inputv1.StopLiveInputResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	item, e := h.service.StopLive(ctx, r.GetSourceId())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	return &inputv1.StopLiveInputResponse{SourceId: item.ID, CaptureId: item.CaptureID, State: item.State}, nil
}
func (h *InputHandler) GetLiveStatus(ctx context.Context, r *inputv1.GetLiveStatusRequest) (*inputv1.LiveInputStatus, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	item, flows, vpns, duration, e := h.service.LiveStatus(ctx, r.GetSourceId())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	c := item.Counters
	return &inputv1.LiveInputStatus{SourceId: item.ID, State: item.State, DurationSeconds: duration, PacketsTotal: c.PacketsTotal, BytesTotal: c.BytesTotal, EspPackets: c.ESPPackets, IkePackets: c.IKEPackets, AhPackets: c.AHPackets, NatTPackets: c.NATTPackets, ActiveFlows: flows, VpnSessions: vpns, PacketDrops: c.PacketDrops}, nil
}
func (h *InputHandler) BeginPcapUpload(ctx context.Context, r *inputv1.BeginPcapUploadRequest) (*inputv1.BeginPcapUploadResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	id, e := h.service.BeginUpload(ctx, r)
	return &inputv1.BeginPcapUploadResponse{UploadId: id, ChunkSizeBytes: coreinput.ChunkSize}, shared.ToGRPC(e)
}
func (h *InputHandler) UploadPcapChunk(ctx context.Context, r *inputv1.UploadPcapChunkRequest) (*inputv1.UploadPcapChunkResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	received, e := h.service.UploadChunk(ctx, r)
	return &inputv1.UploadPcapChunkResponse{Accepted: e == nil, ChunkIndex: r.GetChunkIndex(), ReceivedBytesTotal: received}, shared.ToGRPC(e)
}
func (h *InputHandler) CompletePcapUpload(ctx context.Context, r *inputv1.CompletePcapUploadRequest) (*inputv1.CompletePcapUploadResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	item, e := h.service.CompleteUpload(ctx, r.GetUploadId())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	h.bindSource(ctx, item)
	return &inputv1.CompletePcapUploadResponse{SourceId: item.ID, PcapId: item.PCAPID, State: item.State}, nil
}
func (h *InputHandler) ValidatePcap(ctx context.Context, r *inputv1.ValidatePcapRequest) (*inputv1.ValidatePcapResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	result, e := h.service.Validate(ctx, r.GetSourceId())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	c := result.Counters
	return &inputv1.ValidatePcapResponse{Valid: true, Format: "PCAP", PacketsTotal: c.PacketsTotal, BytesTotal: c.BytesTotal, EspPackets: c.ESPPackets, IkePackets: c.IKEPackets, AhPackets: c.AHPackets, NatTPackets: c.NATTPackets, Message: "classic PCAP validated"}, nil
}
func (h *InputHandler) GetSource(ctx context.Context, r *inputv1.GetSourceRequest) (*inputv1.InputSource, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	item, e := h.service.Get(ctx, r.GetSourceId())
	return source(item), shared.ToGRPC(e)
}
func (h *InputHandler) RemoveSource(ctx context.Context, r *inputv1.RemoveSourceRequest) (*inputv1.RemoveSourceResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	item, e := h.service.Remove(ctx, r.GetSourceId(), r.GetDeleteTemporaryFiles())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	return &inputv1.RemoveSourceResponse{SourceId: item.ID, State: item.State}, nil
}
func source(item coreinput.Source) *inputv1.InputSource {
	return &inputv1.InputSource{SourceId: item.ID, Mode: item.Mode, State: item.State, SensorSessionId: item.SessionID, CaptureId: item.CaptureID, PcapId: item.PCAPID, Filename: item.Filename, SizeBytes: item.Size, Sha256: item.SHA256, CreatedAt: timestamppb.New(item.CreatedAt), UpdatedAt: timestamppb.New(item.UpdatedAt)}
}
func (h *InputHandler) bindSource(ctx context.Context, item coreinput.Source) {
	if h.workspace == nil {
		return
	}
	id, generation, err := h.workspace.CurrentOwnership(ctx)
	if err != nil {
		return
	}
	h.workspace.UpdateIfCurrent(id, generation, func(record *workspace.Record) {
		record.SourceID = item.ID
		record.SensorSessionID = item.SessionID
		record.CaptureID = item.CaptureID
		record.Mode = toWorkspaceMode(item.Mode)
		record.State = workspacev1.WorkspaceState_WORKSPACE_STATE_READY
	})
}
func toWorkspaceMode(mode inputv1.InputMode) workspacev1.AnalysisMode {
	switch mode {
	case inputv1.InputMode_PASSIVE_LIVE:
		return workspacev1.AnalysisMode_PASSIVE_LIVE
	case inputv1.InputMode_PASSIVE_PCAP:
		return workspacev1.AnalysisMode_OFFLINE_PCAP
	case inputv1.InputMode_DEEP_ASSESSMENT:
		return workspacev1.AnalysisMode_DEEP_ASSESSMENT
	default:
		return workspacev1.AnalysisMode_ANALYSIS_MODE_UNSPECIFIED
	}
}
