package core

import (
	"context"
	localsensorv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/localsensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/localsensor"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

type LocalSensorHandler struct {
	localsensorv1.UnimplementedLocalSensorStatusServiceServer
	service *localsensor.Service
}

func NewLocalSensorHandler(service *localsensor.Service) *LocalSensorHandler {
	return &LocalSensorHandler{service: service}
}
func (h *LocalSensorHandler) GetStatus(ctx context.Context, _ *localsensorv1.GetLocalSensorStatusRequest) (*localsensorv1.LocalSensorStatus, error) {
	v, e := h.service.Status(ctx)
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	return &localsensorv1.LocalSensorStatus{Ready: v.Ready, SensorVersion: v.SensorVersion, SessionActive: v.SessionActive, CaptureActive: v.CaptureActive, PacketQueueDepth: v.PacketQueueDepth, FeatureQueueDepth: v.FeatureQueueDepth, LastError: v.LastError}, nil
}
func (h *LocalSensorHandler) GetCapabilities(ctx context.Context, _ *localsensorv1.GetLocalSensorCapabilitiesRequest) (*localsensorv1.LocalSensorCapabilities, error) {
	v, e := h.service.Capabilities(ctx)
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	return &localsensorv1.LocalSensorCapabilities{PassiveLive: v.PassiveLive, PassivePcap: v.PassivePCAP, Ipv4: v.IPv4, Ipv6: v.IPv6, Ikev1: v.IKEv1, Ikev2: v.IKEv2, Esp: v.ESP, Ah: v.AH, NatT: v.NATT, FeatureWindows: v.FeatureWindows, SequenceSketches: v.SequenceSketches, Vici: v.VICI, Xfrm: v.XFRM}, nil
}
func (h *LocalSensorHandler) ProbeModes(ctx context.Context, _ *localsensorv1.ProbeModesRequest) (*localsensorv1.ProbeModesResponse, error) {
	v, e := h.service.Probe(ctx)
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	return &localsensorv1.ProbeModesResponse{PassiveLive: &localsensorv1.ModeAvailability{Available: v.PassiveLive.Available, Reason: v.PassiveLive.Reason}, PassivePcap: &localsensorv1.ModeAvailability{Available: v.PassivePCAP.Available, Reason: v.PassivePCAP.Reason}, DeepAssessment: &localsensorv1.DeepModeAvailability{Available: v.PassiveLive.Available && (v.VICI.Available || v.XFRM.Available), Vici: v.VICI.Available, Xfrm: v.XFRM.Available}}, nil
}
func (h *LocalSensorHandler) GetDeepAssessmentAvailability(ctx context.Context, _ *localsensorv1.GetDeepAssessmentAvailabilityRequest) (*localsensorv1.GetDeepAssessmentAvailabilityResponse, error) {
	v, e := h.service.Probe(ctx)
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	return &localsensorv1.GetDeepAssessmentAvailabilityResponse{Available: v.PassiveLive.Available && (v.VICI.Available || v.XFRM.Available), Vici: &localsensorv1.DependencyAvailability{Available: v.VICI.Available, Reason: v.VICI.Reason}, Xfrm: &localsensorv1.DependencyAvailability{Available: v.XFRM.Available, Reason: v.XFRM.Reason}}, nil
}
