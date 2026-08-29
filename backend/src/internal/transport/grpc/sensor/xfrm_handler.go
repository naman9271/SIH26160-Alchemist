package sensor

import (
	"context"
	xfrmv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/xfrm"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/xfrm"
	"reflect"
	"time"
)

type XfrmHandler struct {
	xfrmv1.UnimplementedKernelXfrmServiceServer
	service *xfrm.Service
}

func NewXfrmHandler(s *xfrm.Service) *XfrmHandler { return &XfrmHandler{service: s} }
func (h *XfrmHandler) v(r any) error {
	if h.service == nil {
		return shared.NewError(shared.Internal, "", "XFRM service is not configured")
	}
	if r == nil || (reflect.ValueOf(r).Kind() == reflect.Ptr && reflect.ValueOf(r).IsNil()) {
		return shared.NewError(shared.InvalidArgument, "", "request is required")
	}
	return nil
}
func (h *XfrmHandler) GetCapabilities(c context.Context, r *xfrmv1.GetXfrmCapabilitiesRequest) (*xfrmv1.XfrmCapabilities, error) {
	if e := h.v(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := h.service.Capabilities(c)
	return x, shared.ToGRPC(e)
}
func (h *XfrmHandler) ListStates(c context.Context, r *xfrmv1.ListXfrmStatesRequest) (*xfrmv1.ListXfrmStatesResponse, error) {
	if e := h.v(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, n, e := h.service.States(c, r)
	return &xfrmv1.ListXfrmStatesResponse{States: x, NextPageToken: n}, shared.ToGRPC(e)
}
func (h *XfrmHandler) GetState(c context.Context, r *xfrmv1.GetXfrmStateRequest) (*xfrmv1.XfrmState, error) {
	x, _, e := h.service.States(c, &xfrmv1.ListXfrmStatesRequest{Source: r.GetSource(), Destination: r.GetDestination(), Protocol: r.GetProtocol(), Spi: r.GetSpi()})
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	if len(x) != 1 {
		return nil, shared.ToGRPC(shared.NewError(shared.NotFound, "", "XFRM state was not found"))
	}
	return x[0], nil
}
func (h *XfrmHandler) ListPolicies(c context.Context, r *xfrmv1.ListXfrmPoliciesRequest) (*xfrmv1.ListXfrmPoliciesResponse, error) {
	x, n, e := h.service.Policies(c, r)
	return &xfrmv1.ListXfrmPoliciesResponse{Policies: x, NextPageToken: n}, shared.ToGRPC(e)
}
func (h *XfrmHandler) GetReplayProtection(c context.Context, r *xfrmv1.GetReplayProtectionRequest) (*xfrmv1.ReplayProtection, error) {
	x, _, e := h.service.States(c, &xfrmv1.ListXfrmStatesRequest{Destination: r.GetDestination(), Protocol: r.GetProtocol(), Spi: r.GetSpi()})
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	if len(x) != 1 {
		return nil, shared.ToGRPC(shared.NewError(shared.NotFound, "", "XFRM state was not found"))
	}
	v := x[0]
	return &xfrmv1.ReplayProtection{Available: v.GetReplayWindow() > 0, Enabled: v.GetReplayWindow() > 0, ReplayWindow: v.GetReplayWindow(), Sequence: v.GetSequence(), ExtendedSequenceNumbers: v.GetExtendedSequenceNumbers(), EvidenceStatus: v.GetEvidenceStatus()}, nil
}
func (h *XfrmHandler) GetKernelSnapshot(c context.Context, r *xfrmv1.GetKernelSnapshotRequest) (*xfrmv1.KernelSnapshot, error) {
	s, _, e := h.service.States(c, &xfrmv1.ListXfrmStatesRequest{})
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	p, _, e := h.service.Policies(c, &xfrmv1.ListXfrmPoliciesRequest{})
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	return &xfrmv1.KernelSnapshot{States: s, Policies: p, SnapshotTimestamp: shared.Timestamp(time.Now())}, nil
}
