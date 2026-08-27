package sensor

import (
	"context"
	viciv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/vici"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/vici"
	"reflect"
	"time"
)

type ViciHandler struct {
	viciv1.UnimplementedStrongSwanViciServiceServer
	service *vici.Service
}

func NewViciHandler(s *vici.Service) *ViciHandler { return &ViciHandler{service: s} }
func (h *ViciHandler) valid(r any) error {
	if h.service == nil {
		return shared.NewError(shared.Internal, "", "VICI service is not configured")
	}
	if r == nil || (reflect.ValueOf(r).Kind() == reflect.Ptr && reflect.ValueOf(r).IsNil()) {
		return shared.NewError(shared.InvalidArgument, "", "request is required")
	}
	return nil
}
func (h *ViciHandler) Probe(c context.Context, r *viciv1.ProbeViciRequest) (*viciv1.ProbeViciResponse, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := h.service.Probe(c, r.GetSocketUri())
	return x, shared.ToGRPC(e)
}
func (h *ViciHandler) b(c context.Context, uri string) (vici.Backend, string, error) {
	return h.service.Backend(c, uri)
}
func (h *ViciHandler) GetCapabilities(c context.Context, r *viciv1.GetViciCapabilitiesRequest) (*viciv1.ViciCapabilities, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	b, u, e := h.b(c, r.GetSocketUri())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := b.Capabilities(c, u)
	return x, shared.ToGRPC(e)
}
func (h *ViciHandler) GetDaemonStats(c context.Context, r *viciv1.GetDaemonStatsRequest) (*viciv1.ViciDaemonStats, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	b, u, e := h.b(c, r.GetSocketUri())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := b.DaemonStats(c, u)
	return x, shared.ToGRPC(e)
}
func (h *ViciHandler) ListIkeSas(c context.Context, r *viciv1.ListIkeSasRequest) (*viciv1.ListIkeSasResponse, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	b, u, e := h.b(c, r.GetSocketUri())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := b.IkeSas(c, u)
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, n, e := vici.FilterIke(x, r)
	return &viciv1.ListIkeSasResponse{IkeSas: x, NextPageToken: n}, shared.ToGRPC(e)
}
func (h *ViciHandler) GetIkeSa(c context.Context, r *viciv1.GetIkeSaRequest) (*viciv1.IkeSa, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	b, u, e := h.b(c, r.GetSocketUri())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := b.IkeSas(c, u)
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	for _, v := range x {
		if v.GetUniqueId() == r.GetIkeUniqueId() {
			return v, nil
		}
	}
	return nil, shared.ToGRPC(shared.NewError(shared.NotFound, "", "IKE SA was not found"))
}
func (h *ViciHandler) ListChildSas(c context.Context, r *viciv1.ListChildSasRequest) (*viciv1.ListChildSasResponse, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	b, u, e := h.b(c, r.GetSocketUri())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := b.ChildSas(c, u)
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, n, e := vici.FilterChild(x, r)
	return &viciv1.ListChildSasResponse{ChildSas: x, NextPageToken: n}, shared.ToGRPC(e)
}
func (h *ViciHandler) GetChildSa(c context.Context, r *viciv1.GetChildSaRequest) (*viciv1.ChildSa, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	b, u, e := h.b(c, r.GetSocketUri())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := b.ChildSas(c, u)
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	for _, v := range x {
		if v.GetUniqueId() == r.GetChildUniqueId() {
			return v, nil
		}
	}
	return nil, shared.ToGRPC(shared.NewError(shared.NotFound, "", "CHILD SA was not found"))
}
func (h *ViciHandler) ListConnections(c context.Context, r *viciv1.ListConnectionsRequest) (*viciv1.ListConnectionsResponse, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	b, u, e := h.b(c, r.GetSocketUri())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := b.Connections(c, u)
	return &viciv1.ListConnectionsResponse{Connections: x}, shared.ToGRPC(e)
}
func (h *ViciHandler) GetConnection(c context.Context, r *viciv1.GetConnectionRequest) (*viciv1.StrongSwanConnection, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	b, u, e := h.b(c, r.GetSocketUri())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := b.Connections(c, u)
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	for _, v := range x {
		if v.GetName() == r.GetName() {
			return v, nil
		}
	}
	return nil, shared.ToGRPC(shared.NewError(shared.NotFound, "", "connection was not found"))
}
func (h *ViciHandler) ListPolicies(c context.Context, r *viciv1.ListViciPoliciesRequest) (*viciv1.ListViciPoliciesResponse, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	b, u, e := h.b(c, r.GetSocketUri())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := b.Policies(c, u)
	return &viciv1.ListViciPoliciesResponse{Policies: x}, shared.ToGRPC(e)
}
func (h *ViciHandler) ListAlgorithms(c context.Context, r *viciv1.ListAlgorithmsRequest) (*viciv1.ListAlgorithmsResponse, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	b, u, e := h.b(c, r.GetSocketUri())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := b.Algorithms(c, u)
	return &viciv1.ListAlgorithmsResponse{Algorithms: x}, shared.ToGRPC(e)
}
func (h *ViciHandler) GetCounters(c context.Context, r *viciv1.GetCountersRequest) (*viciv1.ViciCounters, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	b, u, e := h.b(c, r.GetSocketUri())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := b.Counters(c, u, r.GetConnectionName(), r.GetAllConnections())
	return x, shared.ToGRPC(e)
}
func (h *ViciHandler) ListCertificates(c context.Context, r *viciv1.ListCertificatesRequest) (*viciv1.ListCertificatesResponse, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	b, u, e := h.b(c, r.GetSocketUri())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := b.Certificates(c, u)
	return &viciv1.ListCertificatesResponse{Certificates: x}, shared.ToGRPC(e)
}
func (h *ViciHandler) ListAuthorities(c context.Context, r *viciv1.ListAuthoritiesRequest) (*viciv1.ListAuthoritiesResponse, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	b, u, e := h.b(c, r.GetSocketUri())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	x, e := b.Authorities(c, u)
	return &viciv1.ListAuthoritiesResponse{Authorities: x}, shared.ToGRPC(e)
}
func (h *ViciHandler) GetGatewaySnapshot(c context.Context, r *viciv1.GetGatewaySnapshotRequest) (*viciv1.GatewaySnapshot, error) {
	if e := h.valid(r); e != nil {
		return nil, shared.ToGRPC(e)
	}
	b, u, e := h.b(c, r.GetSocketUri())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	out := &viciv1.GatewaySnapshot{SnapshotTimestamp: shared.Timestamp(time.Now())}
	if x, e := b.DaemonStats(c, u); e == nil {
		out.DaemonStats = x
		out.PerSourceAvailability = append(out.PerSourceAvailability, &viciv1.SourceAvailability{Source: "stats", Available: true})
	} else {
		out.PerSourceAvailability = append(out.PerSourceAvailability, &viciv1.SourceAvailability{Source: "stats", Message: e.Error()})
	}
	if x, e := b.IkeSas(c, u); e == nil {
		out.IkeSas = x
		out.PerSourceAvailability = append(out.PerSourceAvailability, &viciv1.SourceAvailability{Source: "sas", Available: true})
	} else {
		out.PerSourceAvailability = append(out.PerSourceAvailability, &viciv1.SourceAvailability{Source: "sas", Message: e.Error()})
	}
	return out, nil
}
func (h *ViciHandler) StreamEvents(r *viciv1.StreamViciEventsRequest, stream viciv1.StrongSwanViciService_StreamEventsServer) error {
	if e := h.valid(r); e != nil {
		return shared.ToGRPC(e)
	}
	b, u, e := h.b(stream.Context(), r.GetSocketUri())
	if e != nil {
		return shared.ToGRPC(e)
	}
	ch, e := b.Events(stream.Context(), u, r.GetBufferSize())
	if e != nil {
		return shared.ToGRPC(e)
	}
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case x, ok := <-ch:
			if !ok {
				return nil
			}
			if e := stream.Send(x); e != nil {
				return e
			}
		}
	}
}
