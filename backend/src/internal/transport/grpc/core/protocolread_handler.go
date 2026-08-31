package core

import (
	"context"

	protocolv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/protocolread"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/protocolread"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/query"
)

type ProtocolReadHandler struct {
	protocolv1.UnimplementedProtocolReadServiceServer
	service *protocolread.Service
}

func NewProtocolReadHandler(service *protocolread.Service) *ProtocolReadHandler {
	return &ProtocolReadHandler{service: service}
}
func (h *ProtocolReadHandler) valid() error {
	if h == nil || h.service == nil {
		return shared.NewError(shared.Internal, "", "protocol read service is not configured")
	}
	return nil
}
func (h *ProtocolReadHandler) GetSummary(ctx context.Context, r *protocolv1.GetProtocolSummaryRequest) (*protocolv1.ProtocolSummary, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Summary(ctx, r.GetAnalysisId())
	return v, shared.ToGRPC(e)
}
func (h *ProtocolReadHandler) ListSessions(ctx context.Context, r *protocolv1.ListSessionsRequest) (*protocolv1.ListSessionsResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, n, e := h.service.Sessions(ctx, r.GetAnalysisId(), r.GetPageSize(), r.GetPageToken())
	return &protocolv1.ListSessionsResponse{Sessions: v, NextPageToken: n}, shared.ToGRPC(e)
}
func (h *ProtocolReadHandler) GetSession(ctx context.Context, r *protocolv1.GetSessionRequest) (*protocolv1.VpnSession, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Session(ctx, r.GetAnalysisId(), r.GetSessionId())
	return v, shared.ToGRPC(e)
}
func (h *ProtocolReadHandler) ListIkeExchanges(ctx context.Context, r *protocolv1.ListIkeExchangesRequest) (*protocolv1.ListIkeExchangesResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, n, e := h.service.IKE(ctx, r.GetAnalysisId(), r.GetSessionId(), r.GetPageSize(), r.GetPageToken())
	return &protocolv1.ListIkeExchangesResponse{Exchanges: v, NextPageToken: n}, shared.ToGRPC(e)
}
func (h *ProtocolReadHandler) ListSecurityAssociations(ctx context.Context, r *protocolv1.ListSecurityAssociationsRequest) (*protocolv1.ListSecurityAssociationsResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, n, e := h.service.SAs(ctx, r.GetAnalysisId(), r.GetSessionId(), r.GetPageSize(), r.GetPageToken())
	return &protocolv1.ListSecurityAssociationsResponse{SecurityAssociations: v, NextPageToken: n}, shared.ToGRPC(e)
}
func (h *ProtocolReadHandler) GetSecurityAssociation(ctx context.Context, r *protocolv1.GetSecurityAssociationRequest) (*protocolv1.SecurityAssociation, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.SA(ctx, r.GetAnalysisId(), r.GetSecurityAssociationId())
	return v, shared.ToGRPC(e)
}
func (h *ProtocolReadHandler) ListCryptoProperties(ctx context.Context, r *protocolv1.ListCryptoPropertiesRequest) (*protocolv1.ListCryptoPropertiesResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, n, e := h.service.Crypto(ctx, r.GetAnalysisId(), r.GetSessionId(), r.GetPageSize(), r.GetPageToken())
	return &protocolv1.ListCryptoPropertiesResponse{Properties: v, NextPageToken: n}, shared.ToGRPC(e)
}
func (h *ProtocolReadHandler) GetNatTraversal(ctx context.Context, r *protocolv1.GetNatTraversalRequest) (*protocolv1.NatTraversalSummary, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.NAT(ctx, r.GetAnalysisId(), r.GetSessionId())
	return v, shared.ToGRPC(e)
}
func (h *ProtocolReadHandler) GetTimeline(ctx context.Context, r *protocolv1.GetTimelineRequest) (*protocolv1.ProtocolTimeline, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, n, e := h.service.Timeline(ctx, r.GetAnalysisId(), r.GetSessionId(), r.GetPageSize(), r.GetPageToken())
	return &protocolv1.ProtocolTimeline{Events: v, NextPageToken: n}, shared.ToGRPC(e)
}
func (h *ProtocolReadHandler) ListEvidence(ctx context.Context, r *protocolv1.ListProtocolEvidenceRequest) (*protocolv1.ListProtocolEvidenceResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, n, e := h.service.Evidence(ctx, r.GetAnalysisId(), query.Filter{PropertyKey: r.GetPropertyKey(), ResourceType: r.GetResourceType(), ResourceID: r.GetResourceId()}, r.GetPageSize(), r.GetPageToken())
	return &protocolv1.ListProtocolEvidenceResponse{Evidence: v, NextPageToken: n}, shared.ToGRPC(e)
}
