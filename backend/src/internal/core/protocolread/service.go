// Package protocolread presents existing Sensor and Fusion data as frontend-ready
// protocol views. It owns no packet parser, evidence store, or session state.
package protocolread

import (
	"context"
	"fmt"
	"sort"
	"strings"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	protocolv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/protocolread"
	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/query"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/acquisition"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/flow"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/session"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// RunResolver protects Core clients from internal Fusion run IDs.
type RunResolver interface {
	FusionRunID(context.Context, string) (string, error)
}
type EvidenceReader interface {
	List(context.Context, query.ListRequest) (query.ListResponse, error)
}

type Service struct {
	resolver RunResolver
	evidence EvidenceReader
	sensor   acquisition.Services
}

func New(resolver RunResolver, evidence EvidenceReader, sensor acquisition.Services) *Service {
	return &Service{resolver: resolver, evidence: evidence, sensor: sensor}
}

// WorkspaceRunResolver is the production bridge between a public analysis ID
// and the current Core workspace's private Fusion run ID.
type WorkspaceRunResolver struct{ Workspace *workspace.Service }

func (r WorkspaceRunResolver) FusionRunID(ctx context.Context, analysisID string) (string, error) {
	if r.Workspace == nil {
		return "", shared.NewError(shared.Internal, "", "workspace service is not configured")
	}
	record, err := r.Workspace.Get(ctx, "")
	if err != nil {
		return "", err
	}
	if record.AnalysisID != analysisID {
		return "", shared.NewError(shared.NotFound, "", "analysis was not found in the current workspace")
	}
	return record.FusionRunID, nil
}

func (s *Service) evidenceFor(ctx context.Context, analysisID string, filter query.Filter, size uint32, token string) (query.ListResponse, error) {
	if s == nil || s.resolver == nil || s.evidence == nil {
		return query.ListResponse{}, shared.NewError(shared.Internal, "", "protocol read dependencies are not configured")
	}
	if strings.TrimSpace(analysisID) == "" {
		return query.ListResponse{}, shared.NewError(shared.InvalidArgument, "", "analysis_id is required")
	}
	runID, err := s.resolver.FusionRunID(ctx, analysisID)
	if err != nil {
		return query.ListResponse{}, err
	}
	if strings.TrimSpace(runID) == "" {
		return query.ListResponse{}, shared.NewError(shared.FailedPrecondition, "", "analysis has no Fusion evidence run")
	}
	return s.evidence.List(ctx, query.ListRequest{FusionRunID: runID, Filter: filter, PageSize: size, PageToken: token})
}

func (s *Service) allEvidence(ctx context.Context, analysisID string) ([]model.EvidenceItem, error) {
	response, err := s.evidenceFor(ctx, analysisID, query.Filter{}, 1000, "")
	if err != nil {
		return nil, err
	}
	return response.Evidence, nil
}

// EvidenceItems is intentionally model-level so Security can evaluate the
// exact normalized evidence without serializing it through a second API shape.
func (s *Service) EvidenceItems(ctx context.Context, analysisID string) ([]model.EvidenceItem, error) {
	return s.allEvidence(ctx, analysisID)
}

func (s *Service) Summary(ctx context.Context, analysisID string) (*protocolv1.ProtocolSummary, error) {
	items, err := s.allEvidence(ctx, analysisID)
	if err != nil {
		return nil, err
	}
	result := &protocolv1.ProtocolSummary{AnalysisId: analysisID, EvidenceStatus: commonv1.EvidenceStatus_UNKNOWN}
	values := newestByProperty(items)
	if item, ok := values["ike.version"]; ok {
		result.IkeVersion, result.EvidenceStatus, result.Confidence = value(item), item.Status, item.Confidence
		result.IpsecDetected = true
	}
	if item, ok := values["child.protocol"]; ok {
		result.DataProtocol = value(item)
		result.IpsecDetected = true
	}
	if result.DataProtocol == "" {
		if hasResource(items, "ESP_STREAM") {
			result.DataProtocol, result.IpsecDetected = "ESP", true
		}
	}
	if item, ok := values["child.mode"]; ok {
		result.VpnMode = value(item)
	}
	if !result.IpsecDetected {
		result.UnavailableReasons = append(result.UnavailableReasons, "No IKE, ESP, or AH evidence is available")
	}
	if result.IkeVersion == "" {
		result.UnavailableReasons = append(result.UnavailableReasons, "IKE version is unavailable")
	}
	if result.VpnMode == "" {
		result.UnavailableReasons = append(result.UnavailableReasons, "VPN mode is unavailable")
	}
	return result, nil
}

func (s *Service) Sessions(ctx context.Context, analysisID string, pageSize uint32, token string) ([]*protocolv1.VpnSession, string, error) {
	if _, err := s.allEvidence(ctx, analysisID); err != nil {
		return nil, "", err
	}
	if s.sensor.Sessions == nil {
		return nil, "", shared.NewError(shared.Internal, "", "sensor session service is not configured")
	}
	items, err := s.sensor.Sessions.List(ctx)
	if err != nil {
		return nil, "", err
	}
	start, end, next, err := page(items, pageSize, token, func(item session.Session) string { return item.ID })
	if err != nil {
		return nil, "", err
	}
	result := make([]*protocolv1.VpnSession, 0, end-start)
	for _, item := range items[start:end] {
		result = append(result, s.sessionView(ctx, item))
	}
	return result, next, nil
}

func (s *Service) Session(ctx context.Context, analysisID, id string) (*protocolv1.VpnSession, error) {
	if _, err := s.allEvidence(ctx, analysisID); err != nil {
		return nil, err
	}
	if s.sensor.Sessions == nil {
		return nil, shared.NewError(shared.Internal, "", "sensor session service is not configured")
	}
	item, err := s.sensor.Sessions.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.sessionView(ctx, item), nil
}

func (s *Service) sessionView(ctx context.Context, item session.Session) *protocolv1.VpnSession {
	result := &protocolv1.VpnSession{SessionId: item.ID, State: item.State, Mode: item.Mode.String(), EvidenceStatus: commonv1.EvidenceStatus_UNKNOWN}
	if s.sensor.Flows != nil {
		flows, _, err := s.sensor.Flows.List(ctx, &flowv1.ListFlowsRequest{SensorSessionId: item.ID, PageSize: 1000})
		if err == nil {
			for _, record := range flows {
				proto := flow.ToProto(record)
				result.FlowIds = append(result.FlowIds, proto.GetFlowId())
				if proto.GetSpi() != 0 {
					result.SpiValues = append(result.SpiValues, fmt.Sprintf("0x%08x", proto.GetSpi()))
				}
			}
		}
	}
	if len(result.FlowIds) > 0 {
		result.EvidenceStatus = commonv1.EvidenceStatus_DERIVED
	}
	return result
}

func (s *Service) IKE(ctx context.Context, analysisID, sessionID string, size uint32, token string) ([]*protocolv1.IkeExchange, string, error) {
	response, err := s.evidenceFor(ctx, analysisID, query.Filter{ResourceType: "IKE_SA"}, size, token)
	if err != nil {
		return nil, "", err
	}
	byID := map[string]*protocolv1.IkeExchange{}
	for _, item := range response.Evidence {
		if sessionID != "" && item.Metadata["sensor_session_id"] != sessionID {
			continue
		}
		row := byID[item.ResourceID]
		if row == nil {
			row = &protocolv1.IkeExchange{ExchangeId: item.ResourceID, SessionId: item.Metadata["sensor_session_id"], EvidenceStatus: item.Status, Confidence: item.Confidence, ObservedAt: timestamppb.New(item.ObservedAt)}
			byID[item.ResourceID] = row
		}
		switch item.PropertyKey {
		case "ike.version":
			row.IkeVersion = value(item)
		case "ike.initiator_spi":
			row.InitiatorSpi = value(item)
		case "ike.responder_spi":
			row.ResponderSpi = value(item)
		}
	}
	rows := make([]*protocolv1.IkeExchange, 0, len(byID))
	for _, row := range byID {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ExchangeId < rows[j].ExchangeId })
	return rows, response.NextPageToken, nil
}

func (s *Service) SAs(ctx context.Context, analysisID, sessionID string, size uint32, token string) ([]*protocolv1.SecurityAssociation, string, error) {
	response, err := s.evidenceFor(ctx, analysisID, query.Filter{}, size, token)
	if err != nil {
		return nil, "", err
	}
	rows := map[string]*protocolv1.SecurityAssociation{}
	for _, item := range response.Evidence {
		if item.ResourceType != "CHILD_SA" && item.ResourceType != "ESP_STREAM" {
			continue
		}
		if sessionID != "" && item.Metadata["sensor_session_id"] != sessionID {
			continue
		}
		row := rows[item.ResourceID]
		if row == nil {
			row = &protocolv1.SecurityAssociation{SecurityAssociationId: item.ResourceID, SessionId: item.Metadata["sensor_session_id"], EvidenceStatus: item.Status, Confidence: item.Confidence}
			rows[item.ResourceID] = row
		}
		switch item.PropertyKey {
		case "child.protocol":
			row.Protocol = value(item)
		case "child.mode":
			row.Mode = value(item)
		case "child.state":
			row.State = value(item)
		case "child.spi", "esp.spi":
			row.SpiValues = append(row.SpiValues, value(item))
		}
	}
	out := make([]*protocolv1.SecurityAssociation, 0, len(rows))
	for _, row := range rows {
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SecurityAssociationId < out[j].SecurityAssociationId })
	return out, response.NextPageToken, nil
}

func (s *Service) SA(ctx context.Context, analysisID, id string) (*protocolv1.SecurityAssociation, error) {
	rows, _, err := s.SAs(ctx, analysisID, "", 1000, "")
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.SecurityAssociationId == id {
			return row, nil
		}
	}
	return nil, shared.NewError(shared.NotFound, "", "security association was not found")
}

func (s *Service) Crypto(ctx context.Context, analysisID, sessionID string, size uint32, token string) ([]*protocolv1.CryptoProperty, string, error) {
	response, err := s.evidenceFor(ctx, analysisID, query.Filter{}, size, token)
	if err != nil {
		return nil, "", err
	}
	allowed := map[string]bool{"ike.encryption": true, "ike.integrity": true, "ike.prf": true, "ike.dh_group": true, "child.encryption_algorithm": true, "child.integrity_algorithm": true, "child.pfs": true, "child.lifetime_seconds": true}
	out := make([]*protocolv1.CryptoProperty, 0)
	for _, item := range response.Evidence {
		if !allowed[item.PropertyKey] || sessionID != "" && item.Metadata["sensor_session_id"] != sessionID {
			continue
		}
		out = append(out, &protocolv1.CryptoProperty{Name: item.PropertyKey, Value: value(item), ResourceId: item.ResourceID, Source: string(item.Source), EvidenceStatus: item.Status, Confidence: item.Confidence})
	}
	return out, response.NextPageToken, nil
}

func (s *Service) NAT(ctx context.Context, analysisID, sessionID string) (*protocolv1.NatTraversalSummary, error) {
	if _, err := s.allEvidence(ctx, analysisID); err != nil {
		return nil, err
	}
	result := &protocolv1.NatTraversalSummary{EvidenceStatus: commonv1.EvidenceStatus_UNKNOWN, UnavailableReason: "No NAT-T observation is available"}
	if s.sensor.Flows == nil {
		return result, nil
	}
	flows, _, err := s.sensor.Flows.List(ctx, &flowv1.ListFlowsRequest{SensorSessionId: sessionID, PageSize: 1000, Protocol: flowv1.FlowProtocol_NAT_T})
	if err != nil {
		return nil, err
	}
	for _, record := range flows {
		result.Observed = true
		result.NatTPackets += flow.ToProto(record).GetPacketCount()
	}
	if result.Observed {
		result.EvidenceStatus = commonv1.EvidenceStatus_OBSERVED
		result.UnavailableReason = ""
	}
	return result, nil
}

func (s *Service) Timeline(ctx context.Context, analysisID, sessionID string, size uint32, token string) ([]*protocolv1.TimelineEvent, string, error) {
	response, err := s.evidenceFor(ctx, analysisID, query.Filter{}, size, token)
	if err != nil {
		return nil, "", err
	}
	out := make([]*protocolv1.TimelineEvent, 0, len(response.Evidence))
	for _, item := range response.Evidence {
		if sessionID != "" && item.Metadata["sensor_session_id"] != sessionID {
			continue
		}
		out = append(out, &protocolv1.TimelineEvent{EventId: item.ID, EventType: item.PropertyKey, Message: value(item), ObservedAt: timestamppb.New(item.ObservedAt), EvidenceStatus: item.Status})
	}
	return out, response.NextPageToken, nil
}

func (s *Service) Evidence(ctx context.Context, analysisID string, filter query.Filter, size uint32, token string) ([]*protocolv1.ProtocolEvidence, string, error) {
	response, err := s.evidenceFor(ctx, analysisID, filter, size, token)
	if err != nil {
		return nil, "", err
	}
	out := make([]*protocolv1.ProtocolEvidence, 0, len(response.Evidence))
	for _, item := range response.Evidence {
		out = append(out, &protocolv1.ProtocolEvidence{EvidenceId: item.ID, PropertyKey: item.PropertyKey, Value: value(item), Source: string(item.Source), EvidenceStatus: item.Status, Confidence: item.Confidence, ResourceType: item.ResourceType, ResourceId: item.ResourceID, ObservedAt: timestamppb.New(item.ObservedAt), Metadata: item.Metadata})
	}
	return out, response.NextPageToken, nil
}

func newestByProperty(items []model.EvidenceItem) map[string]model.EvidenceItem {
	result := map[string]model.EvidenceItem{}
	for _, item := range items {
		if old, ok := result[item.PropertyKey]; !ok || item.ObservedAt.After(old.ObservedAt) {
			result[item.PropertyKey] = item
		}
	}
	return result
}
func hasResource(items []model.EvidenceItem, kind string) bool {
	for _, item := range items {
		if item.ResourceType == kind {
			return true
		}
	}
	return false
}
func value(item model.EvidenceItem) string {
	if item.Value == nil || item.Value.GetKind() == nil {
		return ""
	}
	return fmt.Sprint(item.Value.AsInterface())
}
func page[T any](items []T, size uint32, token string, id func(T) string) (int, int, string, error) {
	if size == 0 {
		size = 100
	}
	if size > 1000 {
		return 0, 0, "", shared.NewError(shared.InvalidArgument, "", "page_size must not exceed 1000")
	}
	start := 0
	for start < len(items) && token != "" && id(items[start]) <= token {
		start++
	}
	end := start + int(size)
	if end > len(items) {
		end = len(items)
	}
	next := ""
	if end < len(items) {
		next = id(items[end-1])
	}
	return start, end, next, nil
}
