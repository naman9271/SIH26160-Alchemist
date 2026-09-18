// Package xfrm provides a read-only, sanitized kernel IPsec boundary.
package xfrm

import (
	"context"
	"strings"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	xfrmv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/xfrm"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Provider must only return sanitized state: no key bytes or secret material.
type Provider interface {
	Capabilities(context.Context) (*xfrmv1.XfrmCapabilities, error)
	States(context.Context) ([]*xfrmv1.XfrmState, error)
	Policies(context.Context) ([]*xfrmv1.XfrmPolicy, error)
}
type Service struct{ provider Provider }

func New(p Provider) *Service { return &Service{provider: p} }
func (s *Service) Capabilities(ctx context.Context) (*xfrmv1.XfrmCapabilities, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.provider == nil {
		return &xfrmv1.XfrmCapabilities{}, shared.NewError(shared.Unavailable, shared.XFRMUnavailable, "Linux XFRM Netlink is unavailable on this platform")
	}
	return s.provider.Capabilities(ctx)
}
func (s *Service) States(ctx context.Context, r *xfrmv1.ListXfrmStatesRequest) ([]*xfrmv1.XfrmState, string, error) {
	if r == nil {
		return nil, "", shared.NewError(shared.InvalidArgument, "", "request is required")
	}
	if r.GetSource() != "" && !validIP(r.GetSource()) || r.GetDestination() != "" && !validIP(r.GetDestination()) {
		return nil, "", shared.NewError(shared.InvalidArgument, "", "source and destination must be valid IP addresses")
	}
	if r.GetProtocol() != "" && !validProtocol(r.GetProtocol()) {
		return nil, "", shared.NewError(shared.InvalidArgument, "", "protocol must be ESP, AH, or COMP")
	}
	if _, e := s.Capabilities(ctx); e != nil {
		return nil, "", e
	}
	all, e := s.provider.States(ctx)
	if e != nil {
		return nil, "", e
	}
	out := make([]*xfrmv1.XfrmState, 0, len(all))
	for _, v := range all {
		if (r.GetSource() == "" || v.GetSource() == r.GetSource()) && (r.GetDestination() == "" || v.GetDestination() == r.GetDestination()) && (r.GetProtocol() == "" || strings.EqualFold(v.GetProtocol(), r.GetProtocol())) && (r.GetSpi() == 0 || v.GetSpi() == r.GetSpi()) && (r.GetReqid() == 0 || v.GetReqid() == r.GetReqid()) && (r.GetMode() == "" || v.GetMode() == r.GetMode()) {
			v.EvidenceStatus = commonv1.EvidenceStatus_VERIFIED_GATEWAY
			out = append(out, v)
		}
	}
	return out, "", nil
}
func (s *Service) Policies(ctx context.Context, r *xfrmv1.ListXfrmPoliciesRequest) ([]*xfrmv1.XfrmPolicy, string, error) {
	if r == nil {
		return nil, "", shared.NewError(shared.InvalidArgument, "", "request is required")
	}
	if _, e := s.Capabilities(ctx); e != nil {
		return nil, "", e
	}
	all, e := s.provider.Policies(ctx)
	if e != nil {
		return nil, "", e
	}
	out := make([]*xfrmv1.XfrmPolicy, 0, len(all))
	for _, v := range all {
		if (r.GetDirection() == "" || v.GetDirection() == r.GetDirection()) && (r.GetReqid() == 0 || v.GetReqid() == r.GetReqid()) {
			v.EvidenceStatus = commonv1.EvidenceStatus_VERIFIED_GATEWAY
			out = append(out, v)
		}
	}
	return out, "", nil
}

func (s *Service) Snapshot(ctx context.Context) (*xfrmv1.KernelSnapshot, error) {
	states, _, err := s.States(ctx, &xfrmv1.ListXfrmStatesRequest{})
	if err != nil {
		return nil, err
	}
	policies, _, err := s.Policies(ctx, &xfrmv1.ListXfrmPoliciesRequest{})
	if err != nil {
		return nil, err
	}
	out := &xfrmv1.KernelSnapshot{SchemaVersion: FixtureSchemaVersion, States: states, Policies: policies, SnapshotTimestamp: timestamppb.New(time.Now().UTC())}
	for _, state := range states {
		if !state.GetReplayApplicable() {
			continue
		}
		out.ReplayProtection = append(out.ReplayProtection, &xfrmv1.ReplayProtection{Available: true, Enabled: state.GetReplayWindow() > 0,
			ReplayWindow: state.GetReplayWindow(), Sequence: state.GetSequence(), ExtendedSequenceNumbers: state.GetExtendedSequenceNumbers(), EvidenceStatus: commonv1.EvidenceStatus_VERIFIED_GATEWAY})
	}
	out.Availability = []*xfrmv1.ComponentAvailability{{Component: "states", Available: true}, {Component: "policies", Available: true}}
	return out, nil
}
func validIP(v string) bool {
	p := strings.Split(v, ".")
	return len(p) == 4 || strings.Contains(v, ":")
}
func validProtocol(v string) bool {
	v = strings.ToUpper(v)
	return v == "ESP" || v == "AH" || v == "COMP"
}
