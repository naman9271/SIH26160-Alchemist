//go:build linux

package xfrm

import (
	"context"
	"fmt"
	"strings"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	xfrmv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/xfrm"
	"github.com/vishvananda/netlink"
)

type NetlinkProvider struct{}

func NewRealProvider() Provider { return &NetlinkProvider{} }
func (p *NetlinkProvider) Capabilities(ctx context.Context) (*xfrmv1.XfrmCapabilities, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := netlink.XfrmStateList(netlink.FAMILY_ALL); err != nil {
		return nil, err
	}
	return &xfrmv1.XfrmCapabilities{Available: true, StateQuery: true, PolicyQuery: true, ReplayInformation: true}, nil
}
func (p *NetlinkProvider) States(ctx context.Context) ([]*xfrmv1.XfrmState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	result := make([]*xfrmv1.XfrmState, 0, len(states))
	for _, state := range states {
		item := &xfrmv1.XfrmState{Source: state.Src.String(), Destination: state.Dst.String(), Protocol: stringsUpper(state.Proto.String()), Spi: uint32(state.Spi), Reqid: uint32(state.Reqid), Mode: stringsUpper(state.Mode.String()), Direction: fmt.Sprint(state.SADir), ReplayWindow: uint32(state.ReplayWindow), ExtendedSequenceNumbers: state.ESN, ByteLimit: state.Limits.ByteHard, PacketLimit: state.Limits.PacketHard, Bytes: state.Statistics.Bytes, Packets: state.Statistics.Packets, EvidenceStatus: commonv1.EvidenceStatus_VERIFIED_GATEWAY}
		if state.Crypt != nil {
			item.EncryptionAlgorithm, item.EncryptionKeyLength = state.Crypt.Name, uint32(len(state.Crypt.Key)*8)
		}
		if state.Aead != nil {
			item.AeadAlgorithm, item.EncryptionKeyLength, item.AeadIcvLength = state.Aead.Name, uint32(len(state.Aead.Key)*8), uint32(state.Aead.ICVLen)
		}
		if state.Auth != nil {
			item.AuthenticationAlgorithm = state.Auth.Name
		}
		if state.Encap != nil {
			item.Encapsulation = state.Encap.Type.String()
		}
		if state.Replay != nil {
			item.Sequence = uint64(state.Replay.Seq)
		}
		result = append(result, item)
	}
	return result, nil
}
func (p *NetlinkProvider) Policies(ctx context.Context) ([]*xfrmv1.XfrmPolicy, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	result := make([]*xfrmv1.XfrmPolicy, 0, len(policies))
	for _, policy := range policies {
		item := &xfrmv1.XfrmPolicy{Direction: stringsUpper(policy.Dir.String()), Priority: uint32(policy.Priority), Protocol: stringsUpper(policy.Proto.String()), EvidenceStatus: commonv1.EvidenceStatus_VERIFIED_GATEWAY}
		if policy.Src != nil {
			item.SourceSelector = policy.Src.String()
		}
		if policy.Dst != nil {
			item.DestinationSelector = policy.Dst.String()
		}
		if len(policy.Tmpls) > 0 {
			template := policy.Tmpls[0]
			item.SourceTemplate, item.DestinationTemplate, item.Reqid, item.Mode = template.Src.String(), template.Dst.String(), uint32(template.Reqid), stringsUpper(template.Mode.String())
			if item.Protocol == "" {
				item.Protocol = stringsUpper(template.Proto.String())
			}
		}
		result = append(result, item)
	}
	return result, nil
}
func stringsUpper(value string) string { return strings.ToUpper(value) }

var _ Provider = (*NetlinkProvider)(nil)
