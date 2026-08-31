package vici

// FixtureBackend is a read-only recorded StrongSwan gateway collector. It is
// intended for deterministic integration tests and never opens a VICI socket.

import (
	"context"
	"fmt"
	"os"
	"strings"

	viciv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/vici"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const FixtureSchemaVersion = "vici.fixture.v1"

type FixtureBackend struct{ snapshot *viciv1.GatewaySnapshot }

func LoadFixture(path string) (*FixtureBackend, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value := &viciv1.GatewaySnapshot{}
	if err := protojson.Unmarshal(raw, value); err != nil {
		return nil, err
	}
	if err := validateFixture(value); err != nil {
		return nil, err
	}
	return &FixtureBackend{snapshot: value}, nil
}

func NewFixture(snapshot *viciv1.GatewaySnapshot) (*FixtureBackend, error) {
	if err := validateFixture(snapshot); err != nil {
		return nil, err
	}
	return &FixtureBackend{snapshot: proto.Clone(snapshot).(*viciv1.GatewaySnapshot)}, nil
}

func validateFixture(value *viciv1.GatewaySnapshot) error {
	if value == nil {
		return fmt.Errorf("VICI fixture is required")
	}
	if value.GetSchemaVersion() != FixtureSchemaVersion {
		return fmt.Errorf("unsupported VICI fixture schema_version %q", value.GetSchemaVersion())
	}
	if value.GetSnapshotTimestamp() == nil || !value.GetSnapshotTimestamp().IsValid() {
		return fmt.Errorf("VICI fixture snapshot_timestamp is required and must be valid")
	}
	for index, ike := range value.GetIkeSas() {
		if ike == nil || ike.GetUniqueId() == 0 || strings.TrimSpace(ike.GetName()) == "" {
			return fmt.Errorf("VICI fixture ike_sas[%d] must include name and unique_id", index)
		}
	}
	for index, child := range value.GetChildSas() {
		if child == nil || child.GetUniqueId() == 0 || strings.TrimSpace(child.GetName()) == "" {
			return fmt.Errorf("VICI fixture child_sas[%d] must include name and unique_id", index)
		}
	}
	return nil
}

func (b *FixtureBackend) snapshotClone() *viciv1.GatewaySnapshot {
	if b == nil || b.snapshot == nil {
		return &viciv1.GatewaySnapshot{}
	}
	return proto.Clone(b.snapshot).(*viciv1.GatewaySnapshot)
}
func (b *FixtureBackend) Capabilities(context.Context, string) (*viciv1.ViciCapabilities, error) {
	return &viciv1.ViciCapabilities{ListSas: true, ListConnections: true, ListPolicies: true, ListAlgorithms: true, Stats: true, Counters: true, ListCertificates: true, ListAuthorities: true}, nil
}
func (b *FixtureBackend) DaemonStats(context.Context, string) (*viciv1.ViciDaemonStats, error) {
	return b.snapshotClone().GetDaemonStats(), nil
}
func (b *FixtureBackend) IkeSas(context.Context, string) ([]*viciv1.IkeSa, error) {
	return b.snapshotClone().GetIkeSas(), nil
}
func (b *FixtureBackend) ChildSas(context.Context, string) ([]*viciv1.ChildSa, error) {
	return b.snapshotClone().GetChildSas(), nil
}
func (b *FixtureBackend) Connections(context.Context, string) ([]*viciv1.StrongSwanConnection, error) {
	return b.snapshotClone().GetConnections(), nil
}
func (b *FixtureBackend) Policies(context.Context, string) ([]*viciv1.ViciPolicy, error) {
	return b.snapshotClone().GetPolicies(), nil
}
func (b *FixtureBackend) Algorithms(context.Context, string) ([]*viciv1.ViciAlgorithm, error) {
	return b.snapshotClone().GetAlgorithms(), nil
}
func (b *FixtureBackend) Counters(context.Context, string, string, bool) (*viciv1.ViciCounters, error) {
	return b.snapshotClone().GetCounters(), nil
}
func (b *FixtureBackend) Certificates(context.Context, string) ([]*viciv1.Certificate, error) {
	return b.snapshotClone().GetCertificates(), nil
}
func (b *FixtureBackend) Authorities(context.Context, string) ([]*viciv1.Authority, error) {
	return b.snapshotClone().GetAuthorities(), nil
}
func (b *FixtureBackend) Events(context.Context, string, uint32) (<-chan *viciv1.ViciEvent, error) {
	ch := make(chan *viciv1.ViciEvent)
	close(ch)
	return ch, nil
}

var _ Backend = (*FixtureBackend)(nil)
