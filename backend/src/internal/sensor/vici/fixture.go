package vici

// FixtureBackend is a read-only recorded StrongSwan gateway collector. It is
// intended for deterministic integration tests and never opens a VICI socket.

import (
	"context"
	"os"

	viciv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/vici"
	"google.golang.org/protobuf/encoding/protojson"
)

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
	return &FixtureBackend{snapshot: value}, nil
}
func (b *FixtureBackend) Capabilities(context.Context, string) (*viciv1.ViciCapabilities, error) {
	return &viciv1.ViciCapabilities{ListSas: true, ListConnections: true, ListPolicies: true, ListAlgorithms: true, Stats: true, Counters: true, ListCertificates: true, ListAuthorities: true}, nil
}
func (b *FixtureBackend) DaemonStats(context.Context, string) (*viciv1.ViciDaemonStats, error) {
	return b.snapshot.GetDaemonStats(), nil
}
func (b *FixtureBackend) IkeSas(context.Context, string) ([]*viciv1.IkeSa, error) {
	return b.snapshot.GetIkeSas(), nil
}
func (b *FixtureBackend) ChildSas(context.Context, string) ([]*viciv1.ChildSa, error) {
	return b.snapshot.GetChildSas(), nil
}
func (b *FixtureBackend) Connections(context.Context, string) ([]*viciv1.StrongSwanConnection, error) {
	return b.snapshot.GetConnections(), nil
}
func (b *FixtureBackend) Policies(context.Context, string) ([]*viciv1.ViciPolicy, error) {
	return b.snapshot.GetPolicies(), nil
}
func (b *FixtureBackend) Algorithms(context.Context, string) ([]*viciv1.ViciAlgorithm, error) {
	return b.snapshot.GetAlgorithms(), nil
}
func (b *FixtureBackend) Counters(context.Context, string, string, bool) (*viciv1.ViciCounters, error) {
	return b.snapshot.GetCounters(), nil
}
func (b *FixtureBackend) Certificates(context.Context, string) ([]*viciv1.Certificate, error) {
	return b.snapshot.GetCertificates(), nil
}
func (b *FixtureBackend) Authorities(context.Context, string) ([]*viciv1.Authority, error) {
	return b.snapshot.GetAuthorities(), nil
}
func (b *FixtureBackend) Events(context.Context, string, uint32) (<-chan *viciv1.ViciEvent, error) {
	ch := make(chan *viciv1.ViciEvent)
	close(ch)
	return ch, nil
}

var _ Backend = (*FixtureBackend)(nil)
