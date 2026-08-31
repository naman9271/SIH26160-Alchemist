package xfrm

import (
	"context"
	"fmt"
	"os"

	xfrmv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/xfrm"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const FixtureSchemaVersion = "xfrm.fixture.v1"

// FixtureProvider supplies a recorded, sanitized kernel snapshot. It never
// reads or modifies host XFRM state.
type FixtureProvider struct{ snapshot *xfrmv1.KernelSnapshot }

func LoadFixture(path string) (*FixtureProvider, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value := &xfrmv1.KernelSnapshot{}
	if err := protojson.Unmarshal(raw, value); err != nil {
		return nil, err
	}
	if err := validateFixture(value); err != nil {
		return nil, err
	}
	return &FixtureProvider{snapshot: value}, nil
}
func NewFixture(snapshot *xfrmv1.KernelSnapshot) (*FixtureProvider, error) {
	if err := validateFixture(snapshot); err != nil {
		return nil, err
	}
	return &FixtureProvider{snapshot: proto.Clone(snapshot).(*xfrmv1.KernelSnapshot)}, nil
}
func validateFixture(value *xfrmv1.KernelSnapshot) error {
	if value == nil {
		return fmt.Errorf("XFRM fixture is required")
	}
	if value.GetSchemaVersion() != FixtureSchemaVersion {
		return fmt.Errorf("unsupported XFRM fixture schema_version %q", value.GetSchemaVersion())
	}
	if value.GetSnapshotTimestamp() == nil || !value.GetSnapshotTimestamp().IsValid() {
		return fmt.Errorf("XFRM fixture snapshot_timestamp is required and must be valid")
	}
	for index, state := range value.GetStates() {
		if state == nil || state.GetSpi() == 0 || state.GetDestination() == "" {
			return fmt.Errorf("XFRM fixture states[%d] must include destination and non-zero spi", index)
		}
	}
	return nil
}
func (p *FixtureProvider) snapshotClone() *xfrmv1.KernelSnapshot {
	if p == nil || p.snapshot == nil {
		return &xfrmv1.KernelSnapshot{}
	}
	return proto.Clone(p.snapshot).(*xfrmv1.KernelSnapshot)
}
func (p *FixtureProvider) Capabilities(context.Context) (*xfrmv1.XfrmCapabilities, error) {
	return &xfrmv1.XfrmCapabilities{Available: true, StateQuery: true, PolicyQuery: true, ReplayInformation: true}, nil
}
func (p *FixtureProvider) States(context.Context) ([]*xfrmv1.XfrmState, error) {
	return p.snapshotClone().GetStates(), nil
}
func (p *FixtureProvider) Policies(context.Context) ([]*xfrmv1.XfrmPolicy, error) {
	return p.snapshotClone().GetPolicies(), nil
}

var _ Provider = (*FixtureProvider)(nil)
