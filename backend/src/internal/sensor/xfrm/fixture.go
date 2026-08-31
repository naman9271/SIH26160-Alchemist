package xfrm

import (
	"context"
	"os"

	xfrmv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/xfrm"
	"google.golang.org/protobuf/encoding/protojson"
)

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
	return &FixtureProvider{snapshot: value}, nil
}
func (p *FixtureProvider) Capabilities(context.Context) (*xfrmv1.XfrmCapabilities, error) {
	return &xfrmv1.XfrmCapabilities{Available: true, StateQuery: true, PolicyQuery: true, ReplayInformation: true}, nil
}
func (p *FixtureProvider) States(context.Context) ([]*xfrmv1.XfrmState, error) {
	return p.snapshot.GetStates(), nil
}
func (p *FixtureProvider) Policies(context.Context) ([]*xfrmv1.XfrmPolicy, error) {
	return p.snapshot.GetPolicies(), nil
}

var _ Provider = (*FixtureProvider)(nil)
