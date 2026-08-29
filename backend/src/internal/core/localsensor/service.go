package localsensor

import (
	"context"
	"errors"
)

type Dependency struct {
	Available bool
	Reason    string
}

type Status struct {
	Ready, SessionActive, CaptureActive bool
	SensorVersion, LastError            string
	PacketQueueDepth, FeatureQueueDepth uint64
}

type Capabilities struct {
	PassiveLive, PassivePCAP, IPv4, IPv6, IKEv1, IKEv2, ESP, AH, NATT bool
	FeatureWindows, SequenceSketches, VICI, XFRM                      bool
}

type Probe struct{ PassiveLive, PassivePCAP, VICI, XFRM Dependency }

type Provider interface {
	SensorStatus(context.Context) (Status, error)
	SensorCapabilities(context.Context) (Capabilities, error)
	SensorProbe(context.Context) (Probe, error)
}

type Service struct{ provider Provider }

func New(provider Provider) *Service { return &Service{provider: provider} }

func (s *Service) Status(ctx context.Context) (Status, error) {
	if s == nil || s.provider == nil {
		return Status{}, errors.New("local sensor provider is not configured")
	}
	return s.provider.SensorStatus(ctx)
}

func (s *Service) Capabilities(ctx context.Context) (Capabilities, error) {
	if s == nil || s.provider == nil {
		return Capabilities{}, errors.New("local sensor provider is not configured")
	}
	return s.provider.SensorCapabilities(ctx)
}

func (s *Service) Probe(ctx context.Context) (Probe, error) {
	if s == nil || s.provider == nil {
		return Probe{}, errors.New("local sensor provider is not configured")
	}
	return s.provider.SensorProbe(ctx)
}
