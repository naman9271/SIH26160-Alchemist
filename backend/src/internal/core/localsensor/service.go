package localsensor

import "context"

type Dependency struct { Available bool; Reason string }
type Status struct { Ready bool; SensorVersion string; SessionActive bool; CaptureActive bool; PacketQueueDepth uint64; FeatureQueueDepth uint64; LastError string }
type Capabilities struct { PassiveLive, PassivePCAP, IPv4, IPv6, IKEv1, IKEv2, ESP, AH, NATT, FeatureWindows, SequenceSketches, VICI, XFRM bool }
type Probe struct { PassiveLive, PassivePCAP Dependency; VICI, XFRM Dependency }
type Provider interface { Status(context.Context)(Status,error); Capabilities(context.Context)(Capabilities,error); Probe(context.Context)(Probe,error) }
type Service struct{ provider Provider }
func New(provider Provider)*Service{return &Service{provider:provider}}
func(s *Service)Status(ctx context.Context)(Status,error){return s.provider.Status(ctx)}
func(s *Service)Capabilities(ctx context.Context)(Capabilities,error){return s.provider.Capabilities(ctx)}
func(s *Service)Probe(ctx context.Context)(Probe,error){return s.provider.Probe(ctx)}
