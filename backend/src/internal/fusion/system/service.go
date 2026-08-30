// Package system implements the internal FusionSystemService contract.
package system

import (
	"context"
	"runtime/debug"
	"strings"

	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
)

const APISchema = "fusion.v1"

type Probe interface {
	Ready(context.Context) (bool, string)
}

type ProbeFunc func(context.Context) (bool, string)

func (f ProbeFunc) Ready(ctx context.Context) (bool, string) { return f(ctx) }

func StaticProbe(ready bool, reason string) Probe {
	return ProbeFunc(func(context.Context) (bool, string) {
		if ready {
			return true, ""
		}
		return false, reason
	})
}

type ComponentReadiness struct {
	Ready  bool
	Reason string
}

type HealthResponse struct {
	Status model.HealthStatus
}

type ReadinessResponse struct {
	Ready            bool
	Policy           ComponentReadiness
	EvidenceStore    ComponentReadiness
	Correlator       ComponentReadiness
	ConflictEngine   ComponentReadiness
	ConfidenceEngine ComponentReadiness
}

type Version struct {
	EngineVersion string
	APISchema     string
	PolicySchema  string
	BuildCommit   string
}

type Capabilities struct {
	PassiveEvidence          bool
	VICIEvidence             bool
	XFRMEvidence             bool
	MLEvidence               bool
	SHAPEvidence             bool
	SecurityFindingRefs      bool
	ConflictDetection        bool
	ConfidenceCalculation    bool
	Provenance               bool
	IncrementalRecomputation bool
}

type Options struct {
	Policy, EvidenceStore, Correlator, ConflictEngine, ConfidenceEngine Probe
	Version                                                             Version
	Capabilities                                                        Capabilities
}

type Service struct {
	policy, evidenceStore, correlator, conflictEngine, confidenceEngine Probe
	version                                                             Version
	capabilities                                                        Capabilities
}

func New(options Options) *Service {
	return &Service{
		policy: options.Policy, evidenceStore: options.EvidenceStore, correlator: options.Correlator,
		conflictEngine: options.ConflictEngine, confidenceEngine: options.ConfidenceEngine,
		version: defaultVersion(options.Version), capabilities: options.Capabilities,
	}
}

func (s *Service) Health(ctx context.Context) (HealthResponse, error) {
	if err := model.ContextError(ctx); err != nil {
		return HealthResponse{}, err
	}
	if s == nil {
		return HealthResponse{Status: model.HealthUnhealthy}, model.NewError(model.ErrorInternal, "Fusion system service is not configured")
	}
	return HealthResponse{Status: model.HealthHealthy}, nil
}

func (s *Service) Readiness(ctx context.Context) (ReadinessResponse, error) {
	if err := model.ContextError(ctx); err != nil {
		return ReadinessResponse{}, err
	}
	if s == nil {
		return ReadinessResponse{}, model.NewError(model.ErrorInternal, "Fusion system service is not configured")
	}
	result := ReadinessResponse{
		Policy:           probe(ctx, s.policy, "Fusion policy provider is not configured"),
		EvidenceStore:    probe(ctx, s.evidenceStore, "in-memory evidence store is not configured"),
		Correlator:       probe(ctx, s.correlator, "correlator is not configured"),
		ConflictEngine:   probe(ctx, s.conflictEngine, "conflict engine is not configured"),
		ConfidenceEngine: probe(ctx, s.confidenceEngine, "confidence engine is not configured"),
	}
	result.Ready = result.Policy.Ready && result.EvidenceStore.Ready && result.Correlator.Ready && result.ConflictEngine.Ready && result.ConfidenceEngine.Ready
	return result, nil
}

func (s *Service) GetVersion(ctx context.Context) (Version, error) {
	if err := model.ContextError(ctx); err != nil {
		return Version{}, err
	}
	if s == nil {
		return Version{}, model.NewError(model.ErrorInternal, "Fusion system service is not configured")
	}
	return s.version, nil
}

func (s *Service) GetCapabilities(ctx context.Context) (Capabilities, error) {
	if err := model.ContextError(ctx); err != nil {
		return Capabilities{}, err
	}
	if s == nil {
		return Capabilities{}, model.NewError(model.ErrorInternal, "Fusion system service is not configured")
	}
	return s.capabilities, nil
}

func probe(ctx context.Context, component Probe, missing string) ComponentReadiness {
	if component == nil {
		return ComponentReadiness{Reason: missing}
	}
	ready, reason := component.Ready(ctx)
	if !ready && strings.TrimSpace(reason) == "" {
		reason = "component is not ready"
	}
	return ComponentReadiness{Ready: ready, Reason: reason}
}

func defaultVersion(version Version) Version {
	if version.APISchema == "" {
		version.APISchema = APISchema
	}
	if version.PolicySchema == "" {
		version.PolicySchema = "fusion-policy.v1"
	}
	if version.EngineVersion == "" {
		version.EngineVersion = "dev"
	}
	if version.BuildCommit == "" {
		version.BuildCommit = "unknown"
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if version.EngineVersion == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version.EngineVersion = info.Main.Version
		}
		if version.BuildCommit == "unknown" {
			for _, setting := range info.Settings {
				if setting.Key == "vcs.revision" && setting.Value != "" {
					version.BuildCommit = setting.Value
					break
				}
			}
		}
	}
	return version
}
