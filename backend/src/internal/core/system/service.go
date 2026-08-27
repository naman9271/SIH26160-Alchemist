// Package system supplies Core process status from real runtime and injected dependencies.
package system

import (
	"context"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	coresystemv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/system"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

const (
	APIVersion     = "core.v1"
	SensorContract = "sensor.v1"
	MLContract     = "ml.v1"
	FusionContract = "fusion.v1"
)

type Dependencies struct{ InMemoryStore, TempStorage, Sensor, MLWorker, FusionEngine coresystemv1.DependencyState }
type Capabilities struct{ PassiveLive, PassivePCAP, DeepAssessment, SecurityAssessment, RiskScoring, ThreatMatrix, MLClassification, SHAP, MetadataExposure, ExecutiveReport, TechnicalReport bool }
type RuntimeInstrumentation struct {
	EventSubscribers, SensorQueueDepth uint64
	MLRoundTripMS, FusionRecomputeMS   float64
}
type DependencyProvider interface {
	Dependencies(context.Context) (Dependencies, error)
	Capabilities(context.Context) (Capabilities, error)
}
type MetricsProvider interface {
	RuntimeInstrumentation(context.Context) (RuntimeInstrumentation, error)
}
type WorkspaceStateProvider interface{ CurrentState() string }
type Version struct{ CoreVersion, BuildCommit string }
type Options struct {
	StartedAt    time.Time
	Version      Version
	Dependencies DependencyProvider
	Metrics      MetricsProvider
	Workspace    WorkspaceStateProvider
}
type Service interface {
	Health(context.Context) (time.Time, error)
	Readiness(context.Context) (Dependencies, error)
	Version(context.Context) (Version, error)
	Capabilities(context.Context) (Capabilities, error)
	RuntimeStats(context.Context) (RuntimeStats, error)
}
type RuntimeStats struct {
	UptimeSeconds                      uint64
	CPUPercent                         float64
	RSSBytes                           uint64
	Goroutines                         uint32
	EventSubscribers, SensorQueueDepth uint64
	CurrentWorkspaceState              string
	MLRoundTripMS, FusionRecomputeMS   float64
}
type service struct {
	startedAt    time.Time
	startCPU     time.Duration
	version      Version
	dependencies DependencyProvider
	metrics      MetricsProvider
	workspace    WorkspaceStateProvider
}
type unavailableDependencies struct{}

func (unavailableDependencies) Dependencies(context.Context) (Dependencies, error) {
	return Dependencies{InMemoryStore: coresystemv1.DependencyState_READY, TempStorage: coresystemv1.DependencyState_UNAVAILABLE, Sensor: coresystemv1.DependencyState_UNAVAILABLE, MLWorker: coresystemv1.DependencyState_UNAVAILABLE, FusionEngine: coresystemv1.DependencyState_UNAVAILABLE}, nil
}
func (unavailableDependencies) Capabilities(context.Context) (Capabilities, error) {
	return Capabilities{}, nil
}

type zeroMetrics struct{}

func (zeroMetrics) RuntimeInstrumentation(context.Context) (RuntimeInstrumentation, error) {
	return RuntimeInstrumentation{}, nil
}

func New(options Options) Service {
	now := time.Now().UTC()
	if options.StartedAt.IsZero() || options.StartedAt.After(now) {
		options.StartedAt = now
	}
	if options.Dependencies == nil {
		options.Dependencies = unavailableDependencies{}
	}
	if options.Metrics == nil {
		options.Metrics = zeroMetrics{}
	}
	options.Version = defaultVersion(options.Version)
	return &service{startedAt: options.StartedAt, startCPU: cpuTime(), version: options.Version, dependencies: options.Dependencies, metrics: options.Metrics, workspace: options.Workspace}
}
func (s *service) Health(ctx context.Context) (time.Time, error) {
	if err := contextError(ctx); err != nil {
		return time.Time{}, err
	}
	return time.Now().UTC(), nil
}
func (s *service) Readiness(ctx context.Context) (Dependencies, error) {
	if err := contextError(ctx); err != nil {
		return Dependencies{}, err
	}
	return s.dependencies.Dependencies(ctx)
}
func (s *service) Version(ctx context.Context) (Version, error) {
	if err := contextError(ctx); err != nil {
		return Version{}, err
	}
	return s.version, nil
}
func (s *service) Capabilities(ctx context.Context) (Capabilities, error) {
	if err := contextError(ctx); err != nil {
		return Capabilities{}, err
	}
	return s.dependencies.Capabilities(ctx)
}
func (s *service) RuntimeStats(ctx context.Context) (RuntimeStats, error) {
	if err := contextError(ctx); err != nil {
		return RuntimeStats{}, err
	}
	metrics, err := s.metrics.RuntimeInstrumentation(ctx)
	if err != nil {
		return RuntimeStats{}, err
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	now := time.Now().UTC()
	state := "EMPTY"
	if s.workspace != nil {
		state = s.workspace.CurrentState()
	}
	return RuntimeStats{UptimeSeconds: uint64(now.Sub(s.startedAt).Seconds()), CPUPercent: percent(s.startCPU, cpuTime(), now.Sub(s.startedAt)), RSSBytes: memory.Sys, Goroutines: uint32(runtime.NumGoroutine()), EventSubscribers: metrics.EventSubscribers, SensorQueueDepth: metrics.SensorQueueDepth, CurrentWorkspaceState: state, MLRoundTripMS: metrics.MLRoundTripMS, FusionRecomputeMS: metrics.FusionRecomputeMS}, nil
}
func contextError(ctx context.Context) error {
	if ctx == nil {
		return shared.NewError(shared.InvalidArgument, "", "context is required")
	}
	return ctx.Err()
}
func defaultVersion(version Version) Version {
	info, ok := debug.ReadBuildInfo()
	if version.CoreVersion == "" {
		version.CoreVersion = "dev"
		if ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			version.CoreVersion = info.Main.Version
		}
	}
	if version.BuildCommit == "" {
		version.BuildCommit = "unknown"
		if ok {
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
func cpuTime() time.Duration {
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) != nil {
		return 0
	}
	return time.Duration(usage.Utime.Sec)*time.Second + time.Duration(usage.Utime.Usec)*time.Microsecond + time.Duration(usage.Stime.Sec)*time.Second + time.Duration(usage.Stime.Usec)*time.Microsecond
}
func percent(start, current, elapsed time.Duration) float64 {
	if elapsed <= 0 || current < start {
		return 0
	}
	return float64(current-start) / float64(elapsed) * 100
}
