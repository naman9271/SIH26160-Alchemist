// Package system implements SensorSystemService business logic independently
// from protobuf and gRPC transport concerns.
package system

import (
	"context"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

const APIVersion = "sensor.v1"

type Service interface {
	Health(context.Context) (time.Time, error)
	Readiness(context.Context) (Readiness, error)
	Version(context.Context) (Version, error)
	Capabilities(context.Context) (Capabilities, error)
	RuntimeStats(context.Context) (RuntimeStats, error)
}

type service struct {
	startedAt    time.Time
	startCPU     time.Duration
	version      Version
	dependencies DependencyProvider
	metrics      MetricsProvider
}

func New(options Options) Service {
	startedAt := options.StartedAt.UTC()
	now := time.Now().UTC()
	if startedAt.IsZero() || startedAt.After(now) {
		startedAt = now
	}
	if options.Dependencies == nil {
		options.Dependencies = unavailableDependencies{}
	}
	if options.Metrics == nil {
		options.Metrics = zeroMetrics{}
	}
	options.Version = defaultVersion(options.Version)

	return &service{
		startedAt:    startedAt,
		startCPU:     processCPUTime(),
		version:      options.Version,
		dependencies: options.Dependencies,
		metrics:      options.Metrics,
	}
}

func (s *service) Health(ctx context.Context) (time.Time, error) {
	if err := contextError(ctx); err != nil {
		return time.Time{}, err
	}
	return time.Now().UTC(), nil
}

func (s *service) Readiness(ctx context.Context) (Readiness, error) {
	if err := contextError(ctx); err != nil {
		return Readiness{}, err
	}
	return s.dependencies.Readiness(ctx)
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
	pipeline, err := s.metrics.PipelineStats(ctx)
	if err != nil {
		return RuntimeStats{}, err
	}

	now := time.Now().UTC()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)

	cpuPercent := cpuPercent(s.startCPU, processCPUTime(), now.Sub(s.startedAt))

	return RuntimeStats{
		UptimeSeconds:      uint64(now.Sub(s.startedAt).Seconds()),
		CPUPercent:         cpuPercent,
		RSSBytes:           residentBytes(memory.Sys),
		Goroutines:         uint32(runtime.NumGoroutine()),
		ActiveFlows:        pipeline.ActiveFlows,
		PacketQueueDepth:   pipeline.PacketQueueDepth,
		FeatureQueueDepth:  pipeline.FeatureQueueDepth,
		TemporaryDiskBytes: pipeline.TemporaryDiskBytes,
	}, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return sensor.NewError(sensor.InvalidArgument, "", "context is required")
	}
	return ctx.Err()
}

func defaultVersion(version Version) Version {
	buildInfo, ok := debug.ReadBuildInfo()
	if version.SensorVersion == "" {
		version.SensorVersion = "dev"
		if ok && buildInfo.Main.Version != "" && buildInfo.Main.Version != "(devel)" {
			version.SensorVersion = buildInfo.Main.Version
		}
	}
	if version.BuildCommit == "" {
		version.BuildCommit = "unknown"
		if ok {
			for _, setting := range buildInfo.Settings {
				if setting.Key == "vcs.revision" && setting.Value != "" {
					version.BuildCommit = setting.Value
					break
				}
			}
		}
	}
	return version
}

func processCPUTime() time.Duration {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	return timevalDuration(usage.Utime) + timevalDuration(usage.Stime)
}

func timevalDuration(value syscall.Timeval) time.Duration {
	return time.Duration(value.Sec)*time.Second + time.Duration(value.Usec)*time.Microsecond
}

func cpuPercent(start, current, elapsed time.Duration) float64 {
	if elapsed <= 0 || current < start {
		return 0
	}
	return float64(current-start) / float64(elapsed) * 100
}
