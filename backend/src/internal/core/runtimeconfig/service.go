// Package runtimeconfig owns the mutable, non-persistent Core configuration.
package runtimeconfig

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	runtimeconfigv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/runtimeconfig"
	workspacev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/workspace"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"google.golang.org/protobuf/proto"
)

type Service struct {
	mu                sync.RWMutex
	defaults, current *runtimeconfigv1.RuntimeConfig
	listeners         []func(*runtimeconfigv1.RuntimeConfig)
}

// Subscribe registers an in-process runtime consumer. Callbacks receive a
// detached configuration snapshot after every successful change.
func (s *Service) Subscribe(listener func(*runtimeconfigv1.RuntimeConfig)) func() {
	if s == nil || listener == nil {
		return func() {}
	}
	s.mu.Lock()
	s.listeners = append(s.listeners, listener)
	current := proto.Clone(s.current).(*runtimeconfigv1.RuntimeConfig)
	s.mu.Unlock()
	listener(current)
	// Runtime consumers live for the server lifetime; removal is intentionally a no-op.
	return func() {}
}

func Defaults(reportDirectory string) *runtimeconfigv1.RuntimeConfig {
	if strings.TrimSpace(reportDirectory) == "" {
		reportDirectory = filepath.Join(os.TempDir(), "ipsec-core-reports")
	}
	return &runtimeconfigv1.RuntimeConfig{LocalSensor: &runtimeconfigv1.LocalSensorOptions{PassiveCaptureEnabled: true, PacketBufferSize: 4096}, MlTimeoutMs: 2000, FusionRecomputationTimeoutMs: 5000, EventBufferSize: 256, ReportTempDirectory: reportDirectory, DefaultPolicyId: "fusion-default-v1", DefaultAnalysisMode: workspacev1.AnalysisMode_OFFLINE_PCAP}
}
func New(defaults *runtimeconfigv1.RuntimeConfig) *Service {
	if defaults == nil {
		defaults = Defaults("")
	}
	copy := proto.Clone(defaults).(*runtimeconfigv1.RuntimeConfig)
	return &Service{defaults: copy, current: proto.Clone(copy).(*runtimeconfigv1.RuntimeConfig)}
}
func (s *Service) Get(ctx context.Context) (*runtimeconfigv1.RuntimeConfig, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, shared.NewError(shared.Internal, "", "runtime configuration service is not configured")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return proto.Clone(s.current).(*runtimeconfigv1.RuntimeConfig), nil
}
func (s *Service) Update(ctx context.Context, config *runtimeconfigv1.RuntimeConfig, paths []string) (*runtimeconfigv1.RuntimeConfig, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, shared.NewError(shared.Internal, "", "runtime configuration service is not configured")
	}
	if config == nil || len(paths) == 0 {
		return nil, shared.NewError(shared.InvalidArgument, "", "config and update_mask are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := proto.Clone(s.current).(*runtimeconfigv1.RuntimeConfig)
	for _, path := range paths {
		switch path {
		case "ml_endpoint":
			next.MlEndpoint = strings.TrimSpace(config.GetMlEndpoint())
		case "fusion_policy_id":
			next.FusionPolicyId = strings.TrimSpace(config.GetFusionPolicyId())
		case "ml_timeout_ms":
			next.MlTimeoutMs = config.GetMlTimeoutMs()
		case "fusion_recomputation_timeout_ms":
			next.FusionRecomputationTimeoutMs = config.GetFusionRecomputationTimeoutMs()
		case "event_buffer_size":
			next.EventBufferSize = config.GetEventBufferSize()
		case "report_temp_directory":
			next.ReportTempDirectory = strings.TrimSpace(config.GetReportTempDirectory())
		case "default_policy_id":
			next.DefaultPolicyId = strings.TrimSpace(config.GetDefaultPolicyId())
		case "default_analysis_mode":
			next.DefaultAnalysisMode = config.GetDefaultAnalysisMode()
		case "local_sensor":
			if config.GetLocalSensor() == nil {
				next.LocalSensor = nil
			} else {
				next.LocalSensor = proto.Clone(config.GetLocalSensor()).(*runtimeconfigv1.LocalSensorOptions)
			}
		default:
			return nil, shared.NewError(shared.InvalidArgument, "", "unsupported runtime configuration field: "+path)
		}
	}
	if err := validate(next); err != nil {
		return nil, err
	}
	next.Revision = s.current.Revision + 1
	s.current = next
	out := proto.Clone(next).(*runtimeconfigv1.RuntimeConfig)
	listeners := append([]func(*runtimeconfigv1.RuntimeConfig){}, s.listeners...)
	go notify(listeners, out)
	return out, nil
}
func (s *Service) RestoreDefaults(ctx context.Context) (*runtimeconfigv1.RuntimeConfig, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, shared.NewError(shared.Internal, "", "runtime configuration service is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := proto.Clone(s.defaults).(*runtimeconfigv1.RuntimeConfig)
	next.Revision = s.current.Revision + 1
	s.current = next
	out := proto.Clone(next).(*runtimeconfigv1.RuntimeConfig)
	listeners := append([]func(*runtimeconfigv1.RuntimeConfig){}, s.listeners...)
	go notify(listeners, out)
	return out, nil
}
func notify(listeners []func(*runtimeconfigv1.RuntimeConfig), config *runtimeconfigv1.RuntimeConfig) {
	for _, listener := range listeners {
		listener(proto.Clone(config).(*runtimeconfigv1.RuntimeConfig))
	}
}
func (s *Service) ReportDirectory() string {
	value, err := s.Get(context.Background())
	if err != nil {
		return ""
	}
	return value.GetReportTempDirectory()
}
func validate(v *runtimeconfigv1.RuntimeConfig) error {
	if v.GetMlTimeoutMs() == 0 || v.GetMlTimeoutMs() > 120000 {
		return shared.NewError(shared.InvalidArgument, "", "ml_timeout_ms must be between 1 and 120000")
	}
	if v.GetFusionRecomputationTimeoutMs() == 0 || v.GetFusionRecomputationTimeoutMs() > 120000 {
		return shared.NewError(shared.InvalidArgument, "", "fusion_recomputation_timeout_ms must be between 1 and 120000")
	}
	if v.GetEventBufferSize() == 0 || v.GetEventBufferSize() > 10000 {
		return shared.NewError(shared.InvalidArgument, "", "event_buffer_size must be between 1 and 10000")
	}
	if v.GetReportTempDirectory() == "" || !filepath.IsAbs(v.GetReportTempDirectory()) {
		return shared.NewError(shared.InvalidArgument, "", "report_temp_directory must be an absolute path")
	}
	if v.GetDefaultPolicyId() == "" {
		return shared.NewError(shared.InvalidArgument, "", "default_policy_id is required")
	}
	if v.GetDefaultAnalysisMode() == workspacev1.AnalysisMode_ANALYSIS_MODE_UNSPECIFIED {
		return shared.NewError(shared.InvalidArgument, "", "default_analysis_mode is required")
	}
	if v.GetLocalSensor() == nil || v.GetLocalSensor().GetPacketBufferSize() == 0 {
		return shared.NewError(shared.InvalidArgument, "", "local_sensor.packet_buffer_size is required")
	}
	return nil
}
func contextError(ctx context.Context) error {
	if ctx == nil {
		return shared.NewError(shared.InvalidArgument, "", "context is required")
	}
	return ctx.Err()
}
