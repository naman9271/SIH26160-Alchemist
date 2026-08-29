// Package capture manages real passive captures against the shared session state.
package capture

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	capturev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/capture"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/session"
)

const (
	StateStarting  = "STARTING"
	StateCapturing = "CAPTURING"
	StateStopping  = "STOPPING"
	StateStopped   = "STOPPED"
	StateFailed    = "FAILED"
)

const ipsecFilter = "udp port 500 or udp port 4500 or ip proto 50 or ip6 proto 50 or ip proto 51 or ip6 proto 51"

type Config struct {
	SessionID       string
	InterfaceName   string
	Filter          string
	PromiscuousMode bool
	SavePCAP        bool
	MaxDuration     time.Duration
	MaxCaptureBytes uint64
	PacketObserver  PacketObserver
}

// PacketMetadata is a payload-free packet view emitted by capture engines.
type PacketMetadata struct {
	SessionID                         string
	Protocol                          uint8
	SourceAddress, DestinationAddress string
	SourcePort, DestinationPort       uint16
	SPI                               uint32
	IKEInitiatorSPI, IKEResponderSPI  uint64
	IKEVersion                        string
	IKEExchangeType, IKEFlags         uint8
	IKEMessageID                      uint32
	IKE, NATT, EncapsulatedESP        bool
	NATKeepalive                      bool
	Length                            uint64
	SeenAt                            time.Time
}

type PacketObserver func(context.Context, PacketMetadata) error

type Counters struct {
	PacketsTotal uint64
	BytesTotal   uint64
	IKEPackets   uint64
	ESPPackets   uint64
	AHPackets    uint64
	NATTPackets  uint64
	PacketDrops  uint64
}

type Handle interface {
	Stop(context.Context) error
	Done() <-chan error
	Counters() Counters
	TemporaryFiles() []string
}

type Engine interface {
	Available() bool
	ValidateFilter(context.Context, string) error
	Start(context.Context, Config) (Handle, error)
}

type FlowMetrics interface {
	CaptureMetrics(context.Context, string) (activeFlows, activeVPNSessions uint64, err error)
}

type captureRecord struct {
	id, sessionID, interfaceName, filter, state string
	startedAt, endedAt                          time.Time
	handle                                      Handle
}

func (r *captureRecord) CaptureID() string     { return r.id }
func (r *captureRecord) SessionID() string     { return r.sessionID }
func (r *captureRecord) InterfaceName() string { return r.interfaceName }
func (r *captureRecord) Filter() string        { return r.filter }
func (r *captureRecord) State() string         { return r.state }
func (r *captureRecord) StartedAt() time.Time  { return r.startedAt }
func (r *captureRecord) EndedAt() time.Time    { return r.endedAt }

type Service struct {
	mu       sync.RWMutex
	sessions *session.Service
	engine   Engine
	metrics  FlowMetrics
	observer PacketObserver
	captures map[string]*captureRecord
	activeID string
}

func (s *Service) SetPacketObserver(observer PacketObserver) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observer = observer
}

func New(sessions *session.Service, engine Engine, metrics FlowMetrics) *Service {
	if engine == nil {
		engine = NewTCPDumpEngine()
	}
	return &Service{sessions: sessions, engine: engine, metrics: metrics, captures: make(map[string]*captureRecord)}
}

func (s *Service) Available() bool { return s.engine.Available() }

func (s *Service) Probe(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	return s.engine.ValidateFilter(ctx, ipsecFilter)
}

func (s *Service) Active() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeID != ""
}

func (s *Service) Start(ctx context.Context, sessionID, interfaceName string, mode capturev1.CaptureFilterMode, custom string, promiscuous, savePCAP bool, maxDurationSeconds, maxBytes uint64) (*captureRecord, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if s.sessions == nil {
		return nil, shared.NewError(shared.Internal, "", "session service is not configured")
	}
	if strings.TrimSpace(interfaceName) == "" {
		return nil, shared.NewError(shared.InvalidArgument, "", "interface_name is required")
	}
	if _, err := net.InterfaceByName(interfaceName); err != nil {
		return nil, shared.NewError(shared.NotFound, shared.InterfaceNotFound, "network interface was not found")
	}
	filter, err := resolveFilter(mode, custom)
	if err != nil {
		return nil, err
	}
	if err := s.engine.ValidateFilter(ctx, filter); err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.activeID != "" {
		s.mu.Unlock()
		return nil, shared.NewError(shared.FailedPrecondition, shared.CaptureAlreadyRunning, "a capture is already running")
	}
	id, err := shared.NewCaptureID()
	if err != nil {
		s.mu.Unlock()
		return nil, shared.NewError(shared.Internal, "", "could not create capture")
	}
	if err := s.sessions.BeginCapture(ctx, sessionID, string(id)); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	config := Config{SessionID: sessionID, InterfaceName: interfaceName, Filter: filter, PromiscuousMode: promiscuous, SavePCAP: savePCAP, MaxCaptureBytes: maxBytes, PacketObserver: s.observer}
	if maxDurationSeconds > 0 {
		config.MaxDuration = time.Duration(maxDurationSeconds) * time.Second
	}
	handle, err := s.engine.Start(context.Background(), config)
	if err != nil {
		s.sessions.CaptureStartFailed(sessionID, string(id))
		s.mu.Unlock()
		return nil, err
	}
	now := time.Now().UTC()
	record := &captureRecord{id: string(id), sessionID: sessionID, interfaceName: interfaceName, filter: filter, state: StateCapturing, startedAt: now, handle: handle}
	s.captures[record.id], s.activeID = record, record.id
	s.mu.Unlock()
	go s.await(record)
	if config.MaxDuration > 0 {
		go s.stopAfter(record.id, config.MaxDuration)
	}
	return record, nil
}

func (s *Service) stopAfter(id string, duration time.Duration) {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	<-timer.C
	_, _ = s.Stop(context.Background(), id)
}
func (s *Service) await(record *captureRecord) {
	err := <-record.handle.Done()
	s.mu.Lock()
	if record.state == StateCapturing || record.state == StateStopping {
		record.state = StateStopped
		if err != nil {
			record.state = StateFailed
		}
		record.endedAt = time.Now().UTC()
		if s.activeID == record.id {
			s.activeID = ""
		}
	}
	s.mu.Unlock()
	s.sessions.CaptureStopped(record.sessionID, record.id)
}

func (s *Service) Stop(ctx context.Context, id string) (*captureRecord, error) {
	if strings.TrimSpace(id) == "" {
		return nil, shared.NewError(shared.InvalidArgument, "", "capture_id is required")
	}
	s.mu.RLock()
	record, ok := s.captures[id]
	s.mu.RUnlock()
	if !ok {
		return nil, shared.NewError(shared.NotFound, "", "capture was not found")
	}
	s.mu.Lock()
	state := record.state
	if state == StateCapturing {
		record.state = StateStopping
	}
	s.mu.Unlock()
	if state == StateCapturing || state == StateStarting {
		if err := record.handle.Stop(ctx); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	if record.state != StateFailed {
		record.state = StateStopped
	}
	if record.endedAt.IsZero() {
		record.endedAt = time.Now().UTC()
	}
	if s.activeID == id {
		s.activeID = ""
	}
	s.mu.Unlock()
	s.sessions.CaptureStopped(record.sessionID, record.id)
	return record, nil
}

func (s *Service) Status(ctx context.Context, id string) (*captureRecord, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.captures[id]
	if !ok {
		return nil, shared.NewError(shared.NotFound, "", "capture was not found")
	}
	copy := *record
	return &copy, nil
}
func (s *Service) Stats(ctx context.Context, id string) (Counters, uint64, uint64, time.Duration, error) {
	record, err := s.Status(ctx, id)
	if err != nil {
		return Counters{}, 0, 0, 0, err
	}
	counters := record.handle.Counters()
	elapsed := time.Since(record.startedAt)
	if !record.endedAt.IsZero() {
		elapsed = record.endedAt.Sub(record.startedAt)
	}
	var flows, vpns uint64
	if s.metrics != nil {
		flows, vpns, err = s.metrics.CaptureMetrics(ctx, id)
		if err != nil {
			return Counters{}, 0, 0, 0, err
		}
	}
	return counters, flows, vpns, elapsed, nil
}

func (s *Service) UpdateFilter(ctx context.Context, id string, mode capturev1.CaptureFilterMode, custom string) (string, error) {
	filter, err := resolveFilter(mode, custom)
	if err != nil {
		return "", err
	}
	if err = s.engine.ValidateFilter(ctx, filter); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.captures[id]
	if !ok {
		return "", shared.NewError(shared.NotFound, "", "capture was not found")
	}
	if record.state == StateCapturing || record.state == StateStarting {
		return "", shared.NewError(shared.FailedPrecondition, "", "capture backend cannot update a running filter")
	}
	record.filter = filter
	return filter, nil
}
func (s *Service) StopForSession(ctx context.Context, sessionID string) error {
	s.mu.RLock()
	var id string
	for captureID, record := range s.captures {
		if record.sessionID == sessionID && (record.state == StateCapturing || record.state == StateStarting || record.state == StateStopping) {
			id = captureID
			break
		}
	}
	s.mu.RUnlock()
	if id == "" {
		return nil
	}
	_, err := s.Stop(ctx, id)
	return err
}
func (s *Service) ResetForSession(ctx context.Context, sessionID string, deleteFiles bool) error {
	if err := s.StopForSession(ctx, sessionID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, record := range s.captures {
		if record.sessionID != sessionID {
			continue
		}
		if deleteFiles {
			for _, path := range record.handle.TemporaryFiles() {
				_ = removeTemporaryFile(path)
			}
		}
		delete(s.captures, id)
	}
	return nil
}

func resolveFilter(mode capturev1.CaptureFilterMode, custom string) (string, error) {
	switch mode {
	case capturev1.CaptureFilterMode_IPSEC_ONLY:
		if custom != "" {
			return "", shared.NewError(shared.InvalidArgument, "", "custom_bpf is only valid with CUSTOM_BPF")
		}
		return ipsecFilter, nil
	case capturev1.CaptureFilterMode_ALL_TRAFFIC:
		if custom != "" {
			return "", shared.NewError(shared.InvalidArgument, "", "custom_bpf is only valid with CUSTOM_BPF")
		}
		return "", nil
	case capturev1.CaptureFilterMode_CUSTOM_BPF:
		if strings.TrimSpace(custom) == "" {
			return "", shared.NewError(shared.InvalidArgument, "", "custom_bpf is required for CUSTOM_BPF")
		}
		return custom, nil
	default:
		return "", shared.NewError(shared.InvalidArgument, "", "a capture filter mode is required")
	}
}
func contextError(ctx context.Context) error {
	if ctx == nil {
		return shared.NewError(shared.InvalidArgument, "", "context is required")
	}
	return ctx.Err()
}
