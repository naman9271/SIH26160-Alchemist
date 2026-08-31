// Package session owns the shared Sensor-session lifecycle state.
package session

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	sensorv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

const (
	StateReady   = "READY"
	StateRunning = "RUNNING"
	StateStopped = "STOPPED"
	StateEmpty   = "EMPTY"
)

type DeepOptions struct {
	EnableVICI bool
	EnableXFRM bool
}

type Session struct {
	ID             string
	Name           string
	Mode           sensorv1.SensorMode
	State          string
	CaptureID      string
	CreatedAt      time.Time
	StartedAt      time.Time
	LastActivityAt time.Time
	EndedAt        time.Time
	DeepOptions    DeepOptions
}

// LifecycleHooks connect later capture, flow, feature, protocol, VICI, XFRM,
// and temporary-storage implementations without duplicating session state.
type LifecycleHooks interface {
	StopForSession(context.Context, string) error
	ResetForSession(context.Context, string, bool) error
}

type Service struct {
	mu       sync.RWMutex
	sessions map[string]Session
	hooks    LifecycleHooks
}

func New() *Service { return &Service{sessions: make(map[string]Session)} }

func (s *Service) ActiveCount() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var count uint64
	for _, item := range s.sessions {
		if item.State == StateReady || item.State == StateRunning {
			count++
		}
	}
	return count
}

func (s *Service) SetLifecycleHooks(hooks LifecycleHooks) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hooks = hooks
}

func (s *Service) Create(ctx context.Context, mode sensorv1.SensorMode, name string, options *DeepOptions) (Session, error) {
	if err := contextError(ctx); err != nil {
		return Session{}, err
	}
	if strings.TrimSpace(name) == "" {
		return Session{}, shared.NewError(shared.InvalidArgument, "", "session name is required")
	}
	if mode != sensorv1.SensorMode_PASSIVE_LIVE && mode != sensorv1.SensorMode_PASSIVE_PCAP && mode != sensorv1.SensorMode_DEEP_ASSESSMENT {
		return Session{}, shared.NewError(shared.InvalidArgument, "", "a supported sensor mode is required")
	}
	if mode == sensorv1.SensorMode_DEEP_ASSESSMENT {
		if options == nil || (!options.EnableVICI && !options.EnableXFRM) {
			return Session{}, shared.NewError(shared.InvalidArgument, "", "deep assessment requires VICI and/or XFRM telemetry")
		}
	} else if options != nil {
		return Session{}, shared.NewError(shared.InvalidArgument, "", "deep options are valid only for DEEP_ASSESSMENT")
	}
	id, err := shared.NewSensorSessionID()
	if err != nil {
		return Session{}, shared.NewError(shared.Internal, "", "could not create sensor session")
	}
	now := time.Now().UTC()
	item := Session{ID: string(id), Name: strings.TrimSpace(name), Mode: mode, State: StateReady, CreatedAt: now, LastActivityAt: now}
	if options != nil {
		item.DeepOptions = *options
	}
	s.mu.Lock()
	s.sessions[item.ID] = item
	s.mu.Unlock()
	return item, nil
}

func (s *Service) Get(ctx context.Context, id string) (Session, error) {
	if err := contextError(ctx); err != nil {
		return Session{}, err
	}
	if strings.TrimSpace(id) == "" {
		return Session{}, shared.NewError(shared.InvalidArgument, "", "sensor_session_id is required")
	}
	s.mu.RLock()
	item, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return Session{}, shared.NewError(shared.NotFound, "", "sensor session was not found")
	}
	return item, nil
}

// List exposes immutable session snapshots to in-process Core adapters. It
// does not create a second session registry or change Sensor lifecycle rules.
func (s *Service) List(ctx context.Context) ([]Session, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	s.mu.RLock()
	items := make([]Session, 0, len(s.sessions))
	for _, item := range s.sessions {
		items = append(items, item)
	}
	s.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

// BeginCapture atomically validates and transitions a live capture session.
// Deep assessment is passive live capture enriched by read-only VICI/XFRM
// telemetry; it does not mutate the gateway.
func (s *Service) BeginCapture(ctx context.Context, sessionID, captureID string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.sessions[sessionID]
	if !ok {
		return shared.NewError(shared.NotFound, "", "sensor session was not found")
	}
	if item.Mode != sensorv1.SensorMode_PASSIVE_LIVE && item.Mode != sensorv1.SensorMode_DEEP_ASSESSMENT {
		return shared.NewError(shared.FailedPrecondition, shared.SessionNotActive, "live capture requires a PASSIVE_LIVE or DEEP_ASSESSMENT session")
	}
	if item.State != StateReady {
		return shared.NewError(shared.FailedPrecondition, shared.SessionNotActive, "sensor session is not ready for live capture")
	}
	now := time.Now().UTC()
	item.State, item.CaptureID, item.StartedAt, item.LastActivityAt = StateRunning, captureID, now, now
	s.sessions[sessionID] = item
	return nil
}

func (s *Service) CaptureStopped(sessionID, captureID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.sessions[sessionID]
	if !ok || item.CaptureID != captureID {
		return
	}
	item.LastActivityAt = time.Now().UTC()
	s.sessions[sessionID] = item
}

// CaptureStartFailed rolls a reserved session back to READY when the capture
// backend fails before acquisition begins.
func (s *Service) CaptureStartFailed(sessionID, captureID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.sessions[sessionID]
	if !ok || item.CaptureID != captureID || item.State != StateRunning {
		return
	}
	now := time.Now().UTC()
	item.State, item.CaptureID, item.StartedAt, item.LastActivityAt = StateReady, "", time.Time{}, now
	s.sessions[sessionID] = item
}

func (s *Service) Stop(ctx context.Context, id string) (Session, error) {
	if _, err := s.Get(ctx, id); err != nil {
		return Session{}, err
	}
	s.mu.RLock()
	hooks := s.hooks
	item := s.sessions[id]
	s.mu.RUnlock()
	if item.State != StateRunning {
		return Session{}, shared.NewError(shared.FailedPrecondition, shared.SessionNotActive, "only a running session can be stopped")
	}
	if hooks != nil {
		if err := hooks.StopForSession(ctx, id); err != nil {
			return Session{}, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item = s.sessions[id]
	now := time.Now().UTC()
	item.State, item.EndedAt, item.LastActivityAt = StateStopped, now, now
	s.sessions[id] = item
	return item, nil
}

func (s *Service) Reset(ctx context.Context, id string, deleteTemporaryFiles bool) (Session, error) {
	if _, err := s.Get(ctx, id); err != nil {
		return Session{}, err
	}
	s.mu.RLock()
	hooks := s.hooks
	item := s.sessions[id]
	s.mu.RUnlock()
	if item.State != StateStopped {
		return Session{}, shared.NewError(shared.FailedPrecondition, shared.SessionNotActive, "only a stopped session can be reset")
	}
	if hooks != nil {
		if err := hooks.ResetForSession(ctx, id, deleteTemporaryFiles); err != nil {
			return Session{}, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item = s.sessions[id]
	now := time.Now().UTC()
	item.State, item.CaptureID, item.StartedAt, item.EndedAt, item.LastActivityAt = StateEmpty, "", time.Time{}, time.Time{}, now
	s.sessions[id] = item
	return item, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return shared.NewError(shared.InvalidArgument, "", "context is required")
	}
	return ctx.Err()
}
