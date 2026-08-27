// Package workspace owns the single authoritative ephemeral Core workspace.
package workspace

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	workspacev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/workspace"
	sensorv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"google.golang.org/grpc/metadata"
)

const IdempotencyMetadataKey = "x-idempotency-key"

// Coordinator clears one subsystem's state as part of a workspace replacement.
// Implementations are supplied by the Sensor, input, analysis, protocol, ML,
// fusion, security, risk, report, event, artifact and temp-storage modules.
type Coordinator interface {
	Name() string
	Cleanup(context.Context, string, bool, bool) error
}

type Record struct {
	ID              string
	DisplayName     string
	State           workspacev1.WorkspaceState
	Mode            sensorv1.SensorMode
	SensorSessionID string
	SourceID        string
	CaptureID       string
	AnalysisID      string
	AssessmentID    string
	MLJobID         string
	FusionRunID     string
	ReportID        string
	ReportStatus    string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Generation      uint64
}

type StateView struct {
	State          workspacev1.WorkspaceState
	Mode           sensorv1.SensorMode
	HasSource      bool
	HasAnalysis    bool
	HasMLResult    bool
	HasFusedResult bool
	HasReport      bool
}

type Options struct {
	Coordinators   []Coordinator
	CleanupTimeout time.Duration
}

type replay struct{ record Record }

type Service struct {
	operationMu  sync.Mutex
	mu           sync.RWMutex
	current      *Record
	generation   uint64
	coordinators []Coordinator
	timeout      time.Duration
	replays      map[string]replay
}

func New(options Options) *Service {
	timeout := options.CleanupTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Service{coordinators: append([]Coordinator(nil), options.Coordinators...), timeout: timeout, replays: make(map[string]replay)}
}

func IdempotencyKey(ctx context.Context) string {
	if values := metadata.ValueFromIncomingContext(ctx, IdempotencyMetadataKey); len(values) > 0 {
		return strings.TrimSpace(values[0])
	}
	return ""
}

func (s *Service) Create(ctx context.Context, displayName, idempotencyKey string) (Record, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, err
	}
	if strings.TrimSpace(displayName) == "" {
		return Record{}, shared.NewError(shared.InvalidArgument, "", "display_name is required")
	}
	if len(strings.TrimSpace(displayName)) > 200 {
		return Record{}, shared.NewError(shared.InvalidArgument, "", "display_name exceeds 200 characters")
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if existing, ok := s.replay("create", idempotencyKey); ok {
		return existing, nil
	}
	if err := s.cleanupCurrent(ctx, true, true); err != nil {
		return Record{}, err
	}
	record, err := s.newEmpty(strings.TrimSpace(displayName))
	if err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	s.current = &record
	s.mu.Unlock()
	s.storeReplay("create", idempotencyKey, record)
	return record, nil
}

func (s *Service) Get(ctx context.Context, id string) (Record, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil || (id != "" && id != s.current.ID) {
		return Record{}, shared.NewError(shared.NotFound, "", "workspace was not found")
	}
	return *s.current, nil
}

func (s *Service) GetState(ctx context.Context, id string) (StateView, error) {
	record, err := s.Get(ctx, id)
	if err != nil {
		return StateView{}, err
	}
	return stateView(record), nil
}

func (s *Service) Reset(ctx context.Context, force, deleteTemporaryFiles bool, idempotencyKey string) (Record, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, err
	}
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if existing, ok := s.replay("reset", idempotencyKey); ok {
		return existing, nil
	}
	if err := s.cleanupCurrent(ctx, force, deleteTemporaryFiles); err != nil {
		return Record{}, err
	}
	record, err := s.newEmpty("")
	if err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	s.current = &record
	s.mu.Unlock()
	s.storeReplay("reset", idempotencyKey, record)
	return record, nil
}

// UpdateIfCurrent is the sole mutation seam for future asynchronous Core
// subsystems. Generation and workspace ID prevent stale callbacks from an old
// analysis or ML job from mutating a replacement workspace.
func (s *Service) UpdateIfCurrent(workspaceID string, generation uint64, mutate func(*Record)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil || s.current.ID != workspaceID || s.current.Generation != generation {
		return false
	}
	mutate(s.current)
	s.current.UpdatedAt = time.Now().UTC()
	return true
}

func (s *Service) CurrentOwnership(ctx context.Context) (string, uint64, error) {
	record, err := s.Get(ctx, "")
	if err != nil {
		return "", 0, err
	}
	return record.ID, record.Generation, nil
}
func (s *Service) CurrentState() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return "EMPTY"
	}
	return publicState(s.current.State)
}

func (s *Service) cleanupCurrent(ctx context.Context, force, deleteTemporaryFiles bool) error {
	s.mu.RLock()
	current := s.current
	s.mu.RUnlock()
	if current == nil {
		return nil
	}
	s.mu.Lock()
	previous := *s.current
	s.current.State = workspacev1.WorkspaceState_WORKSPACE_STATE_RESETTING
	s.current.UpdatedAt = time.Now().UTC()
	s.mu.Unlock()
	cleanupCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	for _, coordinator := range s.coordinators {
		if err := coordinator.Cleanup(cleanupCtx, previous.ID, force, deleteTemporaryFiles); err != nil {
			s.mu.Lock()
			if s.current != nil && s.current.ID == previous.ID {
				s.current = &previous
			}
			s.mu.Unlock()
			if !force {
				return shared.NewError(shared.FailedPrecondition, "", fmt.Sprintf("workspace cleanup blocked by %s", coordinator.Name()))
			}
			return shared.NewError(shared.Internal, "", fmt.Sprintf("forced workspace cleanup failed in %s", coordinator.Name()))
		}
	}
	return nil
}

func (s *Service) newEmpty(displayName string) (Record, error) {
	id, err := shared.NewWorkspaceID()
	if err != nil {
		return Record{}, shared.NewError(shared.Internal, "", "could not create workspace")
	}
	now := time.Now().UTC()
	s.mu.Lock()
	s.generation++
	generation := s.generation
	s.mu.Unlock()
	return Record{ID: string(id), DisplayName: displayName, State: workspacev1.WorkspaceState_WORKSPACE_STATE_EMPTY, CreatedAt: now, UpdatedAt: now, Generation: generation}, nil
}
func (s *Service) replay(operation, key string) (Record, bool) {
	if key == "" {
		return Record{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.replays[operation+":"+key]
	return item.record, ok
}
func (s *Service) storeReplay(operation, key string, record Record) {
	if key == "" {
		return
	}
	s.mu.Lock()
	s.replays[operation+":"+key] = replay{record: record}
	s.mu.Unlock()
}
func stateView(record Record) StateView {
	return StateView{State: record.State, Mode: record.Mode, HasSource: record.SourceID != "", HasAnalysis: record.AnalysisID != "", HasMLResult: record.MLJobID != "", HasFusedResult: record.FusionRunID != "", HasReport: record.ReportID != ""}
}
func publicState(state workspacev1.WorkspaceState) string {
	switch state {
	case workspacev1.WorkspaceState_WORKSPACE_STATE_EMPTY:
		return "EMPTY"
	case workspacev1.WorkspaceState_WORKSPACE_STATE_READY:
		return "READY"
	case workspacev1.WorkspaceState_WORKSPACE_STATE_ACQUIRING:
		return "ACQUIRING"
	case workspacev1.WorkspaceState_WORKSPACE_STATE_ANALYZING:
		return "ANALYZING"
	case workspacev1.WorkspaceState_WORKSPACE_STATE_COMPLETED:
		return "COMPLETED"
	case workspacev1.WorkspaceState_WORKSPACE_STATE_FAILED:
		return "FAILED"
	case workspacev1.WorkspaceState_WORKSPACE_STATE_RESETTING:
		return "RESETTING"
	default:
		return "UNSPECIFIED"
	}
}
func contextError(ctx context.Context) error {
	if ctx == nil {
		return shared.NewError(shared.InvalidArgument, "", "context is required")
	}
	return ctx.Err()
}
