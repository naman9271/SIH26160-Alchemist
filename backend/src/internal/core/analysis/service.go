// Package analysis owns Core analysis lifecycle IDs and delegates Fusion state
// to the existing internal Fusion runtime. It never parses packets itself.
package analysis

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	analysisv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/analysis"
	inputv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/input"
	workspacev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/workspace"
	coreinput "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/input"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/workspace"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	fusionsession "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/session"
	"google.golang.org/protobuf/proto"
)

type SourceProvider interface {
	Get(context.Context, string) (coreinput.Source, error)
}
type FusionRuns interface {
	Create(context.Context, fusionsession.CreateRequest) (model.Run, error)
	Cancel(context.Context, string) (fusionsession.CancelResponse, error)
}
type PipelineRunner interface {
	Run(context.Context, Record, func(analysisv1.AnalysisStage)) error
}
type Record struct {
	ID, SourceID, PolicyID, FusionRunID string
	Mode                                workspacev1.AnalysisMode
	Options                             *analysisv1.AnalysisOptions
	State                               analysisv1.AnalysisState
	Stage                               analysisv1.AnalysisStage
	Failure                             string
	CreatedAt, UpdatedAt                time.Time
}
type Service struct {
	mu        sync.RWMutex
	source    SourceProvider
	fusion    FusionRuns
	workspace *workspace.Service
	records   map[string]*Record
	pipeline  PipelineRunner
	cancels   map[string]context.CancelFunc
}

func New(source SourceProvider, fusion FusionRuns, workspace *workspace.Service) *Service {
	return &Service{source: source, fusion: fusion, workspace: workspace, records: map[string]*Record{}, cancels: map[string]context.CancelFunc{}}
}
func (s *Service) SetPipeline(pipeline PipelineRunner) {
	s.mu.Lock()
	s.pipeline = pipeline
	s.mu.Unlock()
}
func (s *Service) Start(ctx context.Context, sourceID string, mode workspacev1.AnalysisMode, policyID string, options *analysisv1.AnalysisOptions) (Record, error) {
	if s == nil || s.source == nil || s.fusion == nil {
		return Record{}, shared.NewError(shared.Internal, "", "analysis dependencies are not configured")
	}
	if strings.TrimSpace(sourceID) == "" {
		return Record{}, shared.NewError(shared.InvalidArgument, "", "source_id is required")
	}
	source, err := s.source.Get(ctx, sourceID)
	if err != nil {
		return Record{}, err
	}
	expected := modeFor(source.Mode)
	if mode != workspacev1.AnalysisMode_ANALYSIS_MODE_UNSPECIFIED && mode != expected {
		return Record{}, shared.NewError(shared.InvalidArgument, "", "mode does not match the selected source")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Record{}, err
	}
	if policyID == "" {
		policyID = model.DefaultPolicyID
	}
	run, err := s.fusion.Create(ctx, fusionsession.CreateRequest{AnalysisID: id.String(), PolicyID: policyID})
	if err != nil {
		return Record{}, err
	}
	now := time.Now().UTC()
	copyOptions := defaultOptions(options)
	record := &Record{ID: id.String(), SourceID: sourceID, PolicyID: policyID, FusionRunID: run.ID, Mode: expected, Options: copyOptions, State: analysisv1.AnalysisState_ANALYSIS_STATE_RUNNING, Stage: analysisv1.AnalysisStage_INITIALIZING, CreatedAt: now, UpdatedAt: now}
	s.mu.Lock()
	s.records[record.ID] = record
	s.mu.Unlock()
	s.bindWorkspace(ctx, record)
	s.mu.RLock()
	pipeline := s.pipeline
	s.mu.RUnlock()
	if pipeline == nil {
		s.fail(record.ID, shared.NewError(shared.FailedPrecondition, "", "analysis pipeline is not configured"))
		return s.Get(ctx, record.ID)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancels[record.ID] = cancel
	s.mu.Unlock()
	go s.execute(runCtx, pipeline, *record)
	return *record, nil
}
func (s *Service) Get(ctx context.Context, id string) (Record, error) {
	if strings.TrimSpace(id) == "" {
		return Record{}, shared.NewError(shared.InvalidArgument, "", "analysis_id is required")
	}
	s.mu.RLock()
	record := s.records[id]
	if record != nil {
		copy := *record
		copy.Options = cloneOptions(record.Options)
		record = &copy
	}
	s.mu.RUnlock()
	if record == nil {
		return Record{}, shared.NewError(shared.NotFound, "", "analysis was not found")
	}
	return *record, nil
}
func (s *Service) Cancel(ctx context.Context, id string) (Record, error) {
	record, err := s.Get(ctx, id)
	if err != nil {
		return Record{}, err
	}
	if record.State != analysisv1.AnalysisState_ANALYSIS_STATE_RUNNING {
		return Record{}, shared.NewError(shared.FailedPrecondition, "", "only a running analysis can be cancelled")
	}
	if _, err = s.fusion.Cancel(ctx, record.FusionRunID); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	if cancel := s.cancels[id]; cancel != nil {
		cancel()
		delete(s.cancels, id)
	}
	stored := s.records[id]
	stored.State = analysisv1.AnalysisState_ANALYSIS_STATE_CANCELLED
	stored.Stage = analysisv1.AnalysisStage_CANCELLED
	stored.UpdatedAt = time.Now().UTC()
	out := *stored
	s.mu.Unlock()
	return out, nil
}
func (s *Service) execute(ctx context.Context, pipeline PipelineRunner, record Record) {
	err := pipeline.Run(ctx, record, func(stage analysisv1.AnalysisStage) { s.advance(record.ID, stage) })
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		s.fail(record.ID, err)
		return
	}
	s.mu.Lock()
	if current := s.records[record.ID]; current != nil && current.State == analysisv1.AnalysisState_ANALYSIS_STATE_RUNNING {
		current.State, current.Stage, current.UpdatedAt = analysisv1.AnalysisState_ANALYSIS_STATE_COMPLETED, analysisv1.AnalysisStage_COMPLETED, time.Now().UTC()
	}
	delete(s.cancels, record.ID)
	s.mu.Unlock()
}
func (s *Service) advance(id string, stage analysisv1.AnalysisStage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current := s.records[id]; current != nil && current.State == analysisv1.AnalysisState_ANALYSIS_STATE_RUNNING {
		current.Stage, current.UpdatedAt = stage, time.Now().UTC()
	}
}
func (s *Service) fail(id string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current := s.records[id]; current != nil && current.State == analysisv1.AnalysisState_ANALYSIS_STATE_RUNNING {
		current.State, current.Stage, current.Failure, current.UpdatedAt = analysisv1.AnalysisState_ANALYSIS_STATE_FAILED, analysisv1.AnalysisStage_FAILED, err.Error(), time.Now().UTC()
	}
	if cancel := s.cancels[id]; cancel != nil {
		cancel()
		delete(s.cancels, id)
	}
}
func (s *Service) Progress(ctx context.Context, id string) (Record, error) { return s.Get(ctx, id) }
func (s *Service) Retry(ctx context.Context, id string) (Record, error) {
	record, err := s.Get(ctx, id)
	if err != nil {
		return Record{}, err
	}
	if record.State != analysisv1.AnalysisState_ANALYSIS_STATE_FAILED && record.State != analysisv1.AnalysisState_ANALYSIS_STATE_CANCELLED {
		return Record{}, shared.NewError(shared.FailedPrecondition, "", "only failed or cancelled analyses can be retried")
	}
	return s.Start(ctx, record.SourceID, record.Mode, record.PolicyID, record.Options)
}
func (s *Service) bindWorkspace(ctx context.Context, record *Record) {
	if s.workspace == nil {
		return
	}
	workspaceID, generation, err := s.workspace.CurrentOwnership(ctx)
	if err != nil {
		return
	}
	s.workspace.UpdateIfCurrent(workspaceID, generation, func(current *workspace.Record) {
		current.SourceID = record.SourceID
		current.AnalysisID = record.ID
		current.FusionRunID = record.FusionRunID
		current.Mode = record.Mode
		current.State = workspacev1.WorkspaceState_WORKSPACE_STATE_ANALYZING
	})
}
func modeFor(mode inputv1.InputMode) workspacev1.AnalysisMode {
	switch mode {
	case inputv1.InputMode_PASSIVE_LIVE:
		return workspacev1.AnalysisMode_PASSIVE_LIVE
	case inputv1.InputMode_PASSIVE_PCAP:
		return workspacev1.AnalysisMode_OFFLINE_PCAP
	case inputv1.InputMode_DEEP_ASSESSMENT:
		return workspacev1.AnalysisMode_DEEP_ASSESSMENT
	default:
		return workspacev1.AnalysisMode_ANALYSIS_MODE_UNSPECIFIED
	}
}
func defaultOptions(value *analysisv1.AnalysisOptions) *analysisv1.AnalysisOptions {
	if value == nil {
		return &analysisv1.AnalysisOptions{EnableSecurity: true, EnableMl: true, EnableMetadataExposure: true, EnableFusion: true}
	}
	return cloneOptions(value)
}
func cloneOptions(value *analysisv1.AnalysisOptions) *analysisv1.AnalysisOptions {
	if value == nil {
		return nil
	}
	return proto.Clone(value).(*analysisv1.AnalysisOptions)
}
