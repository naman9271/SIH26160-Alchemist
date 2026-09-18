// Package model contains transport-neutral Fusion domain types.
package model

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/google/uuid"
	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const DefaultPolicyID = "fusion-default-v1"
const EvidenceSchemaVersion = "fusion-evidence.v1"

type HealthStatus string

const (
	HealthHealthy   HealthStatus = "HEALTHY"
	HealthDegraded  HealthStatus = "DEGRADED"
	HealthUnhealthy HealthStatus = "UNHEALTHY"
)

type RunState string

const (
	RunStateActive    RunState = "ACTIVE"
	RunStateFinalized RunState = "FINALIZED"
	RunStateCancelled RunState = "CANCELLED"
)

type Source string

const (
	SourcePacketParser Source = "PACKET_PARSER"
	SourceFlowAnalyzer Source = "FLOW_ANALYZER"
	SourceVICI         Source = "STRONGSWAN_VICI"
	SourceXFRM         Source = "LINUX_XFRM"
	SourceMLClassifier Source = "ML_CLASSIFIER"
	SourceMLAnomaly    Source = "ML_ANOMALY"
	SourceSHAP         Source = "SHAP"
	SourceSecurityRule Source = "SECURITY_RULE_ENGINE"
	SourceOperator     Source = "OPERATOR_INPUT"
)

func (s Source) Valid() bool {
	switch s {
	case SourcePacketParser, SourceFlowAnalyzer, SourceVICI, SourceXFRM,
		SourceMLClassifier, SourceMLAnomaly, SourceSHAP, SourceSecurityRule, SourceOperator:
		return true
	default:
		return false
	}
}

type SourceState string

const (
	SourcePending     SourceState = "PENDING"
	SourceComplete    SourceState = "COMPLETE"
	SourceFailed      SourceState = "FAILED"
	SourceTimedOut    SourceState = "TIMED_OUT"
	SourceUnavailable SourceState = "UNAVAILABLE"
)

func (s SourceState) Terminal() bool {
	return s == SourceComplete || s == SourceFailed || s == SourceTimedOut || s == SourceUnavailable
}

type SourceCoverage struct {
	Source     Source
	State      SourceState
	ReasonCode string
	UpdatedAt  time.Time
}

type Counts struct {
	Evidence    uint64
	Conclusions uint64
	Conflicts   uint64
}

type EvidenceItem struct {
	ID              string
	AnalysisID      string
	PropertyKey     string
	Value           *structpb.Value
	Source          Source
	Status          commonv1.EvidenceStatus
	Confidence      float64
	ObservedAt      time.Time
	ResourceType    string
	ResourceID      string
	SourceReference string
	SchemaVersion   string
	Metadata        map[string]string
}

func (e EvidenceItem) Clone() EvidenceItem {
	copy := e
	if e.Value != nil {
		copy.Value = proto.Clone(e.Value).(*structpb.Value)
	}
	copy.Metadata = maps.Clone(e.Metadata)
	return copy
}

type CorrelationGroup struct {
	ID                 string
	ResourceType       string
	ResourceID         string
	EvidenceIDs        []string
	Keys               map[string]string
	FirstObservedAt    time.Time
	LastObservedAt     time.Time
	UncertaintyReasons []string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type ConflictState string

const (
	ConflictOpen     ConflictState = "OPEN"
	ConflictResolved ConflictState = "RESOLVED"
)

type ResolutionMode string

const (
	ResolutionPolicy         ResolutionMode = "POLICY"
	ResolutionManualOperator ResolutionMode = "MANUAL_OPERATOR_OVERRIDE"
)

type EvidenceConflict struct {
	ID                   string
	PropertyKey          string
	ResourceType         string
	ResourceID           string
	CandidateEvidenceIDs []string
	State                ConflictState
	WinningEvidenceID    string
	ResolutionMode       ResolutionMode
	RationaleCode        string
	CreatedAt            time.Time
	UpdatedAt            time.Time
	ResolvedAt           time.Time
}

func (c EvidenceConflict) Clone() EvidenceConflict {
	copy := c
	copy.CandidateEvidenceIDs = append([]string(nil), c.CandidateEvidenceIDs...)
	return copy
}

type ConfidenceBand string

const (
	ConfidenceVeryLow  ConfidenceBand = "VERY_LOW"
	ConfidenceLow      ConfidenceBand = "LOW"
	ConfidenceMedium   ConfidenceBand = "MEDIUM"
	ConfidenceHigh     ConfidenceBand = "HIGH"
	ConfidenceVeryHigh ConfidenceBand = "VERY_HIGH"
)

type ConfidenceBreakdown struct {
	SourceTrust        float64
	StatusTrust        float64
	Agreement          float64
	Freshness          float64
	CorrelationQuality float64
	ModelConfidence    *float64
	FinalConfidence    float64
	Band               ConfidenceBand
}

func (b ConfidenceBreakdown) Clone() ConfidenceBreakdown {
	copy := b
	if b.ModelConfidence != nil {
		value := *b.ModelConfidence
		copy.ModelConfidence = &value
	}
	return copy
}

type FusedConclusion struct {
	ID                    string
	AnalysisID            string
	PropertyKey           string
	ResourceType          string
	ResourceID            string
	Value                 *structpb.Value
	Confidence            float64
	Band                  ConfidenceBand
	Status                commonv1.EvidenceStatus
	EvidenceIDs           []string
	WinningEvidenceID     string
	SupportingEvidenceIDs []string
	WinningSources        []Source
	HasConflict           bool
	ConflictID            string
	RationaleCode         string
	Breakdown             ConfidenceBreakdown
	ComputedAt            time.Time
}

func (c FusedConclusion) Clone() FusedConclusion {
	copy := c
	if c.Value != nil {
		copy.Value = proto.Clone(c.Value).(*structpb.Value)
	}
	copy.EvidenceIDs = append([]string(nil), c.EvidenceIDs...)
	copy.SupportingEvidenceIDs = append([]string(nil), c.SupportingEvidenceIDs...)
	copy.WinningSources = append([]Source(nil), c.WinningSources...)
	copy.Breakdown = c.Breakdown.Clone()
	return copy
}

type FusionState string

const (
	FusionIdle     FusionState = "IDLE"
	FusionRunning  FusionState = "RUNNING"
	FusionComplete FusionState = "COMPLETE"
	FusionFailed   FusionState = "FAILED"
)

type FusionExecution struct {
	State                    FusionState
	Incremental              bool
	StartedAt                time.Time
	CompletedAt              time.Time
	LastError                string
	LastRecomputedProperties []string
}

type EventType string

const (
	EventFusionRunCreated          EventType = "FUSION_RUN_CREATED"
	EventEvidenceAdded             EventType = "EVIDENCE_ADDED"
	EventEvidenceRemoved           EventType = "EVIDENCE_REMOVED"
	EventSourceCompleted           EventType = "SOURCE_COMPLETED"
	EventSourceUnavailable         EventType = "SOURCE_UNAVAILABLE"
	EventCorrelationCreated        EventType = "CORRELATION_CREATED"
	EventCorrelationChanged        EventType = "CORRELATION_CHANGED"
	EventConflictDetected          EventType = "CONFLICT_DETECTED"
	EventConflictResolved          EventType = "CONFLICT_RESOLVED"
	EventConfidenceUpdated         EventType = "CONFIDENCE_UPDATED"
	EventConclusionCreated         EventType = "CONCLUSION_CREATED"
	EventConclusionUpdated         EventType = "CONCLUSION_UPDATED"
	EventFusionCompletenessUpdated EventType = "FUSION_COMPLETENESS_UPDATED"
	EventFusionFinalized           EventType = "FUSION_FINALIZED"
	EventFusionFailed              EventType = "FUSION_FAILED"
)

func (t EventType) Valid() bool {
	switch t {
	case EventFusionRunCreated, EventEvidenceAdded, EventEvidenceRemoved, EventSourceCompleted,
		EventSourceUnavailable, EventCorrelationCreated, EventCorrelationChanged, EventConflictDetected,
		EventConflictResolved, EventConfidenceUpdated, EventConclusionCreated, EventConclusionUpdated,
		EventFusionCompletenessUpdated, EventFusionFinalized, EventFusionFailed:
		return true
	default:
		return false
	}
}

type FusionEvent struct {
	ID            string
	Sequence      uint64
	FusionRunID   string
	AnalysisID    string
	Type          EventType
	OccurredAt    time.Time
	PropertyKey   string
	EvidenceID    string
	CorrelationID string
	ConflictID    string
	ConclusionID  string
	Source        Source
	ReasonCode    string
	Conclusion    *FusedConclusion
}

func (e FusionEvent) Clone() FusionEvent {
	copy := e
	if e.Conclusion != nil {
		conclusion := e.Conclusion.Clone()
		copy.Conclusion = &conclusion
	}
	return copy
}

func (e FusionExecution) Clone() FusionExecution {
	e.LastRecomputedProperties = append([]string(nil), e.LastRecomputedProperties...)
	return e
}

func (g CorrelationGroup) Clone() CorrelationGroup {
	copy := g
	copy.EvidenceIDs = append([]string(nil), g.EvidenceIDs...)
	copy.Keys = maps.Clone(g.Keys)
	copy.UncertaintyReasons = append([]string(nil), g.UncertaintyReasons...)
	return copy
}

type Run struct {
	ID                 string
	AnalysisID         string
	PolicyID           string
	State              RunState
	Counts             Counts
	RequiredSources    []Source
	SourceCoverage     map[Source]SourceCoverage
	EvidenceByID       map[string]EvidenceItem
	EvidenceByProperty map[string][]string
	EvidenceByResource map[string][]string
	Correlations       map[string]CorrelationGroup
	Conflicts          map[string]EvidenceConflict
	Conclusions        map[string]FusedConclusion
	ConclusionByKey    map[string]string
	Fusion             FusionExecution
	CreatedAt          time.Time
	UpdatedAt          time.Time
	FinalizedAt        time.Time
	CancelledAt        time.Time
}

func (r Run) Clone() Run {
	copy := r
	copy.RequiredSources = append([]Source(nil), r.RequiredSources...)
	copy.SourceCoverage = make(map[Source]SourceCoverage, len(r.SourceCoverage))
	for source, coverage := range r.SourceCoverage {
		copy.SourceCoverage[source] = coverage
	}
	copy.EvidenceByID = make(map[string]EvidenceItem, len(r.EvidenceByID))
	for id, item := range r.EvidenceByID {
		copy.EvidenceByID[id] = item.Clone()
	}
	copy.EvidenceByProperty = cloneIndex(r.EvidenceByProperty)
	copy.EvidenceByResource = cloneIndex(r.EvidenceByResource)
	copy.Correlations = make(map[string]CorrelationGroup, len(r.Correlations))
	for id, group := range r.Correlations {
		copy.Correlations[id] = group.Clone()
	}
	copy.Conflicts = make(map[string]EvidenceConflict, len(r.Conflicts))
	for id, conflict := range r.Conflicts {
		copy.Conflicts[id] = conflict.Clone()
	}
	copy.Conclusions = make(map[string]FusedConclusion, len(r.Conclusions))
	for id, conclusion := range r.Conclusions {
		copy.Conclusions[id] = conclusion.Clone()
	}
	copy.ConclusionByKey = maps.Clone(r.ConclusionByKey)
	copy.Fusion = r.Fusion.Clone()
	return copy
}

func cloneIndex(index map[string][]string) map[string][]string {
	copy := make(map[string][]string, len(index))
	for key, ids := range index {
		copy[key] = append([]string(nil), ids...)
	}
	return copy
}

type FinalSummary struct {
	FusionRunID      string
	State            RunState
	Counts           Counts
	CompletedSources uint64
	FailedSources    uint64
	TimedOutSources  uint64
	Unavailable      []Source
	FinalizedAt      time.Time
}

type ErrorKind string

const (
	ErrorInvalidArgument    ErrorKind = "INVALID_ARGUMENT"
	ErrorNotFound           ErrorKind = "NOT_FOUND"
	ErrorAlreadyExists      ErrorKind = "ALREADY_EXISTS"
	ErrorFailedPrecondition ErrorKind = "FAILED_PRECONDITION"
	ErrorResourceExhausted  ErrorKind = "RESOURCE_EXHAUSTED"
	ErrorUnavailable        ErrorKind = "UNAVAILABLE"
	ErrorDeadlineExceeded   ErrorKind = "DEADLINE_EXCEEDED"
	ErrorCancelled          ErrorKind = "CANCELLED"
	ErrorInternal           ErrorKind = "INTERNAL"
)

type Error struct {
	Kind    ErrorKind
	Message string
	Cause   error
}

func (e *Error) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("%s: %s", e.Kind, e.Message)
	}
	return fmt.Sprintf("%s: %s: %v", e.Kind, e.Message, e.Cause)
}

func (e *Error) Unwrap() error { return e.Cause }

func NewError(kind ErrorKind, message string) *Error {
	return &Error{Kind: kind, Message: message}
}

func ContextError(ctx context.Context) error {
	if ctx == nil {
		return NewError(ErrorInvalidArgument, "context is required")
	}
	if err := ctx.Err(); errors.Is(err, context.Canceled) {
		return &Error{Kind: ErrorCancelled, Message: "operation was cancelled", Cause: err}
	} else if errors.Is(err, context.DeadlineExceeded) {
		return &Error{Kind: ErrorDeadlineExceeded, Message: "operation deadline exceeded", Cause: err}
	}
	return nil
}

func NewFusionRunID() (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("generate fusion run UUIDv7: %w", err)
	}
	return id.String(), nil
}

func NewEvidenceID() (string, error)    { return newUUIDv7("evidence") }
func NewCorrelationID() (string, error) { return newUUIDv7("correlation") }
func NewConflictID() (string, error)    { return newUUIDv7("conflict") }
func NewConclusionID() (string, error)  { return newUUIDv7("conclusion") }
func NewFusionEventID() (string, error) { return newUUIDv7("Fusion event") }

func newUUIDv7(resource string) (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("generate %s UUIDv7: %w", resource, err)
	}
	return id.String(), nil
}

func ValidateAnalysisID(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return NewError(ErrorInvalidArgument, "analysis_id is required")
	}
	id, err := uuid.Parse(value)
	if err != nil {
		return NewError(ErrorInvalidArgument, "analysis_id must be a UUID")
	}
	if id.Version() != 7 {
		return NewError(ErrorInvalidArgument, "analysis_id must be a UUIDv7")
	}
	return nil
}

func ValidateRunID(value string) error {
	return validateUUIDv7(value, "fusion_run_id")
}

func ValidateEvidenceID(value string) error {
	return validateUUIDv7(value, "evidence_id")
}

func ValidateCorrelationID(value string) error {
	return validateUUIDv7(value, "correlation_id")
}

func ValidateConflictID(value string) error    { return validateUUIDv7(value, "conflict_id") }
func ValidateConclusionID(value string) error  { return validateUUIDv7(value, "conclusion_id") }
func ValidateFusionEventID(value string) error { return validateUUIDv7(value, "event_id") }

func validateUUIDv7(value, field string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return NewError(ErrorInvalidArgument, field+" is required")
	}
	id, err := uuid.Parse(value)
	if err != nil {
		return NewError(ErrorInvalidArgument, field+" must be a UUID")
	}
	if id.Version() != 7 {
		return NewError(ErrorInvalidArgument, field+" must be a UUIDv7")
	}
	return nil
}
