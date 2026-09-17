// Package ingest implements the internal EvidenceIngestService contract.
package ingest

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/evidence"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	propertyPattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,254}$`)
	resourcePattern   = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	reasonCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
)

const maxBatchValueBytes = 16 << 20

var sensitiveTerms = []string{"private_key", "key_bytes", "packet_payload", "raw_payload", "password", "credential", "shared_secret", "preshared_key", "psk"}

type Store interface {
	Get(context.Context, string) (model.Run, error)
	AddEvidence(context.Context, string, []model.EvidenceItem) (model.Run, error)
	RemoveEvidence(context.Context, string, string) (model.EvidenceItem, model.Run, error)
	SetSourceCoverage(context.Context, string, model.Source, model.SourceState, string) (model.Run, error)
}

type RecomputeScheduler interface {
	Schedule(context.Context, string, []string) error
}
type EventPublisher interface {
	Publish(context.Context, model.FusionEvent) error
}

type EvidenceInput struct {
	PropertyKey     string
	Value           *structpb.Value
	Source          model.Source
	Status          commonv1.EvidenceStatus
	Confidence      float64
	ObservedAt      time.Time
	ResourceType    string
	ResourceID      string
	SourceReference string
	SchemaVersion   string
	Metadata        map[string]string
}

type AddRequest struct {
	FusionRunID string
	Evidence    EvidenceInput
}

type AddResponse struct {
	EvidenceID         string
	Accepted           bool
	TriggeredRecompute bool
}

type AddBatchRequest struct {
	FusionRunID string
	Evidence    []EvidenceInput
}

type ValidationError struct {
	Index   int
	Message string
}

type AddBatchResponse struct {
	EvidenceIDs        []string
	AcceptedCount      uint64
	RejectedCount      uint64
	ValidationErrors   []ValidationError
	RecomputeScheduled bool
}

type MarkSourceRequest struct {
	FusionRunID string
	Source      model.Source
}

type MarkSourceUnavailableRequest struct {
	FusionRunID string
	Source      model.Source
	ReasonCode  string
}

type MarkSourceResponse struct{ Coverage model.SourceCoverage }

type RemoveRequest struct {
	FusionRunID string
	EvidenceID  string
}

type RemoveResponse struct {
	EvidenceID         string
	Removed            bool
	TriggeredRecompute bool
}

type Service struct {
	store     Store
	scheduler RecomputeScheduler
	now       func() time.Time
	newID     func() (string, error)
	events    EventPublisher
}

func New(store Store, scheduler RecomputeScheduler, publishers ...EventPublisher) *Service {
	service := &Service{store: store, scheduler: scheduler, now: func() time.Time { return time.Now().UTC() }, newID: model.NewEvidenceID}
	if len(publishers) > 0 {
		service.events = publishers[0]
	}
	return service
}

func (s *Service) Add(ctx context.Context, request AddRequest) (AddResponse, error) {
	if err := s.ready(ctx, request.FusionRunID); err != nil {
		return AddResponse{}, err
	}
	run, err := s.store.Get(ctx, strings.TrimSpace(request.FusionRunID))
	if err != nil {
		return AddResponse{}, err
	}
	item, err := s.prepare(run, request.Evidence)
	if err != nil {
		return AddResponse{}, err
	}
	if _, err = s.store.AddEvidence(ctx, run.ID, []model.EvidenceItem{item}); err != nil {
		return AddResponse{}, err
	}
	if err = s.publishEvidence(ctx, run, model.EventEvidenceAdded, item); err != nil {
		return AddResponse{}, err
	}
	triggered, scheduleErr := s.schedule(ctx, run.ID, []model.EvidenceItem{item})
	response := AddResponse{EvidenceID: item.ID, Accepted: true, TriggeredRecompute: triggered}
	return response, scheduleErr
}

func (s *Service) AddBatch(ctx context.Context, request AddBatchRequest) (AddBatchResponse, error) {
	if err := s.ready(ctx, request.FusionRunID); err != nil {
		return AddBatchResponse{}, err
	}
	if len(request.Evidence) == 0 {
		return AddBatchResponse{}, model.NewError(model.ErrorInvalidArgument, "at least one evidence item is required")
	}
	if len(request.Evidence) > 10_000 {
		return AddBatchResponse{}, model.NewError(model.ErrorResourceExhausted, "evidence batch must not exceed 10000 items")
	}
	run, err := s.store.Get(ctx, strings.TrimSpace(request.FusionRunID))
	if err != nil {
		return AddBatchResponse{}, err
	}
	response := AddBatchResponse{EvidenceIDs: make([]string, 0, len(request.Evidence))}
	accepted := make([]model.EvidenceItem, 0, len(request.Evidence))
	valueBytes := 0
	for index, input := range request.Evidence {
		if input.Value != nil {
			valueBytes += proto.Size(input.Value)
		}
		if valueBytes > maxBatchValueBytes {
			return AddBatchResponse{}, model.NewError(model.ErrorResourceExhausted, "evidence batch values exceed 16 MiB")
		}
		item, itemErr := s.prepare(run, input)
		if itemErr != nil {
			response.RejectedCount++
			response.ValidationErrors = append(response.ValidationErrors, ValidationError{Index: index, Message: publicMessage(itemErr)})
			continue
		}
		accepted = append(accepted, item)
		response.EvidenceIDs = append(response.EvidenceIDs, item.ID)
	}
	if len(accepted) == 0 {
		return response, nil
	}
	if _, err = s.store.AddEvidence(ctx, run.ID, accepted); err != nil {
		return AddBatchResponse{}, err
	}
	for _, item := range accepted {
		if err = s.publishEvidence(ctx, run, model.EventEvidenceAdded, item); err != nil {
			return AddBatchResponse{}, err
		}
	}
	response.AcceptedCount = uint64(len(accepted))
	response.RecomputeScheduled, err = s.schedule(ctx, run.ID, accepted)
	return response, err
}

func (s *Service) MarkSourceComplete(ctx context.Context, request MarkSourceRequest) (MarkSourceResponse, error) {
	if err := s.ready(ctx, request.FusionRunID); err != nil {
		return MarkSourceResponse{}, err
	}
	if !request.Source.Valid() {
		return MarkSourceResponse{}, model.NewError(model.ErrorInvalidArgument, "evidence source is invalid")
	}
	run, err := s.store.SetSourceCoverage(ctx, strings.TrimSpace(request.FusionRunID), request.Source, model.SourceComplete, "")
	if err != nil {
		return MarkSourceResponse{}, err
	}
	if err = s.publishSource(ctx, run, model.EventSourceCompleted, request.Source, ""); err != nil {
		return MarkSourceResponse{}, err
	}
	return MarkSourceResponse{Coverage: run.SourceCoverage[request.Source]}, nil
}

func (s *Service) MarkSourceUnavailable(ctx context.Context, request MarkSourceUnavailableRequest) (MarkSourceResponse, error) {
	if err := s.ready(ctx, request.FusionRunID); err != nil {
		return MarkSourceResponse{}, err
	}
	if !request.Source.Valid() {
		return MarkSourceResponse{}, model.NewError(model.ErrorInvalidArgument, "evidence source is invalid")
	}
	request.ReasonCode = strings.TrimSpace(request.ReasonCode)
	if !reasonCodePattern.MatchString(request.ReasonCode) {
		return MarkSourceResponse{}, model.NewError(model.ErrorInvalidArgument, "reason_code must be an uppercase machine-readable code")
	}
	run, err := s.store.SetSourceCoverage(ctx, strings.TrimSpace(request.FusionRunID), request.Source, model.SourceUnavailable, request.ReasonCode)
	if err != nil {
		return MarkSourceResponse{}, err
	}
	if err = s.publishSource(ctx, run, model.EventSourceUnavailable, request.Source, request.ReasonCode); err != nil {
		return MarkSourceResponse{}, err
	}
	return MarkSourceResponse{Coverage: run.SourceCoverage[request.Source]}, nil
}

func (s *Service) Remove(ctx context.Context, request RemoveRequest) (RemoveResponse, error) {
	if err := s.ready(ctx, request.FusionRunID); err != nil {
		return RemoveResponse{}, err
	}
	if err := model.ValidateEvidenceID(request.EvidenceID); err != nil {
		return RemoveResponse{}, err
	}
	removed, _, err := s.store.RemoveEvidence(ctx, strings.TrimSpace(request.FusionRunID), strings.TrimSpace(request.EvidenceID))
	if err != nil {
		return RemoveResponse{}, err
	}
	run, err := s.store.Get(ctx, strings.TrimSpace(request.FusionRunID))
	if err != nil {
		return RemoveResponse{}, err
	}
	if err = s.publishEvidence(ctx, run, model.EventEvidenceRemoved, removed); err != nil {
		return RemoveResponse{}, err
	}
	triggered, scheduleErr := s.schedule(ctx, strings.TrimSpace(request.FusionRunID), []model.EvidenceItem{removed})
	return RemoveResponse{EvidenceID: removed.ID, Removed: true, TriggeredRecompute: triggered}, scheduleErr
}

func (s *Service) publishEvidence(ctx context.Context, run model.Run, eventType model.EventType, item model.EvidenceItem) error {
	if s.events == nil {
		return nil
	}
	if err := s.events.Publish(ctx, model.FusionEvent{FusionRunID: run.ID, AnalysisID: run.AnalysisID, Type: eventType,
		OccurredAt: s.now().UTC(), PropertyKey: item.PropertyKey, EvidenceID: item.ID, Source: item.Source}); err != nil {
		return &model.Error{Kind: model.ErrorUnavailable, Message: "evidence changed but its Fusion event could not be emitted", Cause: err}
	}
	return nil
}

func (s *Service) publishSource(ctx context.Context, run model.Run, eventType model.EventType, source model.Source, reason string) error {
	if s.events == nil {
		return nil
	}
	if err := s.events.Publish(ctx, model.FusionEvent{FusionRunID: run.ID, AnalysisID: run.AnalysisID, Type: eventType,
		OccurredAt: s.now().UTC(), Source: source, ReasonCode: reason}); err != nil {
		return &model.Error{Kind: model.ErrorUnavailable, Message: "source coverage changed but its Fusion event could not be emitted", Cause: err}
	}
	return nil
}

func (s *Service) ready(ctx context.Context, runID string) error {
	if err := model.ContextError(ctx); err != nil {
		return err
	}
	if s == nil || s.store == nil {
		return model.NewError(model.ErrorInternal, "evidence store is not configured")
	}
	return model.ValidateRunID(runID)
}

func (s *Service) prepare(run model.Run, input EvidenceInput) (model.EvidenceItem, error) {
	if run.State != model.RunStateActive {
		return model.EvidenceItem{}, model.NewError(model.ErrorFailedPrecondition, "evidence can only be added to an active Fusion run")
	}
	input.PropertyKey = evidence.Canonical(strings.TrimSpace(input.PropertyKey))
	input.ResourceType = strings.ToUpper(strings.TrimSpace(input.ResourceType))
	input.ResourceID = strings.TrimSpace(input.ResourceID)
	input.SourceReference = strings.TrimSpace(input.SourceReference)
	if !propertyPattern.MatchString(input.PropertyKey) {
		return model.EvidenceItem{}, model.NewError(model.ErrorInvalidArgument, "property_key is invalid")
	}
	if input.Value == nil {
		return model.EvidenceItem{}, model.NewError(model.ErrorInvalidArgument, "evidence value is required")
	}
	if proto.Size(input.Value) > 64<<10 {
		return model.EvidenceItem{}, model.NewError(model.ErrorResourceExhausted, "evidence value exceeds 64 KiB")
	}
	if containsSensitiveTerm(input.PropertyKey) {
		return model.EvidenceItem{}, model.NewError(model.ErrorInvalidArgument, "sensitive key or payload evidence is prohibited")
	}
	if input.Status == commonv1.EvidenceStatus_UNKNOWN {
		input.Value = structpb.NewNullValue()
	}
	if !input.Source.Valid() {
		return model.EvidenceItem{}, model.NewError(model.ErrorInvalidArgument, "evidence source is invalid")
	}
	if err := validateStatus(input.Source, input.Status); err != nil {
		return model.EvidenceItem{}, err
	}
	if math.IsNaN(input.Confidence) || math.IsInf(input.Confidence, 0) || input.Confidence < 0 || input.Confidence > 1 {
		return model.EvidenceItem{}, model.NewError(model.ErrorInvalidArgument, "confidence must be within [0,1]")
	}
	if input.ObservedAt.IsZero() {
		return model.EvidenceItem{}, model.NewError(model.ErrorInvalidArgument, "observed_at is required")
	}
	if input.ObservedAt.After(s.now().Add(5 * time.Minute)) {
		return model.EvidenceItem{}, model.NewError(model.ErrorInvalidArgument, "observed_at is too far in the future")
	}
	if !resourcePattern.MatchString(input.ResourceType) || input.ResourceID == "" || len(input.ResourceID) > 256 {
		return model.EvidenceItem{}, model.NewError(model.ErrorInvalidArgument, "resource_type and resource_id are required and must be valid")
	}
	if len(input.SourceReference) > 512 {
		return model.EvidenceItem{}, model.NewError(model.ErrorInvalidArgument, "source_reference exceeds 512 characters")
	}
	if coverage, exists := run.SourceCoverage[input.Source]; exists && coverage.State.Terminal() {
		return model.EvidenceItem{}, model.NewError(model.ErrorFailedPrecondition, "evidence source has already reached a terminal state")
	}
	id, err := s.newID()
	if err != nil {
		return model.EvidenceItem{}, &model.Error{Kind: model.ErrorInternal, Message: "could not generate evidence ID", Cause: err}
	}
	schemaVersion := strings.TrimSpace(input.SchemaVersion)
	if schemaVersion == "" {
		schemaVersion = model.EvidenceSchemaVersion
	}
	if len(schemaVersion) > 128 {
		return model.EvidenceItem{}, model.NewError(model.ErrorInvalidArgument, "schema_version exceeds 128 characters")
	}
	if len(input.Metadata) > 128 {
		return model.EvidenceItem{}, model.NewError(model.ErrorResourceExhausted, "evidence metadata must not exceed 128 entries")
	}
	metadata := make(map[string]string, len(input.Metadata))
	for key, value := range input.Metadata {
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if key == "" || len(key) > 128 || len(value) > 1024 {
			return model.EvidenceItem{}, model.NewError(model.ErrorInvalidArgument, "evidence metadata contains an invalid key or value")
		}
		if containsSensitiveTerm(key) {
			return model.EvidenceItem{}, model.NewError(model.ErrorInvalidArgument, "sensitive evidence metadata is prohibited")
		}
		metadata[key] = value
	}
	return model.EvidenceItem{
		ID: id, AnalysisID: run.AnalysisID, PropertyKey: input.PropertyKey, Value: input.Value,
		Source: input.Source, Status: input.Status, Confidence: input.Confidence, ObservedAt: input.ObservedAt.UTC(),
		ResourceType: input.ResourceType, ResourceID: input.ResourceID, SourceReference: input.SourceReference,
		SchemaVersion: schemaVersion, Metadata: metadata,
	}.Clone(), nil
}

func validateStatus(source model.Source, status commonv1.EvidenceStatus) error {
	valid := status == commonv1.EvidenceStatus_OBSERVED || status == commonv1.EvidenceStatus_DERIVED ||
		status == commonv1.EvidenceStatus_INFERRED || status == commonv1.EvidenceStatus_VERIFIED_GATEWAY || status == commonv1.EvidenceStatus_UNKNOWN
	if !valid {
		return model.NewError(model.ErrorInvalidArgument, "evidence status is invalid")
	}
	if (source == model.SourceMLClassifier || source == model.SourceMLAnomaly || source == model.SourceSHAP) && status != commonv1.EvidenceStatus_INFERRED && status != commonv1.EvidenceStatus_UNKNOWN {
		return model.NewError(model.ErrorInvalidArgument, "ML and SHAP evidence must be INFERRED or UNKNOWN")
	}
	if (source == model.SourceVICI || source == model.SourceXFRM) && status != commonv1.EvidenceStatus_VERIFIED_GATEWAY && status != commonv1.EvidenceStatus_UNKNOWN {
		return model.NewError(model.ErrorInvalidArgument, "VICI and XFRM evidence must be VERIFIED_GATEWAY or UNKNOWN")
	}
	if (source == model.SourcePacketParser || source == model.SourceFlowAnalyzer) && status != commonv1.EvidenceStatus_OBSERVED && status != commonv1.EvidenceStatus_DERIVED && status != commonv1.EvidenceStatus_UNKNOWN {
		return model.NewError(model.ErrorInvalidArgument, "passive evidence must be OBSERVED, DERIVED, or UNKNOWN")
	}
	if (source == model.SourceSecurityRule || source == model.SourceOperator) && status != commonv1.EvidenceStatus_OBSERVED && status != commonv1.EvidenceStatus_DERIVED && status != commonv1.EvidenceStatus_UNKNOWN {
		return model.NewError(model.ErrorInvalidArgument, "security and operator evidence must be OBSERVED, DERIVED, or UNKNOWN")
	}
	return nil
}

func containsSensitiveTerm(value string) bool {
	value = strings.ToLower(value)
	for _, term := range sensitiveTerms {
		if strings.Contains(value, term) {
			return true
		}
	}
	return false
}

func (s *Service) schedule(ctx context.Context, runID string, items []model.EvidenceItem) (bool, error) {
	if s.scheduler == nil {
		return false, nil
	}
	set := make(map[string]struct{})
	for _, item := range items {
		if item.Source != model.SourceSecurityRule {
			set[item.PropertyKey] = struct{}{}
		}
	}
	if len(set) == 0 {
		return false, nil
	}
	properties := make([]string, 0, len(set))
	for property := range set {
		properties = append(properties, property)
	}
	sort.Strings(properties)
	if err := s.scheduler.Schedule(ctx, runID, properties); err != nil {
		return false, &model.Error{Kind: model.ErrorUnavailable, Message: "evidence was accepted but recomputation could not be scheduled", Cause: err}
	}
	return true, nil
}

func publicMessage(err error) string {
	if fusionErr, ok := err.(*model.Error); ok {
		return fusionErr.Message
	}
	return fmt.Sprintf("invalid evidence: %v", err)
}
