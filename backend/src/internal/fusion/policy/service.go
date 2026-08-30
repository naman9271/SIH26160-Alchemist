// Package policy implements the internal FusionPolicyService contract.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
)

var policyPropertyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*(\.\*)?$`)

type Loader interface {
	Load(context.Context) ([]Definition, string, error)
}

type ListRequest struct{}
type ListResponse struct{ Policies []Definition }
type GetRequest struct{ PolicyID string }
type SetActiveRequest struct{ PolicyID string }
type SetActiveResponse struct{ Policy Definition }
type ValidateRequest struct{ Policy Definition }
type ValidationIssue struct {
	Field   string
	Message string
}
type ValidateResponse struct {
	Valid  bool
	Issues []ValidationIssue
}
type ReloadRequest struct{}
type ReloadResponse struct {
	PoliciesLoaded uint64
	ActivePolicyID string
}

type Service struct {
	repository *Memory
	loader     Loader
}

func NewService(repository *Memory, loader Loader) *Service {
	return &Service{repository: repository, loader: loader}
}

func (s *Service) List(ctx context.Context, _ ListRequest) (ListResponse, error) {
	if err := s.ready(ctx); err != nil {
		return ListResponse{}, err
	}
	items, err := s.repository.List(ctx)
	return ListResponse{Policies: items}, err
}

func (s *Service) Get(ctx context.Context, request GetRequest) (Definition, error) {
	if err := s.ready(ctx); err != nil {
		return Definition{}, err
	}
	return s.repository.Resolve(ctx, strings.TrimSpace(request.PolicyID))
}

func (s *Service) GetActive(ctx context.Context) (Definition, error) {
	if err := s.ready(ctx); err != nil {
		return Definition{}, err
	}
	return s.repository.Active(ctx)
}

func (s *Service) SetActive(ctx context.Context, request SetActiveRequest) (SetActiveResponse, error) {
	if err := s.ready(ctx); err != nil {
		return SetActiveResponse{}, err
	}
	definition, err := s.repository.SetActive(ctx, request.PolicyID)
	return SetActiveResponse{Policy: definition}, err
}

func (s *Service) Validate(ctx context.Context, request ValidateRequest) (ValidateResponse, error) {
	if err := model.ContextError(ctx); err != nil {
		return ValidateResponse{}, err
	}
	issues := ValidateDefinition(request.Policy)
	return ValidateResponse{Valid: len(issues) == 0, Issues: issues}, nil
}

func (s *Service) Reload(ctx context.Context, _ ReloadRequest) (ReloadResponse, error) {
	if err := s.ready(ctx); err != nil {
		return ReloadResponse{}, err
	}
	if s.loader == nil {
		return ReloadResponse{}, model.NewError(model.ErrorFailedPrecondition, "Fusion policy file loader is not configured")
	}
	definitions, activeID, err := s.loader.Load(ctx)
	if err != nil {
		return ReloadResponse{}, err
	}
	for index, definition := range definitions {
		if issues := ValidateDefinition(definition); len(issues) > 0 {
			return ReloadResponse{}, model.NewError(model.ErrorInvalidArgument, fmt.Sprintf("policy %q is invalid: %s: %s", definition.ID, issues[0].Field, issues[0].Message))
		}
		definitions[index] = definition.Clone()
	}
	if err = s.repository.Replace(ctx, definitions, activeID); err != nil {
		return ReloadResponse{}, err
	}
	return ReloadResponse{PoliciesLoaded: uint64(len(definitions)), ActivePolicyID: activeID}, nil
}

func (s *Service) ready(ctx context.Context) error {
	if err := model.ContextError(ctx); err != nil {
		return err
	}
	if s == nil || s.repository == nil {
		return model.NewError(model.ErrorInternal, "Fusion policy repository is not configured")
	}
	return nil
}

func ValidateDefinition(definition Definition) []ValidationIssue {
	issues := make([]ValidationIssue, 0)
	add := func(field, message string) { issues = append(issues, ValidationIssue{Field: field, Message: message}) }
	if strings.TrimSpace(definition.ID) == "" {
		add("id", "is required")
	}
	if definition.SchemaVersion != SchemaVersion {
		add("schema_version", "must equal "+SchemaVersion)
	}
	if definition.FreshnessWindow < 0 {
		add("freshness_window", "must not be negative")
	}
	validateUnit := func(field string, value float64) {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
			add(field, "must be within [0,1]")
		}
	}
	validateUnit("minimum_confidence", definition.MinimumConfidence)
	validateUnit("conflict_threshold", definition.ConflictThreshold)
	validateUnit("correlation_threshold", definition.CorrelationThreshold)
	for source, trust := range definition.SourceTrust {
		if !source.Valid() {
			add("source_trust", "contains an unknown source")
		}
		validateUnit("source_trust."+string(source), trust)
	}
	requireSource := func(field string, source model.Source) {
		if !source.Valid() {
			add(field, "contains an unknown source")
			return
		}
		if _, exists := definition.SourceTrust[source]; !exists {
			add(field, "source "+string(source)+" has no trust definition")
		}
	}
	for _, source := range definition.RequiredSources {
		requireSource("required_sources", source)
	}
	seenStatus := make(map[commonv1.EvidenceStatus]struct{})
	for _, status := range definition.StatusPrecedence {
		if status < commonv1.EvidenceStatus_OBSERVED || status > commonv1.EvidenceStatus_UNKNOWN {
			add("status_precedence", "contains an unknown status")
			continue
		}
		if _, exists := seenStatus[status]; exists {
			add("status_precedence", "contains a duplicate status")
		}
		seenStatus[status] = struct{}{}
	}
	if len(definition.StatusPrecedence) == 0 {
		add("status_precedence", "must not be empty")
	}
	for _, property := range definition.RequiredProperties {
		if !knownProperty(property) || strings.HasSuffix(property, "*") {
			add("required_properties", "contains an unknown property pattern")
		}
	}
	for property, rule := range definition.PropertyRules {
		if !knownProperty(property) {
			add("property_rules."+property, "property key is invalid")
		}
		if rule.FreshnessWindow < 0 {
			add("property_rules."+property+".freshness_window", "must not be negative")
		}
		validateUnit("property_rules."+property+".minimum_confidence", rule.MinimumConfidence)
		seenSource := make(map[model.Source]struct{})
		for _, source := range rule.SourcePrecedence {
			requireSource("property_rules."+property+".source_precedence", source)
			if _, exists := seenSource[source]; exists {
				add("property_rules."+property+".source_precedence", "contains a duplicate source")
			}
			seenSource[source] = struct{}{}
		}
	}
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].Field < issues[j].Field })
	return issues
}

type DirectoryLoader struct{ Directory string }

type fileDefinition struct {
	ID                   string                   `json:"id"`
	SchemaVersion        string                   `json:"schema_version"`
	Active               bool                     `json:"active"`
	RequiredSources      []model.Source           `json:"required_sources"`
	RequiredProperties   []string                 `json:"required_properties"`
	SourceTrust          map[model.Source]float64 `json:"source_trust"`
	StatusPrecedence     []string                 `json:"status_precedence"`
	FreshnessWindow      string                   `json:"freshness_window"`
	MinimumConfidence    float64                  `json:"minimum_confidence"`
	ConflictThreshold    float64                  `json:"conflict_threshold"`
	CorrelationThreshold float64                  `json:"correlation_threshold"`
	PropertyRules        map[string]fileRule      `json:"property_rules"`
}
type fileRule struct {
	SourcePrecedence  []model.Source `json:"source_precedence"`
	FreshnessWindow   string         `json:"freshness_window"`
	MinimumConfidence float64        `json:"minimum_confidence"`
}

func (l DirectoryLoader) Load(ctx context.Context) ([]Definition, string, error) {
	if err := model.ContextError(ctx); err != nil {
		return nil, "", err
	}
	directory := strings.TrimSpace(l.Directory)
	if directory == "" {
		return nil, "", model.NewError(model.ErrorInvalidArgument, "Fusion policy directory is required")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, "", &model.Error{Kind: model.ErrorUnavailable, Message: "could not read Fusion policy directory", Cause: err}
	}
	definitions := make([]Definition, 0)
	activeID := ""
	for _, entry := range entries {
		if entry.IsDir() || strings.ToLower(filepath.Ext(entry.Name())) != ".json" {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(directory, entry.Name()))
		if readErr != nil {
			return nil, "", &model.Error{Kind: model.ErrorUnavailable, Message: "could not read Fusion policy file", Cause: readErr}
		}
		var wire fileDefinition
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		decoderErr := decoder.Decode(&wire)
		if decoderErr != nil {
			return nil, "", &model.Error{Kind: model.ErrorInvalidArgument, Message: "Fusion policy file contains invalid JSON", Cause: decoderErr}
		}
		if decoderErr = decoder.Decode(&struct{}{}); decoderErr != io.EOF {
			return nil, "", model.NewError(model.ErrorInvalidArgument, "Fusion policy file must contain exactly one JSON object")
		}
		definition, convertErr := wire.definition()
		if convertErr != nil {
			return nil, "", convertErr
		}
		definitions = append(definitions, definition)
		if wire.Active {
			if activeID != "" {
				return nil, "", model.NewError(model.ErrorInvalidArgument, "multiple Fusion policies are marked active")
			}
			activeID = definition.ID
		}
	}
	if len(definitions) == 0 {
		return nil, "", model.NewError(model.ErrorNotFound, "no versioned Fusion policy files were found")
	}
	sort.Slice(definitions, func(i, j int) bool { return definitions[i].ID < definitions[j].ID })
	if activeID == "" {
		activeID = definitions[0].ID
	}
	return definitions, activeID, nil
}

func knownProperty(property string) bool {
	if !policyPropertyPattern.MatchString(property) {
		return false
	}
	property = strings.ToLower(property)
	for _, prefix := range []string{"ike.", "child.", "sa.", "esp.", "replay.", "traffic.", "metadata.", "security.rule."} {
		if strings.HasPrefix(property, prefix) {
			return true
		}
	}
	return false
}

func (wire fileDefinition) definition() (Definition, error) {
	freshness, err := parseDuration(wire.FreshnessWindow, "freshness_window")
	if err != nil {
		return Definition{}, err
	}
	statuses := make([]commonv1.EvidenceStatus, 0, len(wire.StatusPrecedence))
	for _, name := range wire.StatusPrecedence {
		value, exists := commonv1.EvidenceStatus_value[strings.ToUpper(strings.TrimSpace(name))]
		if !exists {
			return Definition{}, model.NewError(model.ErrorInvalidArgument, "status_precedence contains an unknown status")
		}
		statuses = append(statuses, commonv1.EvidenceStatus(value))
	}
	rules := make(map[string]PropertyRule, len(wire.PropertyRules))
	for property, candidate := range wire.PropertyRules {
		duration, durationErr := parseDuration(candidate.FreshnessWindow, "property freshness_window")
		if durationErr != nil {
			return Definition{}, durationErr
		}
		rules[property] = PropertyRule{SourcePrecedence: candidate.SourcePrecedence, FreshnessWindow: duration, MinimumConfidence: candidate.MinimumConfidence}
	}
	return Definition{ID: wire.ID, SchemaVersion: wire.SchemaVersion, RequiredSources: wire.RequiredSources,
		RequiredProperties: wire.RequiredProperties, SourceTrust: wire.SourceTrust, StatusPrecedence: statuses,
		FreshnessWindow: freshness, MinimumConfidence: wire.MinimumConfidence, ConflictThreshold: wire.ConflictThreshold,
		CorrelationThreshold: wire.CorrelationThreshold, PropertyRules: rules}, nil
}

func parseDuration(value, field string) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return 0, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, &model.Error{Kind: model.ErrorInvalidArgument, Message: field + " is invalid", Cause: err}
	}
	return duration, nil
}
