// Package security adapts fused evidence to the existing deterministic rule engine.
package security

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	securityv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/security"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	rules "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/security"
)

// ConclusionProvider returns Fusion's winning conclusions for an analysis.
type ConclusionProvider interface {
	FusedConclusions(context.Context, string) ([]model.FusedConclusion, error)
}

type Record struct {
	ID, AnalysisID, PolicyID string
	State                    securityv1.AssessmentState
	Result                   rules.Assessment
	UnknownEvidence          uint64
	MetadataExposure         bool
	CreatedAt, UpdatedAt     time.Time
	Failure                  string
}
type Service struct {
	mu          sync.RWMutex
	conclusions ConclusionProvider
	records     map[string]*Record
}

func New(conclusions ConclusionProvider) *Service {
	return &Service{conclusions: conclusions, records: map[string]*Record{}}
}

func (s *Service) Run(ctx context.Context, analysisID, policyID string) (Record, error) {
	if s == nil || s.conclusions == nil {
		return Record{}, shared.NewError(shared.Internal, "", "security Fusion conclusion provider is not configured")
	}
	if strings.TrimSpace(analysisID) == "" {
		return Record{}, shared.NewError(shared.InvalidArgument, "", "analysis_id is required")
	}
	if strings.TrimSpace(policyID) == "" {
		policyID = model.DefaultPolicyID
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Record{}, err
	}
	now := time.Now().UTC()
	record := &Record{ID: id.String(), AnalysisID: analysisID, PolicyID: policyID, State: securityv1.AssessmentState_ASSESSMENT_RUNNING, CreatedAt: now, UpdatedAt: now}
	s.mu.Lock()
	s.records[record.ID] = record
	s.mu.Unlock()
	return s.evaluate(ctx, record.ID)
}
func (s *Service) Get(ctx context.Context, id string) (Record, error) {
	if ctx == nil {
		return Record{}, shared.NewError(shared.InvalidArgument, "", "context is required")
	}
	s.mu.RLock()
	record := s.records[id]
	if record != nil {
		copy := *record
		record = &copy
	}
	s.mu.RUnlock()
	if record == nil {
		return Record{}, shared.NewError(shared.NotFound, "", "security assessment was not found")
	}
	return *record, nil
}

// LatestForAnalysis returns the newest completed assessment for report and
// dashboard composition without requiring callers to maintain shadow IDs.
func (s *Service) LatestForAnalysis(ctx context.Context, analysisID string) (Record, error) {
	if strings.TrimSpace(analysisID) == "" {
		return Record{}, shared.NewError(shared.InvalidArgument, "", "analysis_id is required")
	}
	s.mu.RLock()
	var selected *Record
	for _, candidate := range s.records {
		if candidate.AnalysisID == analysisID && candidate.State == securityv1.AssessmentState_ASSESSMENT_COMPLETED && (selected == nil || candidate.UpdatedAt.After(selected.UpdatedAt)) {
			copy := *candidate
			selected = &copy
		}
	}
	s.mu.RUnlock()
	if selected == nil {
		return Record{}, shared.NewError(shared.NotFound, "", "completed security assessment was not found")
	}
	return *selected, nil
}
func (s *Service) Reevaluate(ctx context.Context, id, policyID string) (Record, error) {
	old, err := s.Get(ctx, id)
	if err != nil {
		return Record{}, err
	}
	if policyID != "" {
		s.mu.Lock()
		if record := s.records[id]; record != nil {
			record.PolicyID = policyID
			record.UpdatedAt = time.Now().UTC()
		}
		s.mu.Unlock()
	}
	return s.evaluate(ctx, old.ID)
}

func (s *Service) evaluate(ctx context.Context, id string) (Record, error) {
	record, err := s.Get(ctx, id)
	if err != nil {
		return Record{}, err
	}
	items, err := s.conclusions.FusedConclusions(ctx, record.AnalysisID)
	if err != nil {
		s.fail(id, err)
		return s.Get(ctx, id)
	}
	scopes, unknown, metadata := facts(items)
	results := make([]rules.Assessment, 0, len(scopes))
	for _, scope := range scopes {
		result := rules.Assess(scope.Facts)
		for index := range result.Findings {
			result.Findings[index].ResourceType = scope.ResourceType
			result.Findings[index].ResourceID = scope.ResourceID
		}
		results = append(results, result)
	}
	result := mergeAssessments(results)
	s.mu.Lock()
	stored := s.records[id]
	stored.State, stored.Result, stored.UnknownEvidence, stored.MetadataExposure = securityv1.AssessmentState_ASSESSMENT_COMPLETED, result, unknown, metadata
	stored.Failure, stored.UpdatedAt = "", time.Now().UTC()
	out := *stored
	s.mu.Unlock()
	return out, nil
}
func (s *Service) fail(id string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record := s.records[id]; record != nil {
		record.State = securityv1.AssessmentState_ASSESSMENT_FAILED
		record.Failure = err.Error()
		record.UpdatedAt = time.Now().UTC()
	}
}
func (s *Service) Findings(ctx context.Context, id, severity string) ([]rules.Finding, error) {
	record, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	items := append([]rules.Finding(nil), record.Result.Findings...)
	if severity != "" {
		out := items[:0]
		for _, item := range items {
			if string(item.Severity) == strings.ToUpper(severity) {
				out = append(out, item)
			}
		}
		items = out
	}
	return items, nil
}
func (s *Service) Recommendations(ctx context.Context, id string) ([]Recommendation, error) {
	record, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	byText := map[string]*Recommendation{}
	for _, finding := range record.Result.Findings {
		text := finding.Recommendation
		row := byText[text]
		if row == nil {
			row = &Recommendation{Text: text, Priority: priority(finding.Severity)}
			byText[text] = row
		}
		row.RuleIDs = append(row.RuleIDs, finding.RuleID)
	}
	out := make([]Recommendation, 0, len(byText))
	for _, row := range byText {
		sort.Strings(row.RuleIDs)
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out, nil
}

type Recommendation struct {
	Priority, Text string
	RuleIDs        []string
}

func priority(severity rules.Severity) string {
	switch severity {
	case rules.SeverityCritical:
		return "P0"
	case rules.SeverityHigh:
		return "P1"
	case rules.SeverityMedium:
		return "P2"
	default:
		return "P3"
	}
}

type scopedFacts struct {
	ResourceType string
	ResourceID   string
	Facts        rules.Facts
}

func facts(items []model.FusedConclusion) ([]scopedFacts, uint64, bool) {
	type resource struct{ typ, id string }
	winners := map[resource]map[string]model.FusedConclusion{}
	knownConfiguration := map[string]bool{}
	metadataKnown, metadataExposure := false, false
	for _, item := range items {
		if item.Status == commonv1.EvidenceStatus_UNKNOWN {
			continue
		}
		if item.PropertyKey == model.PropertyMetadataExposure {
			metadataKnown = true
			metadataExposure = metadataExposure || scalar(item) != ""
			continue
		}
		if !securityProperty(item.PropertyKey) {
			continue
		}
		for _, property := range model.SecurityConfigurationProperties {
			if item.PropertyKey == property {
				knownConfiguration[property] = true
			}
		}
		scope := resource{typ: item.ResourceType, id: item.ResourceID}
		if scope.typ == "" && scope.id == "" {
			scope = resource{typ: "ANALYSIS", id: "default"}
		}
		if winners[scope] == nil {
			winners[scope] = map[string]model.FusedConclusion{}
		}
		if old, ok := winners[scope][item.PropertyKey]; !ok || item.Confidence > old.Confidence || item.Confidence == old.Confidence && item.ID < old.ID {
			winners[scope][item.PropertyKey] = item
		}
	}
	if len(winners) == 0 {
		winners[resource{typ: "ANALYSIS", id: "default"}] = map[string]model.FusedConclusion{}
	}
	scopes := make([]scopedFacts, 0, len(winners))
	childAEAD := false
	for scope, values := range winners {
		get := func(name string) string {
			if item, ok := values[name]; ok {
				return scalar(item)
			}
			return ""
		}
		parseBool := func(name string) *bool {
			if item, ok := values[name]; ok {
				value := strings.EqualFold(scalar(item), "true") || scalar(item) == "1"
				return &value
			}
			return nil
		}
		f := rules.Facts{IKEVersion: get(model.PropertyIKEVersion), EncryptionAlgorithm: get(model.PropertyChildEncryption), IntegrityAlgorithm: get(model.PropertyChildIntegrity), DHGroup: get(model.PropertyIKEDHGroup), PFS: parseBool(model.PropertyChildPFS), ReplayProtection: parseBool(model.PropertyReplayEnabled), MetadataExposure: metadataExposure, MetadataKnown: metadataKnown}
		// Only a CHILD-SA AEAD transform can supply CHILD-SA integrity. Never
		// substitute the cipher or integrity algorithm protecting the IKE SA.
		if f.IntegrityAlgorithm == "" && isAEAD(f.EncryptionAlgorithm) {
			f.IntegrityAlgorithm = "AEAD"
			childAEAD = true
		}
		if value := get(model.PropertyChildLifetimeSeconds); value != "" {
			f.SALifetimeKnown = true
			_, _ = fmt.Sscan(value, &f.SALifetimeSeconds)
		}
		scopes = append(scopes, scopedFacts{ResourceType: scope.typ, ResourceID: scope.id, Facts: f})
	}
	if childAEAD {
		knownConfiguration[model.PropertyChildIntegrity] = true
	}
	unknown := uint64(0)
	for _, property := range model.SecurityConfigurationProperties {
		if !knownConfiguration[property] {
			unknown++
		}
	}
	sort.Slice(scopes, func(i, j int) bool {
		return scopes[i].ResourceType+"\x00"+scopes[i].ResourceID < scopes[j].ResourceType+"\x00"+scopes[j].ResourceID
	})
	return scopes, unknown, metadataExposure
}

func securityProperty(key string) bool {
	switch key {
	case model.PropertyIKEVersion, model.PropertyIKEEncryption, model.PropertyIKEIntegrity, model.PropertyIKEDHGroup,
		model.PropertyChildEncryption, model.PropertyChildIntegrity, model.PropertyChildPFS,
		model.PropertyReplayEnabled, model.PropertyChildLifetimeSeconds:
		return true
	default:
		return false
	}
}

func mergeAssessments(items []rules.Assessment) rules.Assessment {
	if len(items) == 0 {
		return rules.Assess(rules.Facts{})
	}
	out := rules.Assessment{ThreatMatrix: map[rules.Severity]int{}, RuleResults: map[string]rules.RuleResult{}}
	for _, item := range items {
		for id, result := range item.RuleResults {
			combined := out.RuleResults[id]
			combined.Weight = result.Weight
			combined.Known = combined.Known || result.Known
			combined.Failed = combined.Failed || result.Failed
			out.RuleResults[id] = combined
		}
		out.Findings = append(out.Findings, item.Findings...)
		for severity, count := range item.ThreatMatrix {
			out.ThreatMatrix[severity] += count
		}
	}
	for _, result := range out.RuleResults {
		if !result.Known {
			out.UnknownRule++
			continue
		}
		out.EvaluatedRule++
		if !result.Failed {
			out.Score += result.Weight
		}
	}
	if total := out.EvaluatedRule + out.UnknownRule; total > 0 {
		out.Coverage = out.EvaluatedRule * 100 / total
	}
	out.Grade = assessmentGrade(out.Score)
	sort.Slice(out.Findings, func(i, j int) bool {
		if out.Findings[i].Severity != out.Findings[j].Severity {
			return severityRank(out.Findings[i].Severity) > severityRank(out.Findings[j].Severity)
		}
		return out.Findings[i].ResourceType+out.Findings[i].ResourceID+out.Findings[i].RuleID < out.Findings[j].ResourceType+out.Findings[j].ResourceID+out.Findings[j].RuleID
	})
	return out
}

func assessmentGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

func severityRank(value rules.Severity) int {
	switch value {
	case rules.SeverityCritical:
		return 4
	case rules.SeverityHigh:
		return 3
	case rules.SeverityMedium:
		return 2
	default:
		return 1
	}
}

func isAEAD(algorithm string) bool {
	value := strings.ToUpper(strings.TrimSpace(algorithm))
	if strings.Contains(value, "GCM") || strings.Contains(value, "CCM") || strings.Contains(value, "CHACHA20_POLY1305") {
		return true
	}
	switch value {
	case "ENCR_14", "ENCR_15", "ENCR_16", "ENCR_18", "ENCR_19", "ENCR_20", "ENCR_28":
		return true
	default:
		return false
	}
}
func scalar(item model.FusedConclusion) string {
	if item.Value == nil {
		return ""
	}
	if value := item.Value.GetStringValue(); value != "" {
		return value
	}
	if item.Value.GetBoolValue() {
		return "true"
	}
	if number := item.Value.GetNumberValue(); number != 0 {
		return fmt.Sprint(number)
	}
	return ""
}
