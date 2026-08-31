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

// EvidenceProvider returns only normalized evidence associated with an analysis.
type EvidenceProvider interface {
	EvidenceItems(context.Context, string) ([]model.EvidenceItem, error)
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
	mu       sync.RWMutex
	evidence EvidenceProvider
	records  map[string]*Record
}

func New(evidence EvidenceProvider) *Service {
	return &Service{evidence: evidence, records: map[string]*Record{}}
}

func (s *Service) Run(ctx context.Context, analysisID, policyID string) (Record, error) {
	if s == nil || s.evidence == nil {
		return Record{}, shared.NewError(shared.Internal, "", "security evidence provider is not configured")
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
	items, err := s.evidence.EvidenceItems(ctx, record.AnalysisID)
	if err != nil {
		s.fail(id, err)
		return s.Get(ctx, id)
	}
	facts, unknown, metadata := facts(items)
	result := rules.Assess(facts)
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
func facts(items []model.EvidenceItem) (rules.Facts, uint64, bool) {
	latest := map[string]model.EvidenceItem{}
	for _, item := range items {
		if item.Status == commonv1.EvidenceStatus_UNKNOWN {
			continue
		}
		if old, ok := latest[item.PropertyKey]; !ok || item.ObservedAt.After(old.ObservedAt) {
			latest[item.PropertyKey] = item
		}
	}
	get := func(names ...string) string {
		for _, name := range names {
			if item, ok := latest[name]; ok {
				return scalar(item)
			}
		}
		return ""
	}
	parseBool := func(names ...string) *bool {
		for _, name := range names {
			if item, ok := latest[name]; ok {
				value := strings.EqualFold(scalar(item), "true") || scalar(item) == "1"
				return &value
			}
		}
		return nil
	}
	facts := rules.Facts{IKEVersion: get("ike.version"), EncryptionAlgorithm: get("child.encryption_algorithm", "ike.encryption"), IntegrityAlgorithm: get("child.integrity_algorithm", "ike.integrity"), DHGroup: get("ike.dh_group"), PFS: parseBool("child.pfs"), ReplayProtection: parseBool("replay.enabled"), MetadataExposure: get("metadata.exposure") != ""}
	if value := get("child.lifetime_seconds"); value != "" {
		var life uint64
		_, _ = fmt.Sscan(value, &life)
		facts.SALifetimeSeconds = life
	}
	unknown := uint64(0)
	for _, property := range []string{"ike.version", "child.encryption_algorithm", "child.integrity_algorithm", "ike.dh_group", "child.pfs", "replay.enabled"} {
		if _, ok := latest[property]; !ok {
			unknown++
		}
	}
	return facts, unknown, facts.MetadataExposure
}
func scalar(item model.EvidenceItem) string {
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
