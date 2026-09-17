// Package security adapts fused evidence to the existing deterministic rule engine.
package security

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"strconv"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/evidence"

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
	facts, unknown, metadata := facts(items)
	result := rules.Assess(facts)
	unknown = uint64(len(result.Controls) - result.EvaluatedRule)
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
func facts(items []model.FusedConclusion) (rules.Facts, uint64, bool) {
	winners := map[string]model.FusedConclusion{}
	conflicting := map[string]bool{}
	for _, item := range items {
		item.PropertyKey = evidence.Canonical(item.PropertyKey)
		if item.Status != commonv1.EvidenceStatus_OBSERVED && item.Status != commonv1.EvidenceStatus_VERIFIED_GATEWAY && item.Status != commonv1.EvidenceStatus_DERIVED {
			continue
		}
		if old, ok := winners[item.PropertyKey]; ok && scalar(old) != scalar(item) { conflicting[item.PropertyKey] = true }
		if old, ok := winners[item.PropertyKey]; !ok || item.Confidence > old.Confidence || item.Confidence == old.Confidence && item.ID < old.ID {
			winners[item.PropertyKey] = item
		}
	}
	// Until per-SA scoring is requested, never combine incompatible SA facts into
	// one seemingly verified configuration. The affected control stays unknown.
	for key := range conflicting { delete(winners,key) }
	get := func(names ...string) string {
		for _, name := range names {
			if item, ok := winners[name]; ok {
				return scalar(item)
			}
		}
		return ""
	}
	parseBool := func(names ...string) *bool {
		for _, name := range names {
			if item, ok := winners[name]; ok {
				value, err := strconv.ParseBool(scalar(item))
				if err == nil { return &value }
			}
		}
		return nil
	}
	facts := rules.Facts{IKEVersion: get("ike.version"), EncryptionAlgorithm: get(evidence.ChildEncryption), IntegrityAlgorithm: get(evidence.ChildIntegrity), DHGroup: get("ike.dh_group"), PFS: parseBool(evidence.ChildPFS), ReplayProtection: parseBool(evidence.ReplayEnabled), MetadataExposure: get("metadata.exposure") != ""}
	// AEAD transforms authenticate as well as encrypt, so a separate integrity
	// transform is neither negotiated nor required. Preserve that fact for the
	// rule engine and evidence-coverage calculation.
	if facts.IntegrityAlgorithm == "" && isAEAD(facts.EncryptionAlgorithm) {
		facts.IntegrityAlgorithm = "AEAD"
	}
	if value := get("child.lifetime_seconds"); value != "" {
		var life uint64
		_, _ = fmt.Sscan(value, &life)
		facts.SALifetimeSeconds = life
	}
	unknown := uint64(0)
	for _, available := range []bool{
		facts.IKEVersion != "",
		facts.EncryptionAlgorithm != "",
		facts.IntegrityAlgorithm != "",
		facts.DHGroup != "",
		facts.PFS != nil,
		facts.ReplayProtection != nil,
	} {
		if !available {
			unknown++
		}
	}
	return facts, unknown, facts.MetadataExposure
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
	return fmt.Sprint(item.Value.AsInterface())
}
