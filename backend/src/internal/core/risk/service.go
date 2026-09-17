// Package risk derives an auditable score view from the existing deterministic
// security assessment. It deliberately does not re-run or replace security rules.
package risk

import (
	"context"
	"strings"

	riskv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/risk"
	coresecurity "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/security"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	rules "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/security"
)

type AssessmentProvider interface {
	Get(context.Context, string) (coresecurity.Record, error)
}
type Service struct{ assessments AssessmentProvider }

func New(assessments AssessmentProvider) *Service { return &Service{assessments: assessments} }
func (s *Service) Score(ctx context.Context, assessmentID string) (*riskv1.SecurityScore, error) {
	record, err := s.record(ctx, assessmentID)
	if err != nil {
		return nil, err
	}
	coverage := float64(record.Result.CoveragePercent)/100
	riskLevel := level(record.Result.Score)
	if !record.Result.ScoreAvailable || (record.UnknownEvidence > 0 && (riskLevel == "LOW" || riskLevel == "MODERATE")) { riskLevel = "INDETERMINATE" }
	return &riskv1.SecurityScore{AssessmentId: record.ID, Score: uint32(record.Result.Score), RiskLevel: riskLevel, Confidence: coverage, UnknownEvidenceCount: record.UnknownEvidence}, nil
}
func (s *Service) Breakdown(ctx context.Context, assessmentID string) (*riskv1.RiskBreakdown, error) {
	record, err := s.record(ctx, assessmentID)
	if err != nil {
		return nil, err
	}
	deductions := map[string]uint32{"cryptography": 0, "authentication": 0, "key_exchange": 0, "pfs": 0, "replay": 0, "lifecycle": 0, "metadata": 0}
	for _, finding := range record.Result.Findings {
		category := category(finding)
		deductions[category] += uint32(penalty(finding.Severity))
	}
	makeCategory := func(name string, max uint32) *riskv1.RiskCategory {
		known := false
		for _, control := range record.Result.Controls {
			if control.State != "NOT_EVALUATED" && category(rules.Finding{EvidenceProperties:[]string{control.Property}})==name { known=true }
		}
		if !known { return &riskv1.RiskCategory{} }
		loss := deductions[name]
		if loss > max {
			loss = max
		}
		return &riskv1.RiskCategory{Score: max - loss, Maximum: max}
	}
	penaltyValue := float64(record.UnknownEvidence) * .05
	if penaltyValue > .5 {
		penaltyValue = .5
	}
	return &riskv1.RiskBreakdown{Cryptography: makeCategory("cryptography", 25), Authentication: makeCategory("authentication", 15), KeyExchange: makeCategory("key_exchange", 15), Pfs: makeCategory("pfs", 10), Replay: makeCategory("replay", 7), Lifecycle: makeCategory("lifecycle", 8), Metadata: makeCategory("metadata", 5), UnknownEvidenceCount: record.UnknownEvidence, ConfidencePenalty: penaltyValue}, nil
}
func (s *Service) Overrides(ctx context.Context, assessmentID string) (*riskv1.CriticalOverridesResponse, error) {
	record, err := s.record(ctx, assessmentID)
	if err != nil {
		return nil, err
	}
	out := &riskv1.CriticalOverridesResponse{}
	for _, finding := range record.Result.Findings {
		if finding.Severity == rules.SeverityCritical {
			out.Overrides = append(out.Overrides, &riskv1.CriticalOverride{RuleId: finding.RuleID, ScoreCap: 40, Reason: "Critical deterministic security finding"})
		}
	}
	return out, nil
}
func (s *Service) record(ctx context.Context, id string) (coresecurity.Record, error) {
	if s == nil || s.assessments == nil {
		return coresecurity.Record{}, shared.NewError(shared.Internal, "", "security assessment provider is not configured")
	}
	if strings.TrimSpace(id) == "" {
		return coresecurity.Record{}, shared.NewError(shared.InvalidArgument, "", "assessment_id is required")
	}
	return s.assessments.Get(ctx, id)
}
func level(score int) string {
	switch {
	case score >= 90:
		return "LOW"
	case score >= 70:
		return "MODERATE"
	case score >= 50:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}
func penalty(severity rules.Severity) int {
	switch severity {
	case rules.SeverityCritical:
		return 25
	case rules.SeverityHigh:
		return 15
	case rules.SeverityMedium:
		return 8
	default:
		return 3
	}
}
func category(f rules.Finding) string {
	for _, property := range f.EvidenceProperties {
		switch {
		case strings.Contains(property, "encryption") || strings.Contains(property, "integrity"):
			return "cryptography"
		case strings.Contains(property, "dh_group") || strings.Contains(property, "ike.version"):
			return "key_exchange"
		case strings.Contains(property, "pfs"):
			return "pfs"
		case strings.Contains(property, "replay"):
			return "replay"
		case strings.Contains(property, "lifetime"):
			return "lifecycle"
		case strings.Contains(property, "metadata"):
			return "metadata"
		}
	}
	return "authentication"
}
