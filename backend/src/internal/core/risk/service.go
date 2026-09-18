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
	result := record.Result
	out := &riskv1.SecurityScore{AssessmentId: record.ID, ScoreAvailable: result.ScoreAvailable, CoverageAvailable: result.CoverageAvailable, EvidenceCoverage: result.Coverage, Provisional: result.Provisional, CriticalScoreCapApplied: result.ScoreCapped, UnknownEvidenceCount: record.UnknownEvidence}
	if result.BoundsAvailable {
		out.SecurityLowerBound, out.SecurityUpperBound = result.SecurityLowerBound, result.SecurityUpperBound
		out.RiskLowerBound, out.RiskUpperBound = 100-result.SecurityUpperBound, 100-result.SecurityLowerBound
	}
	if result.ScoreAvailable {
		out.ObservedSecurityScore = result.Score
		out.Score = uint32(result.Score + .5) // legacy clients; score_available is authoritative.
		out.RiskScore = 100 - result.Score
		out.RiskLevel = level(out.RiskScore)
	} else {
		out.RiskLevel = "UNAVAILABLE"
	}
	return out, nil
}
func (s *Service) Breakdown(ctx context.Context, assessmentID string) (*riskv1.RiskBreakdown, error) {
	record, err := s.record(ctx, assessmentID)
	if err != nil {
		return nil, err
	}
	makeCategory := func(ruleIDs ...string) *riskv1.RiskCategory {
		category := &riskv1.RiskCategory{}
		for _, id := range ruleIDs {
			result, ok := record.Result.RuleResults[id]
			if !ok {
				continue
			}
			category.Maximum += result.Weight
			if result.Known && !result.Failed {
				category.Score += result.Weight
			}
		}
		return category
	}
	return &riskv1.RiskBreakdown{
		Cryptography:         makeCategory("SIH_IKE_SUITE_001", "SIH_CHILD_SUITE_001", "SIH_IKE_POLICY_001", "SIH_CHILD_POLICY_001"),
		Authentication:       makeCategory("SIH_AUTH_001"),
		KeyExchange:          makeCategory("SIH_IKE_VERSION_001", "SIH_DH_001"),
		Pfs:                  makeCategory("SIH_PFS_CONFIG_001", "SIH_PFS_EXCHANGE_001"),
		Replay:               makeCategory("SIH_REPLAY_001"),
		Lifecycle:            makeCategory("SIH_IKE_LIFETIME_001", "SIH_CHILD_LIFETIME_001"),
		Metadata:             makeCategory("SIH_METADATA_001"),
		SaConfiguration:      makeCategory("SIH_SA_PARAMETERS_001"),
		UnknownEvidenceCount: record.UnknownEvidence,
		EvidenceCoverage:     record.Result.Coverage,
	}, nil
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
func level(score float64) string {
	switch {
	case score <= 10:
		return "LOW"
	case score <= 30:
		return "MODERATE"
	case score <= 50:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}
