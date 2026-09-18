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
	// This field is an evidence-coverage indicator, not statistical model
	// confidence. Missing evidence therefore reduces it all the way to zero.
	confidence := float64(record.Result.Coverage) / 100
	return &riskv1.SecurityScore{AssessmentId: record.ID, Score: uint32(record.Result.Score), RiskLevel: level(record.Result.Score), Confidence: confidence, UnknownEvidenceCount: record.UnknownEvidence}, nil
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
			category.Maximum += uint32(result.Weight)
			if result.Known && !result.Failed {
				category.Score += uint32(result.Weight)
			}
		}
		return category
	}
	penaltyValue := 1 - float64(record.Result.Coverage)/100
	return &riskv1.RiskBreakdown{
		Cryptography:         makeCategory("IPSEC_CIPHER_001"),
		Authentication:       makeCategory("IPSEC_INTEGRITY_001"),
		KeyExchange:          makeCategory("IPSEC_IKE_001", "IPSEC_DH_001"),
		Pfs:                  makeCategory("IPSEC_PFS_001"),
		Replay:               makeCategory("IPSEC_REPLAY_001"),
		Lifecycle:            makeCategory("IPSEC_LIFETIME_001"),
		Metadata:             makeCategory("IPSEC_METADATA_001"),
		UnknownEvidenceCount: record.UnknownEvidence,
		ConfidencePenalty:    penaltyValue,
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
