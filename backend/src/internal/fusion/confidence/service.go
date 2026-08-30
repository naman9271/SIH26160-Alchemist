// Package confidence implements deterministic, policy-driven confidence.
package confidence

import (
	"context"
	"math"
	"strings"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/decision"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
)

type Store interface {
	Get(context.Context, string) (model.Run, error)
}

type CalculateRequest struct {
	PolicyID           string
	PropertyKey        string
	Candidates         []model.EvidenceItem
	WinningEvidenceID  string
	CorrelationQuality *float64
}

type Result struct {
	Confidence float64
	Band       model.ConfidenceBand
	Breakdown  model.ConfidenceBreakdown
}

type GetBreakdownRequest struct {
	FusionRunID  string
	ConclusionID string
}

type CalibrateMLRequest struct {
	Probability  float64
	ModelName    string
	ModelVersion string
	IsUnknown    bool
}

type CalibratedConfidence struct {
	Confidence float64
	Band       model.ConfidenceBand
	Status     commonv1.EvidenceStatus
}

type Service struct {
	store    Store
	policies policy.Provider
	now      func() time.Time
}

func New(store Store, policies policy.Provider) *Service {
	return &Service{store: store, policies: policies, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) Ready(ctx context.Context) (bool, string) {
	if err := model.ContextError(ctx); err != nil {
		return false, err.Error()
	}
	if s == nil || s.policies == nil {
		return false, "confidence policy provider is not configured"
	}
	return s.policies.Ready(ctx)
}

func (s *Service) Calculate(ctx context.Context, request CalculateRequest) (Result, error) {
	if err := model.ContextError(ctx); err != nil {
		return Result{}, err
	}
	if s == nil || s.policies == nil {
		return Result{}, model.NewError(model.ErrorInternal, "confidence policy provider is not configured")
	}
	if len(request.Candidates) == 0 || strings.TrimSpace(request.WinningEvidenceID) == "" {
		return Result{}, model.NewError(model.ErrorInvalidArgument, "candidate evidence and winning_evidence_id are required")
	}
	definition, err := s.policies.Resolve(ctx, strings.TrimSpace(request.PolicyID))
	if err != nil {
		return Result{}, err
	}
	var winner *model.EvidenceItem
	for index := range request.Candidates {
		if request.Candidates[index].ID == request.WinningEvidenceID {
			copy := request.Candidates[index].Clone()
			winner = &copy
			break
		}
	}
	if winner == nil {
		return Result{}, model.NewError(model.ErrorInvalidArgument, "winning evidence is not in the candidate set")
	}
	correlationQuality := 1.0
	if request.CorrelationQuality != nil {
		correlationQuality = *request.CorrelationQuality
		if invalidUnit(correlationQuality) {
			return Result{}, model.NewError(model.ErrorInvalidArgument, "correlation_quality must be within [0,1]")
		}
	}
	sourceTrust, configured := definition.SourceTrust[winner.Source]
	if !configured {
		sourceTrust = .5
	}
	statusTrust := statusTrust(winner.Status)
	agreement := agreement(request.Candidates, *winner)
	freshnessWindow := definition.Rule(request.PropertyKey).FreshnessWindow
	if freshnessWindow <= 0 {
		freshnessWindow = definition.FreshnessWindow
	}
	if freshnessWindow <= 0 {
		freshnessWindow = 24 * time.Hour
	}
	freshness := freshnessScore(winner.ObservedAt, s.now(), freshnessWindow)
	common := .30*sourceTrust + .25*statusTrust + .20*agreement + .15*freshness + .10*correlationQuality
	common = clamp(common)
	var modelConfidence *float64
	final := common * winner.Confidence
	if isML(winner.Source) {
		value := winner.Confidence
		modelConfidence = &value
		final = math.Min(value, common)
	}
	if winner.Status == commonv1.EvidenceStatus_UNKNOWN {
		final = math.Min(final, winner.Confidence)
	}
	final = clamp(final)
	band := Band(final)
	breakdown := model.ConfidenceBreakdown{
		SourceTrust: sourceTrust, StatusTrust: statusTrust, Agreement: agreement, Freshness: freshness,
		CorrelationQuality: correlationQuality, ModelConfidence: modelConfidence, FinalConfidence: final, Band: band,
	}
	return Result{Confidence: final, Band: band, Breakdown: breakdown}, nil
}

func (s *Service) GetBreakdown(ctx context.Context, request GetBreakdownRequest) (model.ConfidenceBreakdown, error) {
	if err := model.ContextError(ctx); err != nil {
		return model.ConfidenceBreakdown{}, err
	}
	if s == nil || s.store == nil {
		return model.ConfidenceBreakdown{}, model.NewError(model.ErrorInternal, "Fusion store is not configured")
	}
	if err := model.ValidateRunID(request.FusionRunID); err != nil {
		return model.ConfidenceBreakdown{}, err
	}
	if err := model.ValidateConclusionID(request.ConclusionID); err != nil {
		return model.ConfidenceBreakdown{}, err
	}
	run, err := s.store.Get(ctx, strings.TrimSpace(request.FusionRunID))
	if err != nil {
		return model.ConfidenceBreakdown{}, err
	}
	conclusion, exists := run.Conclusions[strings.TrimSpace(request.ConclusionID)]
	if !exists {
		return model.ConfidenceBreakdown{}, model.NewError(model.ErrorNotFound, "fused conclusion was not found")
	}
	return conclusion.Breakdown.Clone(), nil
}

func (s *Service) CalibrateML(ctx context.Context, request CalibrateMLRequest) (CalibratedConfidence, error) {
	if err := model.ContextError(ctx); err != nil {
		return CalibratedConfidence{}, err
	}
	if invalidUnit(request.Probability) {
		return CalibratedConfidence{}, model.NewError(model.ErrorInvalidArgument, "ML probability must be within [0,1]")
	}
	if strings.TrimSpace(request.ModelName) == "" || strings.TrimSpace(request.ModelVersion) == "" {
		return CalibratedConfidence{}, model.NewError(model.ErrorInvalidArgument, "model_name and model_version are required")
	}
	status := commonv1.EvidenceStatus_INFERRED
	if request.IsUnknown {
		status = commonv1.EvidenceStatus_UNKNOWN
	}
	return CalibratedConfidence{Confidence: request.Probability, Band: Band(request.Probability), Status: status}, nil
}

func Band(value float64) model.ConfidenceBand {
	switch {
	case value < .25:
		return model.ConfidenceVeryLow
	case value < .50:
		return model.ConfidenceLow
	case value < .75:
		return model.ConfidenceMedium
	case value < .90:
		return model.ConfidenceHigh
	default:
		return model.ConfidenceVeryHigh
	}
}

func statusTrust(status commonv1.EvidenceStatus) float64 {
	switch status {
	case commonv1.EvidenceStatus_VERIFIED_GATEWAY:
		return 1
	case commonv1.EvidenceStatus_OBSERVED:
		return .95
	case commonv1.EvidenceStatus_DERIVED:
		return .80
	case commonv1.EvidenceStatus_INFERRED:
		return .70
	default:
		return .25
	}
}

func agreement(candidates []model.EvidenceItem, winner model.EvidenceItem) float64 {
	known, matching := 0, 0
	winnerValue := decision.CanonicalValue(winner)
	for _, candidate := range candidates {
		if candidate.Status == commonv1.EvidenceStatus_UNKNOWN {
			continue
		}
		known++
		if decision.CanonicalValue(candidate) == winnerValue {
			matching++
		}
	}
	if known == 0 {
		return 0
	}
	return float64(matching) / float64(known)
}

func freshnessScore(observed, now time.Time, window time.Duration) float64 {
	if observed.IsZero() {
		return 0
	}
	age := now.Sub(observed)
	if age <= 0 {
		return 1
	}
	if age >= window {
		return 0
	}
	return 1 - float64(age)/float64(window)
}

func isML(source model.Source) bool {
	return source == model.SourceMLClassifier || source == model.SourceMLAnomaly || source == model.SourceSHAP
}

func invalidUnit(value float64) bool {
	return math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1
}
func clamp(value float64) float64 { return math.Max(0, math.Min(1, value)) }
