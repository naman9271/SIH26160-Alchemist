package analysis

import (
	"context"
	"fmt"
	"sort"
	"strings"

	analysisv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/analysis"
	fusionv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/fusion"
	mlv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/ml"
	riskv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/risk"
	coresecurity "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/security"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	rules "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/security"
)

type FusionReadModel interface {
	Summary(context.Context, string) (*fusionv1.FusionSummary, error)
	FusedConclusions(context.Context, string) ([]model.FusedConclusion, error)
}
type SecurityReadModel interface {
	LatestForAnalysis(context.Context, string) (coresecurity.Record, error)
}
type RiskReadModel interface {
	Score(context.Context, string) (*riskv1.SecurityScore, error)
}
type MLReadModel interface {
	LatestForAnalysis(context.Context, string) (string, []*mlv1.TrafficPrediction, map[string]*mlv1.PredictionExplanation, error)
}
type ReadModels struct {
	Fusion   FusionReadModel
	Security SecurityReadModel
	Risk     RiskReadModel
	ML       MLReadModel
}

func (s *Service) SetReadModels(models ReadModels) { s.mu.Lock(); s.views = models; s.mu.Unlock() }

func (s *Service) ProgressDetails(ctx context.Context, id string) (*analysisv1.AnalysisProgress, error) {
	record, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	result := &analysisv1.AnalysisProgress{AnalysisId: id, Stage: record.Stage, ViciState: analysisv1.AvailabilityState_UNAVAILABLE, XfrmState: analysisv1.AvailabilityState_UNAVAILABLE}
	if source, sourceErr := s.source.Get(ctx, record.SourceID); sourceErr == nil {
		result.PacketsProcessed = source.Counters.PacketsTotal
		result.BytesProcessed = source.Counters.BytesTotal
		if source.SessionID != "" {
			result.SessionsFound = 1
		}
	}
	models := s.readModels()
	if models.Fusion != nil {
		if summary, summaryErr := models.Fusion.Summary(ctx, id); summaryErr == nil {
			result.EvidenceCount = summary.GetEvidenceCount()
			result.ViciState = sourceAvailability(summary, "vici")
			result.XfrmState = sourceAvailability(summary, "xfrm")
		}
		if conclusions, conclusionErr := models.Fusion.FusedConclusions(ctx, id); conclusionErr == nil {
			flows, sessions, sas := resourceCounts(conclusions)
			result.FlowsProcessed = flows
			if sessions > result.SessionsFound {
				result.SessionsFound = sessions
			}
			result.SasFound = sas
		}
	}
	if models.Security != nil {
		if assessment, assessmentErr := models.Security.LatestForAnalysis(ctx, id); assessmentErr == nil {
			result.FindingsGenerated = uint64(len(assessment.Result.Findings))
		}
	}
	if models.ML != nil {
		if _, predictions, _, mlErr := models.ML.LatestForAnalysis(ctx, id); mlErr == nil {
			result.MlPredictions = uint64(len(predictions))
		}
	}
	return result, nil
}

func (s *Service) SummaryDetails(ctx context.Context, id string) (*analysisv1.AnalysisSummary, error) {
	record, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	result := &analysisv1.AnalysisSummary{AnalysisId: id, Mode: record.Mode, Protocol: &analysisv1.ProtocolSummary{}, Traffic: &analysisv1.TrafficSummary{State: analysisv1.AvailabilityState_UNAVAILABLE}, Security: &analysisv1.SecuritySummary{State: analysisv1.AvailabilityState_UNAVAILABLE}, FindingCounts: &analysisv1.FindingCounts{}, FusionState: analysisv1.AvailabilityState_UNAVAILABLE, ViciState: analysisv1.AvailabilityState_UNAVAILABLE, XfrmState: analysisv1.AvailabilityState_UNAVAILABLE}
	if source, sourceErr := s.source.Get(ctx, record.SourceID); sourceErr == nil {
		result.PacketCount = source.Counters.PacketsTotal
		result.ByteCount = source.Counters.BytesTotal
		if source.SessionID != "" {
			result.SessionCount = 1
		}
	}
	models := s.readModels()
	var conclusions []model.FusedConclusion
	if models.Fusion != nil {
		if summary, summaryErr := models.Fusion.Summary(ctx, id); summaryErr == nil {
			result.EvidenceCount = summary.GetEvidenceCount()
			result.FusionState = analysisv1.AvailabilityState_AVAILABLE
			result.ViciState = sourceAvailability(summary, "vici")
			result.XfrmState = sourceAvailability(summary, "xfrm")
		}
		conclusions, _ = models.Fusion.FusedConclusions(ctx, id)
	}
	properties := bestConclusions(conclusions)
	result.Protocol.IkeVersion = conclusionScalar(properties["ike.version"])
	result.Protocol.DataProtocol = conclusionScalar(properties["child.protocol"])
	result.Protocol.VpnMode = conclusionScalar(properties["child.mode"])
	protocols := map[string]struct{}{}
	if result.Protocol.IkeVersion != "" {
		protocols[result.Protocol.IkeVersion] = struct{}{}
	}
	if result.Protocol.DataProtocol != "" {
		protocols[result.Protocol.DataProtocol] = struct{}{}
	}
	result.Protocols = sortedKeys(protocols)
	result.IpsecDetected = len(result.Protocols) > 0
	classes := map[string]struct{}{}
	for _, item := range conclusions {
		if item.PropertyKey == "traffic.class" {
			if value := conclusionScalar(item); value != "" {
				classes[value] = struct{}{}
			}
		}
	}
	result.TrafficClasses = sortedKeys(classes)
	if len(result.TrafficClasses) > 0 {
		result.Traffic.TrafficClass = result.TrafficClasses[0]
		result.Traffic.State = analysisv1.AvailabilityState_AVAILABLE
		if item, ok := properties["traffic.class"]; ok {
			result.Traffic.Confidence = item.Confidence
		}
	}
	flows, sessions, sas := resourceCounts(conclusions)
	result.FlowCount = flows
	if sessions > result.SessionCount {
		result.SessionCount = sessions
	}
	result.SaCount = sas
	if models.Security != nil {
		if assessment, assessmentErr := models.Security.LatestForAnalysis(ctx, id); assessmentErr == nil {
			result.Security.State = analysisv1.AvailabilityState_AVAILABLE
			countFindings(result.FindingCounts, assessment.Result.Findings)
			if models.Risk != nil {
				if score, scoreErr := models.Risk.Score(ctx, assessment.ID); scoreErr == nil {
					result.Security.Score = score.GetScore()
					result.Security.RiskLevel = score.GetRiskLevel()
				}
			}
		}
	}
	if models.ML != nil {
		if _, predictions, _, mlErr := models.ML.LatestForAnalysis(ctx, id); mlErr == nil && len(predictions) > 0 {
			best := predictions[0]
			for _, candidate := range predictions[1:] {
				if candidate.GetConfidence() > best.GetConfidence() {
					best = candidate
				}
			}
			result.MlResult = fmt.Sprintf("%s (%.2f)", best.GetTrafficClass(), best.GetConfidence())
		}
	}
	return result, nil
}

func (s *Service) readModels() ReadModels { s.mu.RLock(); defer s.mu.RUnlock(); return s.views }
func sourceAvailability(summary *fusionv1.FusionSummary, name string) analysisv1.AvailabilityState {
	for _, source := range summary.GetUnavailableSources() {
		if source == name {
			return analysisv1.AvailabilityState_UNAVAILABLE
		}
	}
	return analysisv1.AvailabilityState_AVAILABLE
}
func resourceCounts(items []model.FusedConclusion) (uint64, uint64, uint64) {
	flows, sessions, sas := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for _, item := range items {
		key := item.ResourceType + "\x00" + item.ResourceID
		switch item.ResourceType {
		case "FLOW":
			flows[key] = struct{}{}
		case "VPN_SESSION":
			sessions[key] = struct{}{}
		case "IKE_SA", "VICI_IKE_SA", "CHILD_SA", "VICI_CHILD_SA", "XFRM_STATE", "ESP_STREAM", "AH_STREAM":
			sas[key] = struct{}{}
		}
	}
	return uint64(len(flows)), uint64(len(sessions)), uint64(len(sas))
}
func bestConclusions(items []model.FusedConclusion) map[string]model.FusedConclusion {
	result := map[string]model.FusedConclusion{}
	for _, item := range items {
		old, ok := result[item.PropertyKey]
		if !ok || item.Confidence > old.Confidence || item.Confidence == old.Confidence && item.ID < old.ID {
			result[item.PropertyKey] = item
		}
	}
	return result
}
func conclusionScalar(item model.FusedConclusion) string {
	if item.Value == nil {
		return ""
	}
	return fmt.Sprint(item.Value.AsInterface())
}
func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
func countFindings(out *analysisv1.FindingCounts, items []rules.Finding) {
	for _, item := range items {
		switch strings.ToUpper(string(item.Severity)) {
		case "CRITICAL":
			out.Critical++
		case "HIGH":
			out.High++
		case "MEDIUM":
			out.Medium++
		default:
			out.Low++
		}
	}
}
