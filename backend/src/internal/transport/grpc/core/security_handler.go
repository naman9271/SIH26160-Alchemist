package core

import (
	"context"
	"fmt"

	securityv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/security"
	coresecurity "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/security"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	rules "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/security"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type SecurityHandler struct {
	securityv1.UnimplementedSecurityAssessmentServiceServer
	service *coresecurity.Service
}

func NewSecurityHandler(service *coresecurity.Service) *SecurityHandler {
	return &SecurityHandler{service: service}
}
func (h *SecurityHandler) valid() error {
	if h == nil || h.service == nil {
		return shared.NewError(shared.Internal, "", "security assessment service is not configured")
	}
	return nil
}
func (h *SecurityHandler) Run(ctx context.Context, r *securityv1.RunSecurityAssessmentRequest) (*securityv1.RunSecurityAssessmentResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Run(ctx, r.GetAnalysisId(), r.GetPolicyId())
	return &securityv1.RunSecurityAssessmentResponse{AssessmentId: v.ID, State: v.State}, shared.ToGRPC(e)
}
func (h *SecurityHandler) Get(ctx context.Context, r *securityv1.GetSecurityAssessmentRequest) (*securityv1.SecurityAssessment, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Get(ctx, r.GetAssessmentId())
	return assessment(v), shared.ToGRPC(e)
}
func (h *SecurityHandler) ListFindings(ctx context.Context, r *securityv1.ListFindingsRequest) (*securityv1.ListFindingsResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Findings(ctx, r.GetAssessmentId(), r.GetSeverity())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	if r.GetPageSize() > 0 && r.GetPageSize() < uint32(len(v)) {
		v = v[:r.GetPageSize()]
	}
	out := make([]*securityv1.SecurityFinding, 0, len(v))
	for i, f := range v {
		out = append(out, finding(r.GetAssessmentId(), i, f))
	}
	return &securityv1.ListFindingsResponse{Findings: out}, nil
}
func (h *SecurityHandler) GetFinding(ctx context.Context, r *securityv1.GetFindingRequest) (*securityv1.SecurityFinding, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	items, e := h.service.Findings(ctx, r.GetAssessmentId(), "")
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	for i, f := range items {
		if finding(r.GetAssessmentId(), i, f).GetFindingId() == r.GetFindingId() {
			return finding(r.GetAssessmentId(), i, f), nil
		}
	}
	return nil, shared.ToGRPC(shared.NewError(shared.NotFound, "", "security finding was not found"))
}
func (h *SecurityHandler) GetThreatMatrix(ctx context.Context, r *securityv1.GetThreatMatrixRequest) (*securityv1.ThreatMatrix, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	record, e := h.service.Get(ctx, r.GetAssessmentId())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	out := &securityv1.ThreatMatrix{SeverityCounts: map[string]uint64{}}
	for i, f := range record.Result.Findings {
		out.SeverityCounts[string(f.Severity)]++
		out.Findings = append(out.Findings, finding(record.ID, i, f))
	}
	return out, nil
}
func (h *SecurityHandler) ListRecommendations(ctx context.Context, r *securityv1.ListRecommendationsRequest) (*securityv1.ListRecommendationsResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	items, e := h.service.Recommendations(ctx, r.GetAssessmentId())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	out := &securityv1.ListRecommendationsResponse{}
	for _, item := range items {
		out.Recommendations = append(out.Recommendations, &securityv1.Recommendation{Priority: item.Priority, Text: item.Text, RuleIds: item.RuleIDs})
	}
	return out, nil
}
func (h *SecurityHandler) GetCompliance(ctx context.Context, r *securityv1.GetComplianceRequest) (*securityv1.ComplianceSummary, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Get(ctx, r.GetAssessmentId())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	return &securityv1.ComplianceSummary{PolicyId: v.PolicyID, Label: v.Result.PolicyLabel, PolicyReference: v.Result.PolicyReference, RulesEvaluated: uint64(v.Result.EvaluatedRule), RulesFailed: uint64(len(v.Result.Findings)), RulesUnknown: uint64(v.Result.UnknownRule), RulesNotApplicable: uint64(v.Result.NotApplicableRule)}, nil
}
func (h *SecurityHandler) GetMetadataExposure(ctx context.Context, r *securityv1.GetMetadataExposureRequest) (*securityv1.MetadataExposureAssessment, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Get(ctx, r.GetAssessmentId())
	if e != nil {
		return nil, shared.ToGRPC(e)
	}
	status := "UNAVAILABLE"
	explanation := "No deterministic metadata-exposure evidence is available"
	if v.MetadataExposure {
		status = "OBSERVED"
		explanation = "Outer endpoints, timing, direction, and traffic volume remain observable"
	}
	return &securityv1.MetadataExposureAssessment{Observable: v.MetadataExposure, Status: status, Explanation: explanation}, nil
}
func (h *SecurityHandler) Reevaluate(ctx context.Context, r *securityv1.ReevaluateSecurityRequest) (*securityv1.ReevaluateSecurityResponse, error) {
	if e := h.valid(); e != nil {
		return nil, shared.ToGRPC(e)
	}
	v, e := h.service.Reevaluate(ctx, r.GetAssessmentId(), r.GetPolicyId())
	return &securityv1.ReevaluateSecurityResponse{AssessmentId: v.ID, State: v.State}, shared.ToGRPC(e)
}
func assessment(v coresecurity.Record) *securityv1.SecurityAssessment {
	out := &securityv1.SecurityAssessment{AssessmentId: v.ID, AnalysisId: v.AnalysisID, PolicyId: v.PolicyID, PolicyLabel: v.Result.PolicyLabel, PolicyReference: v.Result.PolicyReference, State: v.State, Grade: v.Result.Grade, EvaluatedAt: timestamppb.New(v.UpdatedAt), FailureReason: v.Failure, ObservedSecurityScore: v.Result.Score, ScoreAvailable: v.Result.ScoreAvailable, EvidenceCoverage: v.Result.Coverage, CoverageAvailable: v.Result.CoverageAvailable, SecurityLowerBound: v.Result.SecurityLowerBound, SecurityUpperBound: v.Result.SecurityUpperBound, Provisional: v.Result.Provisional, CriticalScoreCapApplied: v.Result.ScoreCapped}
	if v.Result.ScoreAvailable {
		out.Score = uint32(v.Result.Score + .5)
	}
	for i, f := range v.Result.Findings {
		out.Findings = append(out.Findings, finding(v.ID, i, f))
	}
	for _, control := range v.Result.Controls {
		out.Controls = append(out.Controls, controlResult(control))
	}
	for _, item := range v.PerSAAssessments {
		out.PerSaScores = append(out.PerSaScores, &securityv1.SASecurityScore{ResourceType: item.ResourceType, ResourceId: item.ResourceID, ObservedSecurityScore: item.Score, ScoreAvailable: item.ScoreAvailable, EvidenceCoverage: item.Coverage, CoverageAvailable: item.CoverageAvailable, SecurityLowerBound: item.SecurityLowerBound, SecurityUpperBound: item.SecurityUpperBound, Provisional: item.Provisional, CriticalScoreCapApplied: item.ScoreCapped, Grade: item.Grade})
	}
	out.IncompleteSaResourceIds = append(out.IncompleteSaResourceIds, v.IncompleteSAResourceIDs...)
	return out
}
func finding(id string, index int, f rules.Finding) *securityv1.SecurityFinding {
	out := &securityv1.SecurityFinding{FindingId: fmt.Sprintf("%s:%d", id, index), RuleId: f.RuleID, Title: f.Title, Severity: string(f.Severity), Category: "SIH_BASELINE_COMPLIANCE", Description: f.Description, Recommendation: f.Recommendation, EvidenceProperties: f.EvidenceProperties, AffectedResourceType: f.ResourceType, AffectedResourceId: f.ResourceID, PolicyId: f.PolicyID, PolicyReference: f.PolicyReference}
	for _, evidence := range f.Evidence {
		out.Evidence = append(out.Evidence, supportingEvidence(evidence))
	}
	return out
}

func controlResult(value rules.ControlResult) *securityv1.SecurityControlResult {
	status := securityv1.ControlStatus_UNKNOWN
	switch value.Status {
	case rules.ControlPass:
		status = securityv1.ControlStatus_PASS
	case rules.ControlFail:
		status = securityv1.ControlStatus_FAIL
	case rules.ControlNotApplicable:
		status = securityv1.ControlStatus_NOT_APPLICABLE
	}
	out := &securityv1.SecurityControlResult{ControlId: value.ControlID, Category: value.Category, Area: value.Area, Title: value.Title, Status: status, Severity: string(value.Severity), Explanation: value.Explanation, Remediation: value.Remediation, AffectedResourceType: value.ResourceType, AffectedResourceId: value.ResourceID, PolicyId: value.PolicyID, PolicyReference: value.PolicyReference, Weight: value.Weight}
	for _, evidence := range value.Evidence {
		out.Evidence = append(out.Evidence, supportingEvidence(evidence))
	}
	return out
}

func supportingEvidence(value rules.EvidenceReference) *securityv1.SupportingEvidence {
	return &securityv1.SupportingEvidence{PropertyKey: value.PropertyKey, NormalizedValue: value.Value, EvidenceIds: value.EvidenceIDs, Sources: value.Sources}
}
