// Package policy exposes the authoritative, versioned Fusion policies to Core
// clients. It deliberately delegates parsing and validation to Fusion.
package policy

import (
	"context"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	policyv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/policy"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	fusionpolicy "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
)

type Service struct{ policy *fusionpolicy.Service }

func New(service *fusionpolicy.Service) *Service { return &Service{policy: service} }
func (s *Service) List(ctx context.Context) ([]*policyv1.SecurityPolicy, error) {
	if err := s.valid(); err != nil {
		return nil, err
	}
	result, err := s.policy.List(ctx, fusionpolicy.ListRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]*policyv1.SecurityPolicy, 0, len(result.Policies))
	for _, item := range result.Policies {
		out = append(out, view(item))
	}
	return out, nil
}
func (s *Service) Get(ctx context.Context, id string) (*policyv1.SecurityPolicy, error) {
	if err := s.valid(); err != nil {
		return nil, err
	}
	value, err := s.policy.Get(ctx, fusionpolicy.GetRequest{PolicyID: id})
	if err != nil {
		return nil, err
	}
	return view(value), nil
}
func (s *Service) Active(ctx context.Context) (*policyv1.SecurityPolicy, error) {
	if err := s.valid(); err != nil {
		return nil, err
	}
	value, err := s.policy.GetActive(ctx)
	if err != nil {
		return nil, err
	}
	return view(value), nil
}
func (s *Service) SetActive(ctx context.Context, id string) (*policyv1.SecurityPolicy, error) {
	if err := s.valid(); err != nil {
		return nil, err
	}
	value, err := s.policy.SetActive(ctx, fusionpolicy.SetActiveRequest{PolicyID: id})
	if err != nil {
		return nil, err
	}
	return view(value.Policy), nil
}
func (s *Service) Validate(ctx context.Context, value *policyv1.SecurityPolicy) (*policyv1.ValidatePolicyResponse, error) {
	if err := s.valid(); err != nil {
		return nil, err
	}
	definition := definitionFrom(value)
	result, err := s.policy.Validate(ctx, fusionpolicy.ValidateRequest{Policy: definition})
	if err != nil {
		return nil, err
	}
	out := &policyv1.ValidatePolicyResponse{Valid: result.Valid}
	for _, issue := range result.Issues {
		out.Issues = append(out.Issues, &policyv1.ValidationIssue{Field: issue.Field, Message: issue.Message})
	}
	return out, nil
}
func (s *Service) Reload(ctx context.Context) (*policyv1.ReloadPoliciesResponse, error) {
	if err := s.valid(); err != nil {
		return nil, err
	}
	value, err := s.policy.Reload(ctx, fusionpolicy.ReloadRequest{})
	if err != nil {
		return nil, err
	}
	return &policyv1.ReloadPoliciesResponse{PoliciesLoaded: value.PoliciesLoaded, ActivePolicyId: value.ActivePolicyID}, nil
}
func (s *Service) valid() error {
	if s == nil || s.policy == nil {
		return shared.NewError(shared.Internal, "", "policy service is not configured")
	}
	return nil
}

func view(value fusionpolicy.Definition) *policyv1.SecurityPolicy {
	out := &policyv1.SecurityPolicy{PolicyId: value.ID, SchemaVersion: value.SchemaVersion, RequiredProperties: append([]string(nil), value.RequiredProperties...), FreshnessWindowSeconds: uint64(value.FreshnessWindow / time.Second), MinimumConfidence: value.MinimumConfidence, ConflictThreshold: value.ConflictThreshold, CorrelationThreshold: value.CorrelationThreshold, SourceTrust: map[string]float64{}, PropertyRules: map[string]*policyv1.PropertyRule{}}
	for _, source := range value.RequiredSources {
		out.RequiredSources = append(out.RequiredSources, string(source))
	}
	for source, trust := range value.SourceTrust {
		out.SourceTrust[string(source)] = trust
	}
	for _, status := range value.StatusPrecedence {
		out.StatusPrecedence = append(out.StatusPrecedence, status.String())
	}
	for key, rule := range value.PropertyRules {
		item := &policyv1.PropertyRule{FreshnessWindowSeconds: uint64(rule.FreshnessWindow / time.Second), MinimumConfidence: rule.MinimumConfidence}
		for _, source := range rule.SourcePrecedence {
			item.SourcePrecedence = append(item.SourcePrecedence, string(source))
		}
		out.PropertyRules[key] = item
	}
	return out
}
func definitionFrom(value *policyv1.SecurityPolicy) fusionpolicy.Definition {
	if value == nil {
		return fusionpolicy.Definition{}
	}
	out := fusionpolicy.Definition{ID: value.GetPolicyId(), SchemaVersion: value.GetSchemaVersion(), RequiredProperties: append([]string(nil), value.GetRequiredProperties()...), FreshnessWindow: time.Duration(value.GetFreshnessWindowSeconds()) * time.Second, MinimumConfidence: value.GetMinimumConfidence(), ConflictThreshold: value.GetConflictThreshold(), CorrelationThreshold: value.GetCorrelationThreshold(), SourceTrust: map[model.Source]float64{}, PropertyRules: map[string]fusionpolicy.PropertyRule{}}
	// Conversion is intentionally conservative: unknown source/status names remain
	// absent and are reported by Fusion's existing validator rather than accepted.
	for source, trust := range value.GetSourceTrust() {
		parsed := model.Source(source)
		out.SourceTrust[parsed] = trust
	}
	for _, source := range value.GetRequiredSources() {
		out.RequiredSources = append(out.RequiredSources, model.Source(source))
	}
	for _, status := range value.GetStatusPrecedence() {
		if number, ok := commonv1.EvidenceStatus_value[status]; ok {
			out.StatusPrecedence = append(out.StatusPrecedence, commonv1.EvidenceStatus(number))
		}
	}
	for key, rule := range value.GetPropertyRules() {
		parsed := fusionpolicy.PropertyRule{FreshnessWindow: time.Duration(rule.GetFreshnessWindowSeconds()) * time.Second, MinimumConfidence: rule.GetMinimumConfidence()}
		for _, source := range rule.GetSourcePrecedence() {
			parsed.SourcePrecedence = append(parsed.SourcePrecedence, model.Source(source))
		}
		out.PropertyRules[key] = parsed
	}
	return out
}
