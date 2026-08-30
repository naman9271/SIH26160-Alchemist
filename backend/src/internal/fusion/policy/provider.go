// Package policy resolves versioned Fusion policies used by run creation.
package policy

import (
	"context"
	"maps"
	"sort"
	"strings"
	"sync"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
)

const SchemaVersion = "fusion-policy.v1"

type Definition struct {
	ID                   string
	SchemaVersion        string
	RequiredSources      []model.Source
	RequiredProperties   []string
	SourceTrust          map[model.Source]float64
	FreshnessWindow      time.Duration
	MinimumConfidence    float64
	ConflictThreshold    float64
	CorrelationThreshold float64
	StatusPrecedence     []commonv1.EvidenceStatus
	PropertyRules        map[string]PropertyRule
}

type PropertyRule struct {
	SourcePrecedence  []model.Source
	FreshnessWindow   time.Duration
	MinimumConfidence float64
}

func (r PropertyRule) Clone() PropertyRule {
	r.SourcePrecedence = append([]model.Source(nil), r.SourcePrecedence...)
	return r
}

func (d Definition) Clone() Definition {
	d.RequiredSources = append([]model.Source(nil), d.RequiredSources...)
	d.RequiredProperties = append([]string(nil), d.RequiredProperties...)
	d.SourceTrust = maps.Clone(d.SourceTrust)
	d.StatusPrecedence = append([]commonv1.EvidenceStatus(nil), d.StatusPrecedence...)
	d.PropertyRules = make(map[string]PropertyRule, len(d.PropertyRules))
	for property, rule := range d.PropertyRules {
		d.PropertyRules[property] = rule.Clone()
	}
	return d
}

func (d Definition) Rule(property string) PropertyRule {
	if rule, ok := d.PropertyRules[property]; ok {
		return rule.Clone()
	}
	best := ""
	for prefix := range d.PropertyRules {
		if strings.HasSuffix(prefix, "*") && strings.HasPrefix(property, strings.TrimSuffix(prefix, "*")) && len(prefix) > len(best) {
			best = prefix
		}
	}
	if best != "" {
		return d.PropertyRules[best].Clone()
	}
	return PropertyRule{FreshnessWindow: d.FreshnessWindow, MinimumConfidence: d.MinimumConfidence}
}

type Provider interface {
	Resolve(context.Context, string) (Definition, error)
	Ready(context.Context) (bool, string)
}

type Memory struct {
	mu       sync.RWMutex
	policies map[string]Definition
	activeID string
}

func NewMemory(definitions ...Definition) *Memory {
	provider := &Memory{policies: make(map[string]Definition)}
	for _, definition := range definitions {
		if strings.TrimSpace(definition.ID) == "" {
			continue
		}
		if definition.SchemaVersion == "" {
			definition.SchemaVersion = SchemaVersion
		}
		provider.policies[definition.ID] = definition.Clone()
		if provider.activeID == "" {
			provider.activeID = definition.ID
		}
	}
	return provider
}

func NewDefault() *Memory {
	return NewMemory(Definition{
		ID:              model.DefaultPolicyID,
		SchemaVersion:   SchemaVersion,
		RequiredSources: []model.Source{model.SourcePacketParser, model.SourceFlowAnalyzer},
		RequiredProperties: []string{
			"ike.version", "ike.encryption", "ike.integrity", "ike.prf", "ike.dh_group",
			"child.mode", "child.esp_encryption", "child.integrity", "child.pfs",
			"replay.enabled", "traffic.class", "metadata.exposure",
		},
		SourceTrust: map[model.Source]float64{
			model.SourcePacketParser: .95, model.SourceFlowAnalyzer: .90,
			model.SourceVICI: 1, model.SourceXFRM: 1,
			model.SourceMLClassifier: .75, model.SourceMLAnomaly: .75, model.SourceSHAP: .70,
			model.SourceSecurityRule: .85, model.SourceOperator: 1,
		},
		FreshnessWindow:   24 * time.Hour,
		MinimumConfidence: .25, ConflictThreshold: .05, CorrelationThreshold: .50,
		StatusPrecedence: []commonv1.EvidenceStatus{commonv1.EvidenceStatus_VERIFIED_GATEWAY, commonv1.EvidenceStatus_OBSERVED, commonv1.EvidenceStatus_DERIVED, commonv1.EvidenceStatus_INFERRED, commonv1.EvidenceStatus_UNKNOWN},
		PropertyRules: map[string]PropertyRule{
			"ike.version":   {SourcePrecedence: []model.Source{model.SourceVICI, model.SourcePacketParser, model.SourceXFRM}},
			"child.*":       {SourcePrecedence: []model.Source{model.SourceVICI, model.SourceXFRM, model.SourcePacketParser}},
			"replay.*":      {SourcePrecedence: []model.Source{model.SourceXFRM, model.SourceVICI, model.SourcePacketParser}},
			"traffic.class": {SourcePrecedence: []model.Source{model.SourceOperator, model.SourceMLClassifier}},
		},
	})
}

func (p *Memory) List(ctx context.Context) ([]Definition, error) {
	if err := model.ContextError(ctx); err != nil {
		return nil, err
	}
	if p == nil {
		return nil, model.NewError(model.ErrorUnavailable, "Fusion policy provider is not configured")
	}
	p.mu.RLock()
	result := make([]Definition, 0, len(p.policies))
	for _, definition := range p.policies {
		result = append(result, definition.Clone())
	}
	p.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (p *Memory) Active(ctx context.Context) (Definition, error) {
	if err := model.ContextError(ctx); err != nil {
		return Definition{}, err
	}
	if p == nil {
		return Definition{}, model.NewError(model.ErrorUnavailable, "Fusion policy provider is not configured")
	}
	p.mu.RLock()
	definition, exists := p.policies[p.activeID]
	p.mu.RUnlock()
	if !exists {
		return Definition{}, model.NewError(model.ErrorFailedPrecondition, "no active Fusion policy is configured")
	}
	return definition.Clone(), nil
}

func (p *Memory) SetActive(ctx context.Context, id string) (Definition, error) {
	if err := model.ContextError(ctx); err != nil {
		return Definition{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return Definition{}, model.NewError(model.ErrorInvalidArgument, "policy_id is required")
	}
	if p == nil {
		return Definition{}, model.NewError(model.ErrorUnavailable, "Fusion policy provider is not configured")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	definition, exists := p.policies[id]
	if !exists {
		return Definition{}, model.NewError(model.ErrorNotFound, "Fusion policy was not found")
	}
	p.activeID = id
	return definition.Clone(), nil
}

func (p *Memory) Replace(ctx context.Context, definitions []Definition, activeID string) error {
	if err := model.ContextError(ctx); err != nil {
		return err
	}
	if p == nil {
		return model.NewError(model.ErrorUnavailable, "Fusion policy provider is not configured")
	}
	if len(definitions) == 0 {
		return model.NewError(model.ErrorFailedPrecondition, "at least one Fusion policy must be loaded")
	}
	replacement := make(map[string]Definition, len(definitions))
	for _, definition := range definitions {
		if _, exists := replacement[definition.ID]; exists {
			return model.NewError(model.ErrorAlreadyExists, "duplicate Fusion policy ID")
		}
		replacement[definition.ID] = definition.Clone()
	}
	if _, exists := replacement[activeID]; !exists {
		return model.NewError(model.ErrorInvalidArgument, "active policy is not present in the reload set")
	}
	p.mu.Lock()
	p.policies, p.activeID = replacement, activeID
	p.mu.Unlock()
	return nil
}

func (p *Memory) Resolve(ctx context.Context, id string) (Definition, error) {
	if err := model.ContextError(ctx); err != nil {
		return Definition{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return Definition{}, model.NewError(model.ErrorInvalidArgument, "policy_id is required")
	}
	if p == nil {
		return Definition{}, model.NewError(model.ErrorUnavailable, "Fusion policy provider is not configured")
	}
	p.mu.RLock()
	definition, exists := p.policies[id]
	p.mu.RUnlock()
	if !exists {
		return Definition{}, model.NewError(model.ErrorNotFound, "Fusion policy was not found")
	}
	return definition.Clone(), nil
}

func (p *Memory) Ready(ctx context.Context) (bool, string) {
	if err := model.ContextError(ctx); err != nil {
		return false, err.Error()
	}
	if p == nil {
		return false, "Fusion policy provider is not configured"
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.policies) == 0 {
		return false, "no Fusion policy is loaded"
	}
	return true, ""
}
