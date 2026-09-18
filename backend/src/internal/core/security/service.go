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

// ConclusionProvider returns Fusion's winning conclusions for an analysis.
type ConclusionProvider interface {
	FusedConclusions(context.Context, string) ([]model.FusedConclusion, error)
}

type Record struct {
	ID, AnalysisID, PolicyID string
	State                    securityv1.AssessmentState
	Result                   rules.Assessment
	PerSAAssessments         []rules.Assessment
	IncompleteSAResourceIDs  []string
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
		policyID = rules.SIHBaselinePolicyID
	}
	if policyID != rules.SIHBaselinePolicyID {
		return Record{}, shared.NewError(shared.InvalidArgument, "", "unsupported security assessment policy; use "+rules.SIHBaselinePolicyID)
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
		if policyID != rules.SIHBaselinePolicyID {
			return Record{}, shared.NewError(shared.InvalidArgument, "", "unsupported security assessment policy; use "+rules.SIHBaselinePolicyID)
		}
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
	scopes, unknown, metadata := facts(items)
	results := make([]rules.Assessment, 0, len(scopes))
	for _, scope := range scopes {
		result := rules.Assess(scope.Facts)
		result.ResourceType, result.ResourceID = scope.ResourceType, scope.ResourceID
		for index := range result.Findings {
			result.Findings[index].ResourceType = scope.ResourceType
			result.Findings[index].ResourceID = scope.ResourceID
		}
		for index := range result.Controls {
			result.Controls[index].ResourceType = scope.ResourceType
			result.Controls[index].ResourceID = scope.ResourceID
		}
		results = append(results, result)
	}
	result, incomplete := deploymentAssessment(results)
	s.mu.Lock()
	stored := s.records[id]
	stored.State, stored.Result, stored.PerSAAssessments, stored.IncompleteSAResourceIDs, stored.UnknownEvidence, stored.MetadataExposure = securityv1.AssessmentState_ASSESSMENT_COMPLETED, result, results, incomplete, unknown, metadata
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

type scopedFacts struct {
	ResourceType string
	ResourceID   string
	Facts        rules.Facts
}

func facts(items []model.FusedConclusion) ([]scopedFacts, uint64, bool) {
	type resource struct{ typ, id string }
	winners := map[resource]map[string]model.FusedConclusion{}
	knownConfiguration := map[string]bool{}
	metadataKnown, metadataExposure := false, false
	var metadataProtectionRequired *bool
	var metadataEvidence, metadataPolicyEvidence rules.EvidenceReference
	for _, item := range items {
		if item.Status == commonv1.EvidenceStatus_UNKNOWN {
			continue
		}
		if item.PropertyKey == model.PropertyMetadataExposure {
			metadataKnown = true
			metadataExposure = metadataExposure || scalar(item) != ""
			sources := make([]string, 0, len(item.WinningSources))
			for _, source := range item.WinningSources {
				sources = append(sources, string(source))
			}
			metadataEvidence = rules.EvidenceReference{PropertyKey: item.PropertyKey, Value: scalar(item), EvidenceIDs: append([]string(nil), item.EvidenceIDs...), Sources: sources}
			continue
		}
		if item.PropertyKey == model.PropertyMetadataProtectionRequired {
			value := strings.EqualFold(scalar(item), "true") || scalar(item) == "1"
			metadataProtectionRequired = &value
			sources := make([]string, 0, len(item.WinningSources))
			for _, source := range item.WinningSources {
				sources = append(sources, string(source))
			}
			metadataPolicyEvidence = rules.EvidenceReference{PropertyKey: item.PropertyKey, Value: scalar(item), EvidenceIDs: append([]string(nil), item.EvidenceIDs...), Sources: sources}
			continue
		}
		if !securityProperty(item.PropertyKey) {
			continue
		}
		for _, property := range model.SecurityConfigurationProperties {
			if item.PropertyKey == property {
				knownConfiguration[property] = true
			}
		}
		scope := resource{typ: item.ResourceType, id: item.ResourceID}
		if scope.typ == "" && scope.id == "" {
			scope = resource{typ: "ANALYSIS", id: "default"}
		}
		if winners[scope] == nil {
			winners[scope] = map[string]model.FusedConclusion{}
		}
		if old, ok := winners[scope][item.PropertyKey]; !ok || item.Confidence > old.Confidence || item.Confidence == old.Confidence && item.ID < old.ID {
			winners[scope][item.PropertyKey] = item
		}
	}
	if len(winners) == 0 {
		winners[resource{typ: "ANALYSIS", id: "default"}] = map[string]model.FusedConclusion{}
	}
	scopes := make([]scopedFacts, 0, len(winners))
	childAEAD := false
	hasAnalysisScope := false
	for scope, values := range winners {
		if scope.typ == "ANALYSIS" {
			hasAnalysisScope = true
		}
		get := func(name string) string {
			if item, ok := values[name]; ok {
				return scalar(item)
			}
			return ""
		}
		parseBool := func(name string) *bool {
			if item, ok := values[name]; ok {
				value := strings.EqualFold(scalar(item), "true") || scalar(item) == "1"
				return &value
			}
			return nil
		}
		parseNumber := func(name string) (uint64, bool) {
			value := get(name)
			if value == "" {
				return 0, false
			}
			var number uint64
			_, err := fmt.Sscan(value, &number)
			return number, err == nil
		}
		evidence := make(map[string]rules.EvidenceReference, len(values))
		for property, item := range values {
			sources := make([]string, 0, len(item.WinningSources))
			for _, source := range item.WinningSources {
				sources = append(sources, string(source))
			}
			evidence[property] = rules.EvidenceReference{PropertyKey: property, Value: scalar(item), EvidenceIDs: append([]string(nil), item.EvidenceIDs...), Sources: sources}
		}
		if scope.typ == "ANALYSIS" && metadataKnown {
			evidence[model.PropertyMetadataExposure] = metadataEvidence
		}
		if scope.typ == "ANALYSIS" && metadataProtectionRequired != nil {
			evidence[model.PropertyMetadataProtectionRequired] = metadataPolicyEvidence
		}
		ikeKey, ikeKeyKnown := parseNumber(model.PropertyIKEEncryptionKeyBits)
		ikeTag, ikeTagKnown := parseNumber(model.PropertyIKEAEADTagBits)
		childKey, childKeyKnown := parseNumber(model.PropertyChildEncryptionKeyBits)
		childTag, childTagKnown := parseNumber(model.PropertyChildAEADTagBits)
		ikeLifetime, ikeLifetimeKnown := parseNumber(model.PropertyIKELifetimeSeconds)
		childLifetime, childLifetimeKnown := parseNumber(model.PropertyChildLifetimeSeconds)
		installAge, installAgeKnown := parseNumber(model.PropertyChildInstallAgeSeconds)
		remaining, remainingKnown := parseNumber(model.PropertyChildRemainingLifetimeSeconds)
		replayWindow, replayWindowKnown := parseNumber(model.PropertyReplayWindow)
		selectorsKnown := get(model.PropertyChildLocalSelectors) != "" && get(model.PropertyChildRemoteSelectors) != ""
		f := rules.Facts{ResourceType: scope.typ, IKEVersion: get(model.PropertyIKEVersion), IKEEncryption: get(model.PropertyIKEEncryption), IKEIntegrity: get(model.PropertyIKEIntegrity), IKEAuthentication: get(model.PropertyIKEAuthentication), DHGroup: get(model.PropertyIKEDHGroup), IKEEncryptionKeyBits: ikeKey, IKEEncryptionKeyKnown: ikeKeyKnown, IKEAEADTagBits: ikeTag, IKEAEADTagKnown: ikeTagKnown, IKELifetimeSeconds: ikeLifetime, IKELifetimeKnown: ikeLifetimeKnown, EncryptionAlgorithm: get(model.PropertyChildEncryption), IntegrityAlgorithm: get(model.PropertyChildIntegrity), EncryptionKeyBits: childKey, EncryptionKeyKnown: childKeyKnown, AEADTagBits: childTag, AEADTagKnown: childTagKnown, Mode: get(model.PropertyChildMode), Protocol: get(model.PropertyChildProtocol), State: get(model.PropertyChildState), Direction: get(model.PropertyChildDirection), SelectorsKnown: selectorsKnown, PFS: parseBool(model.PropertyChildPFS), FreshExchangeObserved: parseBool(model.PropertyChildFreshExchange), ReplayProtection: parseBool(model.PropertyReplayEnabled), ReplayESN: parseBool(model.PropertyReplayESN), ReplayWindow: replayWindow, ReplayWindowKnown: replayWindowKnown, SALifetimeSeconds: childLifetime, SALifetimeKnown: childLifetimeKnown, InstallAgeSeconds: installAge, InstallAgeKnown: installAgeKnown, RemainingExpirySeconds: remaining, RemainingExpiryKnown: remainingKnown, MetadataExposure: metadataExposure, MetadataKnown: metadataKnown && scope.typ == "ANALYSIS", MetadataProtectionRequired: metadataProtectionRequired, Evidence: evidence}
		f.ConfiguredIKEProposals = get(model.PropertyConfiguredIKEProposals)
		f.ConfiguredChildProposals = get(model.PropertyConfiguredChildProposals)
		if consistency := parseBool(model.PropertySAConfigurationRuntimeConsistent); consistency != nil {
			f.ConfigurationRuntimeKnown, f.ConfigurationRuntimeConsistent = true, *consistency
		}
		// Only a CHILD-SA AEAD transform can supply CHILD-SA integrity. Never
		// substitute the cipher or integrity algorithm protecting the IKE SA.
		if f.IntegrityAlgorithm == "" && isAEAD(f.EncryptionAlgorithm) {
			f.IntegrityAlgorithm = "AEAD"
			childAEAD = true
		}
		scopes = append(scopes, scopedFacts{ResourceType: scope.typ, ResourceID: scope.id, Facts: f})
	}
	if metadataKnown && !hasAnalysisScope {
		evidence := map[string]rules.EvidenceReference{model.PropertyMetadataExposure: metadataEvidence}
		if metadataProtectionRequired != nil {
			evidence[model.PropertyMetadataProtectionRequired] = metadataPolicyEvidence
		}
		scopes = append(scopes, scopedFacts{ResourceType: "METADATA", ResourceID: "analysis", Facts: rules.Facts{ResourceType: "METADATA", MetadataExposure: metadataExposure, MetadataKnown: true, MetadataProtectionRequired: metadataProtectionRequired, Evidence: evidence}})
	}
	if childAEAD {
		knownConfiguration[model.PropertyChildIntegrity] = true
	}
	unknown := uint64(0)
	for _, property := range model.SecurityConfigurationProperties {
		if !knownConfiguration[property] {
			unknown++
		}
	}
	sort.Slice(scopes, func(i, j int) bool {
		return scopes[i].ResourceType+"\x00"+scopes[i].ResourceID < scopes[j].ResourceType+"\x00"+scopes[j].ResourceID
	})
	return scopes, unknown, metadataExposure
}

func securityProperty(key string) bool {
	switch key {
	case model.PropertyIKEVersion, model.PropertyIKEEncryption, model.PropertyIKEIntegrity, model.PropertyIKEAuthentication, model.PropertyConfiguredIKEProposals, model.PropertyConfiguredChildProposals,
		model.PropertyIKEEncryptionKeyBits, model.PropertyIKEAEADTagBits, model.PropertyIKEDHGroup, model.PropertyIKELifetimeSeconds,
		model.PropertyChildMode, model.PropertyChildProtocol, model.PropertyChildState, model.PropertyChildDirection,
		model.PropertyChildLocalSelectors, model.PropertyChildRemoteSelectors, model.PropertyChildEncryption,
		model.PropertyChildIntegrity, model.PropertyChildEncryptionKeyBits, model.PropertyChildAEADTagBits,
		model.PropertyChildPFS, model.PropertyChildFreshExchange, model.PropertyReplayEnabled, model.PropertyReplayWindow,
		model.PropertyReplayESN, model.PropertyReplaySequence, model.PropertyChildLifetimeSeconds,
		model.PropertyChildInstallAgeSeconds, model.PropertyChildRemainingLifetimeSeconds, model.PropertySAConfigurationRuntimeConsistent:
		return true
	default:
		return false
	}
}

// deploymentAssessment deliberately does not merge unrelated SAs. Its
// headline is the lowest observed SA score, while every per-SA result and
// incomplete SA remains available to callers.
func deploymentAssessment(items []rules.Assessment) (rules.Assessment, []string) {
	if len(items) == 0 {
		return rules.Assess(rules.Facts{}), nil
	}
	candidates := make([]rules.Assessment, 0, len(items))
	incomplete := make([]string, 0)
	for _, item := range items {
		if item.Provisional || !item.ScoreAvailable {
			incomplete = append(incomplete, item.ResourceType+"/"+item.ResourceID)
		}
		if isSAResource(item.ResourceType) && item.ScoreAvailable {
			candidates = append(candidates, item)
		}
	}
	if len(candidates) == 0 {
		for _, item := range items {
			if item.ScoreAvailable {
				candidates = append(candidates, item)
			}
		}
	}
	if len(candidates) == 0 {
		out := rules.Assess(rules.Facts{})
		out.Controls = nil
		for _, item := range items {
			out.Controls = append(out.Controls, item.Controls...)
			out.Findings = append(out.Findings, item.Findings...)
		}
		return out, incomplete
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Score < candidates[j].Score })
	out := candidates[0]
	out.Findings = nil
	out.Controls = nil
	out.ThreatMatrix = map[rules.Severity]int{}
	for _, item := range items {
		out.Controls = append(out.Controls, item.Controls...)
		out.Findings = append(out.Findings, item.Findings...)
		for severity, count := range item.ThreatMatrix {
			out.ThreatMatrix[severity] += count
		}
	}
	sort.Slice(out.Findings, func(i, j int) bool {
		if out.Findings[i].Severity != out.Findings[j].Severity {
			return severityRank(out.Findings[i].Severity) > severityRank(out.Findings[j].Severity)
		}
		return out.Findings[i].ResourceType+out.Findings[i].ResourceID+out.Findings[i].RuleID < out.Findings[j].ResourceType+out.Findings[j].ResourceID+out.Findings[j].RuleID
	})
	return out, incomplete
}

func isSAResource(value string) bool {
	upper := strings.ToUpper(value)
	return strings.Contains(upper, "_SA") || strings.Contains(upper, "XFRM")
}

func severityRank(value rules.Severity) int {
	switch value {
	case rules.SeverityCritical:
		return 4
	case rules.SeverityHigh:
		return 3
	case rules.SeverityMedium:
		return 2
	default:
		return 1
	}
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
