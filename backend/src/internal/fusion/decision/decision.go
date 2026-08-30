// Package decision contains the shared deterministic winner-selection rules.
package decision

import (
	"bytes"
	"sort"
	"strings"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/store"
	"google.golang.org/protobuf/encoding/protojson"
)

type EvidenceGroup struct {
	PropertyKey  string
	ResourceType string
	ResourceID   string
	Evidence     []model.EvidenceItem
}

type Result struct {
	Winner     model.EvidenceItem
	Supporting []model.EvidenceItem
	Rationale  string
}

func GroupEvidence(run model.Run, affectedProperties map[string]struct{}) []EvidenceGroup {
	membership := make(map[string]model.CorrelationGroup)
	for _, group := range run.Correlations {
		for _, evidenceID := range group.EvidenceIDs {
			membership[evidenceID] = group
		}
	}
	groups := make(map[string]*EvidenceGroup)
	for _, item := range store.SortedEvidence(run) {
		if len(affectedProperties) > 0 {
			if _, included := affectedProperties[item.PropertyKey]; !included {
				continue
			}
		}
		if item.Source == model.SourceSecurityRule && !strings.HasPrefix(item.PropertyKey, "security.rule.") {
			continue
		}
		resourceType, resourceID := item.ResourceType, item.ResourceID
		if correlation, exists := membership[item.ID]; exists {
			resourceType, resourceID = correlation.ResourceType, correlation.ResourceID
		}
		key := store.ConclusionKey(item.PropertyKey, resourceType, resourceID)
		group := groups[key]
		if group == nil {
			group = &EvidenceGroup{PropertyKey: item.PropertyKey, ResourceType: resourceType, ResourceID: resourceID}
			groups[key] = group
		}
		group.Evidence = append(group.Evidence, item.Clone())
	}
	result := make([]EvidenceGroup, 0, len(groups))
	for _, group := range groups {
		sort.Slice(group.Evidence, func(i, j int) bool { return group.Evidence[i].ID < group.Evidence[j].ID })
		result = append(result, *group)
	}
	sort.Slice(result, func(i, j int) bool {
		return store.ConclusionKey(result[i].PropertyKey, result[i].ResourceType, result[i].ResourceID) <
			store.ConclusionKey(result[j].PropertyKey, result[j].ResourceType, result[j].ResourceID)
	})
	return result
}

func Select(property string, evidence []model.EvidenceItem, definition policy.Definition) (Result, error) {
	if len(evidence) == 0 {
		return Result{}, model.NewError(model.ErrorInvalidArgument, "candidate evidence is required")
	}
	candidates := make([]model.EvidenceItem, 0, len(evidence))
	for _, item := range evidence {
		if item.PropertyKey == property && !(item.Source == model.SourceSecurityRule && !strings.HasPrefix(property, "security.rule.")) {
			candidates = append(candidates, item.Clone())
		}
	}
	if len(candidates) == 0 {
		return Result{}, model.NewError(model.ErrorFailedPrecondition, "no eligible evidence exists for the property")
	}
	rule := definition.Rule(property)
	sort.SliceStable(candidates, func(i, j int) bool { return better(candidates[i], candidates[j], rule, definition, time.Now().UTC()) })
	winner := candidates[0]
	winningValue := CanonicalValue(winner)
	supporting := make([]model.EvidenceItem, 0, len(candidates))
	for _, item := range candidates {
		if CanonicalValue(item) == winningValue {
			supporting = append(supporting, item.Clone())
		}
	}
	return Result{Winner: winner.Clone(), Supporting: supporting, Rationale: rationale(winner, candidates, rule)}, nil
}

func DistinctKnownValues(evidence []model.EvidenceItem) map[string][]string {
	values := make(map[string][]string)
	for _, item := range evidence {
		if item.Status == commonv1.EvidenceStatus_UNKNOWN || item.Value == nil || CanonicalValue(item) == "null" {
			continue
		}
		value := CanonicalValue(item)
		values[value] = append(values[value], item.ID)
	}
	return values
}

func CanonicalValue(item model.EvidenceItem) string {
	if item.Value == nil {
		return "null"
	}
	encoded, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(item.Value)
	if err != nil {
		return "null"
	}
	return string(bytes.TrimSpace(encoded))
}

func better(left, right model.EvidenceItem, rule policy.PropertyRule, definition policy.Definition, now time.Time) bool {
	leftStatus, rightStatus := statusRank(left.Status, definition), statusRank(right.Status, definition)
	if leftStatus != rightStatus {
		return leftStatus > rightStatus
	}
	leftPrecedence, rightPrecedence := sourcePrecedence(left.Source, rule), sourcePrecedence(right.Source, rule)
	if leftPrecedence != rightPrecedence {
		return leftPrecedence < rightPrecedence
	}
	leftTrust, rightTrust := definition.SourceTrust[left.Source], definition.SourceTrust[right.Source]
	if leftTrust != rightTrust {
		return leftTrust > rightTrust
	}
	if left.Confidence != right.Confidence {
		return left.Confidence > right.Confidence
	}
	leftFresh, rightFresh := freshness(left.ObservedAt, now), freshness(right.ObservedAt, now)
	if leftFresh != rightFresh {
		return leftFresh > rightFresh
	}
	return left.ID < right.ID
}

func statusRank(status commonv1.EvidenceStatus, definition policy.Definition) int {
	if len(definition.StatusPrecedence) == 0 {
		return StatusRank(status)
	}
	for index, candidate := range definition.StatusPrecedence {
		if candidate == status {
			return len(definition.StatusPrecedence) - index
		}
	}
	return 0
}

func sourcePrecedence(source model.Source, rule policy.PropertyRule) int {
	for index, candidate := range rule.SourcePrecedence {
		if source == candidate {
			return index
		}
	}
	return len(rule.SourcePrecedence) + 1
}

func StatusRank(status commonv1.EvidenceStatus) int {
	switch status {
	case commonv1.EvidenceStatus_VERIFIED_GATEWAY:
		return 4
	case commonv1.EvidenceStatus_OBSERVED:
		return 3
	case commonv1.EvidenceStatus_DERIVED:
		return 2
	case commonv1.EvidenceStatus_INFERRED:
		return 1
	default:
		return 0
	}
}

func freshness(observed, now time.Time) int64 {
	if observed.After(now) {
		return now.UnixNano()
	}
	return observed.UnixNano()
}

func rationale(winner model.EvidenceItem, candidates []model.EvidenceItem, rule policy.PropertyRule) string {
	for _, item := range candidates {
		if item.ID == winner.ID || CanonicalValue(item) == CanonicalValue(winner) {
			continue
		}
		if winner.Status == commonv1.EvidenceStatus_VERIFIED_GATEWAY && StatusRank(item.Status) < StatusRank(winner.Status) {
			if item.Status == commonv1.EvidenceStatus_DERIVED {
				return "VERIFIED_OVERRIDES_DERIVED"
			}
			return "VERIFIED_GATEWAY_PRECEDENCE"
		}
		if sourcePrecedence(winner.Source, rule) < sourcePrecedence(item.Source, rule) {
			return "PROPERTY_SOURCE_PRECEDENCE"
		}
	}
	return "BEST_SUPPORTED_EVIDENCE"
}
