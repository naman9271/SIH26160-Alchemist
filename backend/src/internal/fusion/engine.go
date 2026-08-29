// Package fusion deterministically resolves evidence without scoring security
// or applying a second ML confidence threshold.
package fusion

import (
	"errors"
	"sort"
	"strings"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
)

type Source string

const (
	SourcePacketParser Source = "PACKET_PARSER"
	SourceFlowAnalyzer Source = "FLOW_ANALYZER"
	SourceVICI         Source = "STRONGSWAN_VICI"
	SourceXFRM         Source = "LINUX_XFRM"
	SourceMLClassifier Source = "ML_CLASSIFIER"
	SourceMLAnomaly    Source = "ML_ANOMALY"
	SourceSHAP         Source = "SHAP"
	SourceSecurityRule Source = "SECURITY_RULE_ENGINE"
)

type Evidence struct {
	ID, Property, Value, ModelVersion string
	Source                            Source
	Status                            commonv1.EvidenceStatus
	Confidence                        float64
	ObservedAt                        time.Time
	IsUnknown                         bool
}

type Conflict struct {
	EvidenceID, Value string
	Source            Source
}

type Conclusion struct {
	Property, Value string
	Status          commonv1.EvidenceStatus
	Confidence      float64
	WinningSource   Source
	EvidenceIDs     []string
	Conflicts       []Conflict
	FindingRefs     []string
}

type Engine struct{}

func New() *Engine { return &Engine{} }

func (e *Engine) Fuse(property string, evidence []Evidence) (Conclusion, error) {
	property = strings.TrimSpace(property)
	if property == "" {
		return Conclusion{}, errors.New("fusion property is required")
	}
	eligible := make([]Evidence, 0, len(evidence))
	for _, item := range evidence {
		if item.Property != property || item.Source == SourceSecurityRule {
			continue
		}
		if item.Confidence < 0 || item.Confidence > 1 {
			return Conclusion{}, errors.New("evidence confidence must be within [0,1]")
		}
		if item.Source == SourceMLClassifier && item.Status != commonv1.EvidenceStatus_INFERRED && item.Status != commonv1.EvidenceStatus_UNKNOWN {
			return Conclusion{}, errors.New("classifier evidence must be INFERRED or UNKNOWN")
		}
		if item.IsUnknown {
			item.Value = "UNKNOWN"
			item.Status = commonv1.EvidenceStatus_UNKNOWN
		}
		if strings.TrimSpace(item.Value) == "" {
			continue
		}
		eligible = append(eligible, item)
	}
	if len(eligible) == 0 {
		return Conclusion{Property: property, Value: "UNKNOWN", Status: commonv1.EvidenceStatus_UNKNOWN}, nil
	}
	sort.SliceStable(eligible, func(i, j int) bool {
		left, right := statusRank(eligible[i].Status), statusRank(eligible[j].Status)
		if left != right {
			return left > right
		}
		if eligible[i].Confidence != eligible[j].Confidence {
			return eligible[i].Confidence > eligible[j].Confidence
		}
		return eligible[i].ObservedAt.After(eligible[j].ObservedAt)
	})
	winner := eligible[0]
	result := Conclusion{
		Property: property, Value: winner.Value, Status: winner.Status,
		Confidence: winner.Confidence, WinningSource: winner.Source,
	}
	for _, item := range eligible {
		if item.ID != "" {
			result.EvidenceIDs = append(result.EvidenceIDs, item.ID)
		}
		if item.Value != winner.Value {
			result.Conflicts = append(result.Conflicts, Conflict{EvidenceID: item.ID, Value: item.Value, Source: item.Source})
		}
	}
	return result, nil
}

// AttachFindingRefs is intentionally post-fusion. Finding IDs add report
// provenance but cannot alter the selected protocol/traffic conclusion.
func AttachFindingRefs(conclusion Conclusion, findingIDs ...string) Conclusion {
	for _, id := range findingIDs {
		if strings.TrimSpace(id) != "" {
			conclusion.FindingRefs = append(conclusion.FindingRefs, id)
		}
	}
	return conclusion
}

func statusRank(status commonv1.EvidenceStatus) int {
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
