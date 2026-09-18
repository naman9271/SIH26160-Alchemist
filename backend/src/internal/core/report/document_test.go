package report

import (
	"testing"
	"time"

	analysisv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/analysis"
	fusionv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/fusion"
	mlv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/ml"
	protocolv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/protocolread"
	riskv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/risk"
	workspacev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/workspace"
	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
	coreanalysis "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/analysis"
	coreinput "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/input"
	coresystem "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/system"
	rules "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/security"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/capture"
)

func TestReportDocumentIncludesOnlySupportedOptionalSections(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	record := coreanalysis.Record{ID: "analysis-deep", Mode: workspacev1.AnalysisMode_DEEP_ASSESSMENT, State: analysisv1.AnalysisState_ANALYSIS_STATE_COMPLETED, Stage: analysisv1.AnalysisStage_COMPLETED, CreatedAt: now, UpdatedAt: now.Add(time.Minute)}
	source := &coreinput.Source{ID: "source", CaptureID: "capture", Counters: capture.Counters{PacketsTotal: 20, BytesTotal: 4096, ESPPackets: 12}}
	assessment := rules.Assess(rules.Facts{IKEVersion: "IKEv1"})
	payload := map[string]interface{}{
		"security_assessment":    assessment,
		"unknown_evidence_count": uint64(2),
		"ml_predictions":         []*mlv1.TrafficPrediction{{TrafficClass: "browsing", Confidence: .82}},
		"analysis_progress":      &analysisv1.AnalysisProgress{PacketsProcessed: 20, FlowsProcessed: 1, SessionsFound: 1, EvidenceCount: 3},
		"flow_records":           []reportFlow{{Flow: &flowv1.Flow{Protocol: flowv1.FlowProtocol_ESP, SourceAddress: "192.0.2.1", DestinationAddress: "192.0.2.2"}, Stats: &flowv1.FlowStats{PacketCount: 12, ByteCount: 4096}}},
		"vpn_sessions":           []*protocolv1.VpnSession{{SessionId: "session-1", Mode: "PASSIVE_PCAP", State: "READY"}},
		"protocol_evidence":      []*protocolv1.ProtocolEvidence{{PropertyKey: "ike.version", Value: "IKEv2", Confidence: .95}},
		"fusion_status":          &fusionv1.FusionStatus{State: "COMPLETE", EvidenceCount: 3, ConclusionCount: 1},
		"risk_score":             &riskv1.SecurityScore{Score: 92, ObservedSecurityScore: 92, ScoreAvailable: true, RiskScore: 8, RiskLevel: "LOW", EvidenceCoverage: 90, CoverageAvailable: true, UnknownEvidenceCount: 2},
		"risk_breakdown":         &riskv1.RiskBreakdown{Cryptography: &riskv1.RiskCategory{Score: 25, Maximum: 25}},
		"system_capabilities":    coresystem.Capabilities{PassivePCAP: true, SecurityAssessment: true, ExecutiveReport: true},
		"ml_worker":              &mlv1.MLWorkerStatus{Available: true, ModelLoaded: true, ModelVersion: "test"},
	}
	document := buildReportDocument(record, source, nil, payload, now)
	titles := map[string]bool{}
	for _, section := range document.Sections {
		titles[section.Title] = true
	}
	for _, expected := range []string{"Progress Flow", "Flows", "VPN Sessions", "Deep Analysis", "Live Capture", "Traffic Classification", "Evidence", "Security Findings", "Recommendations", "Risk & Fixes", "System Health"} {
		if !titles[expected] {
			t.Fatalf("expected section %q", expected)
		}
	}
	if titles["Passive Analysis"] {
		t.Fatal("deep assessment must not be mislabeled as passive analysis")
	}
	if titles["Appendix: Evidence Conclusions"] {
		t.Fatal("empty evidence appendix should be omitted")
	}
}

func TestReportDocumentKeepsDashboardSectionsWhenDataIsUnavailable(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	document := buildReportDocument(coreanalysis.Record{ID: "analysis", CreatedAt: now, UpdatedAt: now}, nil, nil, map[string]interface{}{}, now)
	titles := map[string]bool{}
	for _, section := range document.Sections {
		titles[section.Title] = true
		switch section.Title {
		case "Deep Analysis", "Live Capture", "Recommendations", "Appendix: Evidence Conclusions":
			t.Fatalf("unsupported optional section %q should be omitted", section.Title)
		}
	}
	for _, expected := range []string{"Progress Flow", "VPN Sessions", "Flows", "Traffic Classification", "Evidence", "Security Findings", "Risk & Fixes", "System Health"} {
		if !titles[expected] {
			t.Fatalf("dashboard section %q should explain unavailable data", expected)
		}
	}
}

func TestFindingResourceKeepsConcurrentSAsDistinguishable(t *testing.T) {
	strong := findingResource(rules.Finding{ResourceType: "CHILD_SA", ResourceID: "child-strong"})
	weak := findingResource(rules.Finding{ResourceType: "CHILD_SA", ResourceID: "child-weak"})
	if strong != " [CHILD_SA child-strong]" || weak != " [CHILD_SA child-weak]" || strong == weak {
		t.Fatalf("report SA labels were not distinct: strong=%q weak=%q", strong, weak)
	}
}
