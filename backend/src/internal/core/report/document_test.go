package report

import (
	"testing"
	"time"

	analysisv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/analysis"
	mlv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/ml"
	workspacev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/workspace"
	coreanalysis "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/analysis"
	coreinput "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/input"
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
	}
	document := buildReportDocument(record, source, nil, payload, now)
	titles := map[string]bool{}
	for _, section := range document.Sections {
		titles[section.Title] = true
	}
	for _, expected := range []string{"Deep Analysis", "Live Capture", "Traffic Classification", "Security Findings", "Recommendations"} {
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

func TestReportDocumentOmitsUnavailableOptionalSections(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	document := buildReportDocument(coreanalysis.Record{ID: "analysis", CreatedAt: now, UpdatedAt: now}, nil, nil, map[string]interface{}{}, now)
	for _, section := range document.Sections {
		switch section.Title {
		case "Deep Analysis", "Live Capture", "Traffic Classification", "Security Findings", "Recommendations", "Appendix: Evidence Conclusions":
			t.Fatalf("unsupported optional section %q should be omitted", section.Title)
		}
	}
}
