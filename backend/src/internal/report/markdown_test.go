package report

import (
	"strings"
	"testing"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/security"
)

func TestGenerateIncludesEvidenceFindingsAndLimits(t *testing.T) {
	disabled := false
	assessment := security.Assess(security.Facts{IKEVersion: "IKEv2", PFS: &disabled})
	output := Generate(Input{
		AnalysisID: "analysis-1", GeneratedAt: time.Unix(100, 0), Assessment: assessment,
		Conclusions: []fusion.Conclusion{{Property: "traffic.class", Value: "UNKNOWN", Status: commonv1.EvidenceStatus_UNKNOWN, Confidence: .42, WinningSource: fusion.SourceMLClassifier}},
	})
	for _, expected := range []string{"Observed security score", "Perfect Forward Secrecy", "traffic.class", "ESP payloads were not decrypted", "UNKNOWN", "ANOMALY"} {
		if !strings.Contains(output.ExecutiveMarkdown+output.TechnicalMarkdown, expected) {
			t.Fatalf("report is missing %q", expected)
		}
	}
}
