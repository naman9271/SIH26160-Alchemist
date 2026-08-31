package report

import (
	"bytes"
	"testing"

	fusionv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/fusion"
)

func TestReportPDFContainsReadableRequiredSections(t *testing.T) {
	conclusions := make([]*fusionv1.FusedConclusion, 60)
	for i := range conclusions {
		conclusions[i] = &fusionv1.FusedConclusion{PropertyKey: "ike.encryption", Value: "AES_GCM", Confidence: .9, RationaleCode: "VERIFIED"}
	}
	pdf := reportPDF("analysis", conclusions, map[string]interface{}{})
	for _, section := range [][]byte{[]byte("Executive Summary"), []byte("Protocol / IPsec Details"), []byte("Security Findings"), []byte("Risk Score"), []byte("Fusion / Evidence Table"), []byte("Technical Appendix")} {
		if !bytes.Contains(pdf, section) {
			t.Fatalf("PDF missing %q", section)
		}
	}
	if bytes.Count(pdf, []byte("/Type/Page/")) < 2 {
		t.Fatalf("expected multi-page PDF, got %d pages", bytes.Count(pdf, []byte("/Type/Page/")))
	}
}
