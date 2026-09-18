// Package report renders deterministic, temporary assessment reports. It does
// not use an LLM and never invents evidence or recommendations.
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/security"
)

type Input struct {
	AnalysisID  string
	GeneratedAt time.Time
	Conclusions []fusion.Conclusion
	Assessment  security.Assessment
}

type Output struct {
	ExecutiveMarkdown string
	TechnicalMarkdown string
}

func Generate(input Input) Output {
	generatedAt := input.GeneratedAt.UTC()
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	conclusions := append([]fusion.Conclusion(nil), input.Conclusions...)
	sort.Slice(conclusions, func(i, j int) bool { return conclusions[i].Property < conclusions[j].Property })
	findings := append([]security.Finding(nil), input.Assessment.Findings...)

	var executive strings.Builder
	fmt.Fprintf(&executive, "# IPsec VPN Executive Assessment\n\n")
	fmt.Fprintf(&executive, "- Analysis: `%s`\n", markdown(input.AnalysisID))
	fmt.Fprintf(&executive, "- Generated: `%s`\n", generatedAt.Format(time.RFC3339))
	fmt.Fprintf(&executive, "- Security score: **%d/100 (%s)**\n", input.Assessment.Score, input.Assessment.Grade)
	if input.Assessment.PolicyID != "" {
		fmt.Fprintf(&executive, "- Assessment policy: **%s** (%s)\n", markdown(input.Assessment.PolicyLabel), markdown(input.Assessment.PolicyID))
	}
	fmt.Fprintf(&executive, "- Findings: **%d**\n\n", len(findings))
	if len(findings) == 0 {
		executive.WriteString("No deterministic rule finding was produced from the available evidence. Missing evidence is not treated as a pass.\n")
	} else {
		executive.WriteString("## Priority actions\n\n")
		for _, finding := range findings {
			fmt.Fprintf(&executive, "- **%s — %s:** %s\n", finding.Severity, markdown(finding.Title), markdown(finding.Recommendation))
		}
	}

	var technical strings.Builder
	fmt.Fprintf(&technical, "# IPsec VPN Technical Assessment\n\n")
	fmt.Fprintf(&technical, "Analysis `%s`, generated `%s`.\n\n", markdown(input.AnalysisID), generatedAt.Format(time.RFC3339))
	if input.Assessment.PolicyID != "" {
		fmt.Fprintf(&technical, "Policy: **%s** (%s). Reference: %s. This is project-baseline compliance, not formal certification.\n\n", markdown(input.Assessment.PolicyLabel), markdown(input.Assessment.PolicyID), markdown(input.Assessment.PolicyReference))
	}
	technical.WriteString("## Fused conclusions\n\n")
	technical.WriteString("| Property | Value | Evidence status | Confidence | Source |\n|---|---|---|---:|---|\n")
	for _, conclusion := range conclusions {
		fmt.Fprintf(&technical, "| %s | %s | %s | %.3f | %s |\n", markdown(conclusion.Property), markdown(conclusion.Value), conclusion.Status.String(), conclusion.Confidence, conclusion.WinningSource)
	}
	technical.WriteString("\n## Findings and evidence\n\n")
	for _, finding := range findings {
		fmt.Fprintf(&technical, "### %s — %s\n\n", finding.RuleID, markdown(finding.Title))
		fmt.Fprintf(&technical, "- Severity: `%s`\n- Description: %s\n- Recommendation: %s\n- Evidence properties: `%s`\n\n", finding.Severity, markdown(finding.Description), markdown(finding.Recommendation), markdown(strings.Join(finding.EvidenceProperties, "`, `")))
	}
	technical.WriteString("## Policy controls\n\n")
	technical.WriteString("| Control | Area | Status | Affected resource | Supporting evidence |\n|---|---|---|---|---|\n")
	for _, control := range input.Assessment.Controls {
		refs := make([]string, 0, len(control.Evidence))
		for _, evidence := range control.Evidence {
			refs = append(refs, evidence.PropertyKey+"="+evidence.Value)
		}
		resource := strings.Trim(strings.TrimSpace(control.ResourceType+"/"+control.ResourceID), "/")
		fmt.Fprintf(&technical, "| %s | %s | %s | %s | %s |\n", markdown(control.ControlID), markdown(control.Area), control.Status, markdown(resource), markdown(strings.Join(refs, ", ")))
	}
	technical.WriteString("\n")
	technical.WriteString("## Interpretation limits\n\n")
	technical.WriteString("ESP payloads were not decrypted. UNKNOWN means the classifier abstained; it does not mean the flow is anomalous. ANOMALY is a separate experimental signal. Missing gateway evidence is reported as unavailable, not guessed.\n")

	return Output{ExecutiveMarkdown: executive.String(), TechnicalMarkdown: technical.String()}
}

func markdown(value string) string {
	replacer := strings.NewReplacer("|", "\\|", "`", "'", "\n", " ", "\r", " ")
	return replacer.Replace(strings.TrimSpace(value))
}
