package report

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	fusionv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/fusion"
	mlv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/ml"
	riskv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/risk"
	coreanalysis "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/analysis"
	coreinput "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/input"
	rules "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/security"
)

// reportDocument is the stable presentation model between analysis data and
// PDF layout. It deliberately contains prose and table cells, never raw JSON.
type reportDocument struct {
	Title, Subtitle, AnalysisID, AnalysisType, InputInfo string
	GeneratedAt                                          time.Time
	Sections                                             []reportSection
}

type reportSection struct {
	Title      string
	Paragraphs []string
	Tables     []reportTable
	Items      []reportItem
}

type reportTable struct {
	Headers []string
	Rows    [][]string
	Widths  []int
}

type reportItem struct {
	Heading, Body string
}

func buildReportDocument(record coreanalysis.Record, source *coreinput.Source, conclusions []*fusionv1.FusedConclusion, payload map[string]interface{}, generatedAt time.Time) reportDocument {
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	mode := analysisMode(record.Mode.String())
	document := reportDocument{
		Title: "Alchemist IPSEC VPN AI Analyser", Subtitle: "IPSEC VPN Traffic & AI Analysis Report",
		AnalysisID: record.ID, AnalysisType: mode, GeneratedAt: generatedAt.UTC(), InputInfo: "Input metadata unavailable",
	}
	if source != nil {
		document.InputInfo = sourceDescription(*source)
	}

	assessment, hasAssessment := payload["security_assessment"].(rules.Assessment)
	riskScore, _ := payload["risk_score"].(*riskv1.SecurityScore)
	predictions, _ := payload["ml_predictions"].([]*mlv1.TrafficPrediction)
	protocol := filterConclusions(conclusions, isProtocolProperty)
	traffic := filterConclusions(conclusions, isTrafficProperty)

	executive := reportSection{Title: "Executive Summary"}
	executive.Paragraphs = append(executive.Paragraphs, fmt.Sprintf("The %s analysis completed with %d fused conclusions from the evidence available to the system.", strings.ToLower(mode), len(conclusions)))
	if hasAssessment {
		riskLevel := "not calculated"
		confidence := "not calculated"
		unknown := payloadUint64(payload, "unknown_evidence_count")
		if riskScore != nil {
			riskLevel = strings.ToLower(riskScore.GetRiskLevel())
			confidence = formatPercent(riskScore.GetConfidence())
		}
		executive.Paragraphs = append(executive.Paragraphs, fmt.Sprintf("The deterministic security assessment scored the supported evidence %d out of 100 (grade %s), with %s risk and %s assessment confidence. %d evidence items remained unknown.", assessment.Score, assessment.Grade, riskLevel, confidence, unknown))
		if len(assessment.Findings) == 0 {
			executive.Paragraphs = append(executive.Paragraphs, "No deterministic rule finding was raised from the evidence that could be evaluated. This is not proof that unavailable or unknown evidence is safe.")
		} else {
			executive.Paragraphs = append(executive.Paragraphs, fmt.Sprintf("The assessment produced %d supported finding(s). The highest-priority items are listed in Security Findings and Recommendations.", len(assessment.Findings)))
		}
	} else {
		executive.Paragraphs = append(executive.Paragraphs, "A completed deterministic security assessment was not available, so this report does not assign a security result.")
	}
	executive.Paragraphs = append(executive.Paragraphs, "ESP payloads were not decrypted. Traffic classifications, when present, are metadata-based estimates and not protocol facts.")
	document.Sections = append(document.Sections, executive)

	overviewRows := [][]string{
		{"Analysis type", mode},
		{"Analysis state", humanValue(record.State.String())},
		{"Final stage", humanValue(record.Stage.String())},
		{"Started", formatTime(record.CreatedAt)},
		{"Completed / updated", formatTime(record.UpdatedAt)},
		{"Duration", formatDuration(record.UpdatedAt.Sub(record.CreatedAt))},
		{"Fused conclusions", strconv.Itoa(len(conclusions))},
	}
	if source != nil {
		overviewRows = append(overviewRows,
			[]string{"Input", sourceDescription(*source)},
			[]string{"Packets analysed", formatUint(source.Counters.PacketsTotal)},
			[]string{"Traffic volume", formatBytes(source.Counters.BytesTotal)},
		)
		if source.Size > 0 {
			overviewRows = append(overviewRows, []string{"Input size", formatBytes(source.Size)})
		}
	}
	document.Sections = append(document.Sections, reportSection{Title: "Analysis Overview", Tables: []reportTable{{Headers: []string{"Metric", "Value"}, Rows: overviewRows, Widths: []int{28, 66}}}})

	if source != nil || len(traffic) > 0 {
		trafficRows := [][]string{}
		if source != nil {
			trafficRows = append(trafficRows,
				[]string{"Packets", formatUint(source.Counters.PacketsTotal)},
				[]string{"Bytes", formatBytes(source.Counters.BytesTotal)},
				[]string{"IKE packets", formatUint(source.Counters.IKEPackets)},
				[]string{"ESP packets", formatUint(source.Counters.ESPPackets)},
				[]string{"AH packets", formatUint(source.Counters.AHPackets)},
				[]string{"NAT-T packets", formatUint(source.Counters.NATTPackets)},
				[]string{"Packet drops", formatUint(source.Counters.PacketDrops)},
			)
		}
		for _, conclusion := range traffic {
			trafficRows = append(trafficRows, []string{humanLabel(conclusion.GetPropertyKey()), humanValue(conclusion.GetValue())})
		}
		document.Sections = append(document.Sections, reportSection{Title: "Traffic Analysis", Paragraphs: []string{"These values describe observable packet and flow metadata. They do not reveal encrypted ESP payload content."}, Tables: []reportTable{{Headers: []string{"Traffic metric", "Observed value"}, Rows: uniqueRows(trafficRows), Widths: []int{42, 52}}}})
	}

	if len(protocol) > 0 {
		document.Sections = append(document.Sections, reportSection{Title: "IPSEC / VPN Analysis", Paragraphs: []string{"The table presents the winning IPsec-related conclusions selected by Fusion from the available sources."}, Tables: []reportTable{conclusionTable(protocol)}})
	}

	if record.Mode.String() != "DEEP_ASSESSMENT" {
		passive := reportSection{Title: "Passive Analysis", Paragraphs: []string{"Observed information: packet headers and IPsec metadata were collected without decrypting ESP payloads."}}
		if source != nil {
			passive.Paragraphs = append(passive.Paragraphs, fmt.Sprintf("The source contained %s packets, including %s ESP, %s IKE, %s AH, and %s NAT-T packets.", formatUint(source.Counters.PacketsTotal), formatUint(source.Counters.ESPPackets), formatUint(source.Counters.IKEPackets), formatUint(source.Counters.AHPackets), formatUint(source.Counters.NATTPackets)))
		}
		passive.Paragraphs = append(passive.Paragraphs, "Interpretation: conclusions are limited to what the capture exposed. Missing gateway state remains unknown and is not treated as a passing security check.")
		document.Sections = append(document.Sections, passive)
	}

	if record.Mode.String() == "DEEP_ASSESSMENT" {
		document.Sections = append(document.Sections, reportSection{Title: "Deep Analysis", Paragraphs: []string{"This authorized assessment combined passive capture evidence with read-only gateway evidence requested through StrongSwan VICI and Linux XFRM. Only gateway facts that reached Fusion are reported as verified; an unavailable source is not guessed.", fmt.Sprintf("Fusion produced %d supported conclusion(s) for this analysis. Review the evidence appendix to see the status and winning source for each fact.", len(conclusions))}})
	}

	if record.Mode.String() == "PASSIVE_LIVE" || record.Mode.String() == "DEEP_ASSESSMENT" {
		rows := [][]string{{"Capture source", document.InputInfo}}
		if source != nil {
			rows = append(rows, []string{"Capture ID", fallback(source.CaptureID, "Not recorded")}, []string{"Packets captured", formatUint(source.Counters.PacketsTotal)}, []string{"Packet drops", formatUint(source.Counters.PacketDrops)})
		}
		document.Sections = append(document.Sections, reportSection{Title: "Live Capture", Paragraphs: []string{"The live source was stopped before analysis and then processed through the same evidence, Fusion, security, risk, and optional ML pipeline as an uploaded capture."}, Tables: []reportTable{{Headers: []string{"Capture detail", "Value"}, Rows: rows, Widths: []int{28, 66}}}})
	}

	if len(predictions) > 0 {
		document.Sections = append(document.Sections, classificationSection(predictions))
	}

	if hasAssessment {
		findings := reportSection{Title: "Security Findings"}
		if len(assessment.Findings) == 0 {
			findings.Paragraphs = []string{"No supported deterministic security finding was produced from the available evidence. Unknown or unavailable evidence still requires review."}
		} else {
			for _, finding := range assessment.Findings {
				findings.Items = append(findings.Items, reportItem{Heading: fmt.Sprintf("%s - %s (%s)", finding.Severity, finding.Title, finding.RuleID), Body: finding.Description})
			}
		}
		document.Sections = append(document.Sections, findings)
		if len(assessment.Findings) > 0 {
			recommendations := reportSection{Title: "Recommendations", Paragraphs: []string{"Actions below are derived directly from supported deterministic findings and are ordered by severity."}}
			for _, finding := range assessment.Findings {
				recommendations.Items = append(recommendations.Items, reportItem{Heading: fmt.Sprintf("%s priority - %s", finding.Severity, finding.Title), Body: finding.Recommendation})
			}
			document.Sections = append(document.Sections, recommendations)
		}
	}

	conclusion := reportSection{Title: "Conclusion"}
	if hasAssessment {
		conclusion.Paragraphs = []string{fmt.Sprintf("This analysis completed with a security score of %d/100 and %d supported finding(s). Use the recommendations as the next actions, while treating all unknown or unavailable evidence as unresolved rather than safe.", assessment.Score, len(assessment.Findings))}
	} else {
		conclusion.Paragraphs = []string{"The analysis completed, but no security assessment was available. Review collection coverage and repeat the analysis before making a security decision."}
	}
	document.Sections = append(document.Sections, conclusion)

	if len(conclusions) > 0 {
		document.Sections = append(document.Sections, reportSection{Title: "Appendix: Evidence Conclusions", Paragraphs: []string{"This technical appendix lists Fusion's winning conclusions. Status identifies whether a fact was observed, derived, inferred, gateway-verified, or unknown."}, Tables: []reportTable{conclusionTable(conclusions)}})
	}
	return document
}

func classificationSection(predictions []*mlv1.TrafficPrediction) reportSection {
	type aggregate struct {
		count      int
		confidence float64
	}
	byClass := map[string]aggregate{}
	for _, prediction := range predictions {
		if prediction == nil {
			continue
		}
		name := humanValue(prediction.GetTrafficClass())
		if prediction.GetIsUnknown() {
			name = "Unknown"
		}
		item := byClass[name]
		item.count++
		item.confidence += prediction.GetConfidence()
		byClass[name] = item
	}
	names := make([]string, 0, len(byClass))
	for name := range byClass {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([][]string, 0, len(names))
	for _, name := range names {
		item := byClass[name]
		rows = append(rows, []string{name, strconv.Itoa(item.count), formatPercent(float64(item.count) / float64(len(predictions))), formatPercent(item.confidence / float64(item.count))})
	}
	return reportSection{Title: "Traffic Classification", Paragraphs: []string{"These results are ML inferences from encrypted-flow metadata. UNKNOWN is a deliberate low-confidence abstention, not an anomaly or security finding."}, Tables: []reportTable{{Headers: []string{"Classification", "Count", "Share", "Avg confidence"}, Rows: rows, Widths: []int{44, 10, 16, 20}}}}
}

func conclusionTable(conclusions []*fusionv1.FusedConclusion) reportTable {
	rows := make([][]string, 0, len(conclusions))
	for _, conclusion := range conclusions {
		if conclusion == nil {
			continue
		}
		status := evidenceStatus(conclusion.GetEvidenceStatus())
		sources := strings.Join(conclusion.GetWinningSources(), ", ")
		rows = append(rows, []string{humanLabel(conclusion.GetPropertyKey()), humanValue(conclusion.GetValue()), status, formatPercent(conclusion.GetConfidence()), fallback(sources, "Not recorded")})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i][0] < rows[j][0] })
	return reportTable{Headers: []string{"Property", "Value", "Status", "Confidence", "Winning source"}, Rows: rows, Widths: []int{25, 24, 13, 12, 20}}
}

func filterConclusions(values []*fusionv1.FusedConclusion, match func(string) bool) []*fusionv1.FusedConclusion {
	out := make([]*fusionv1.FusedConclusion, 0)
	for _, value := range values {
		if value != nil && match(strings.ToLower(value.GetPropertyKey())) {
			out = append(out, value)
		}
	}
	return out
}

func isProtocolProperty(key string) bool {
	for _, prefix := range []string{"ike.", "child.", "esp.", "ah.", "nat_", "nat.", "sa.", "session."} {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}
func isTrafficProperty(key string) bool {
	return strings.HasPrefix(key, "traffic.") || strings.HasPrefix(key, "flow.")
}

func analysisMode(value string) string {
	switch value {
	case "PASSIVE_PCAP", "OFFLINE_PCAP":
		return "Passive PCAP"
	case "PASSIVE_LIVE":
		return "Passive Live Capture"
	case "DEEP_ASSESSMENT":
		return "Authorized Deep Assessment"
	default:
		return humanValue(value)
	}
}

func sourceDescription(source coreinput.Source) string {
	if source.Filename != "" {
		return fmt.Sprintf("PCAP file %s", source.Filename)
	}
	if source.CaptureID != "" {
		return fmt.Sprintf("Live capture %s", source.CaptureID)
	}
	return fmt.Sprintf("Source %s", source.ID)
}

func humanLabel(value string) string {
	parts := strings.Fields(strings.NewReplacer(".", " ", "_", " ", "-", " ").Replace(value))
	for index, part := range parts {
		switch strings.ToLower(part) {
		case "ike":
			parts[index] = "IKE"
		case "ipsec":
			parts[index] = "IPSEC"
		case "esp":
			parts[index] = "ESP"
		case "ah":
			parts[index] = "AH"
		case "nat":
			parts[index] = "NAT"
		case "pfs":
			parts[index] = "PFS"
		case "sa":
			parts[index] = "SA"
		default:
			parts[index] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
		}
	}
	return strings.Join(parts, " ")
}

func humanValue(value string) string {
	value = strings.TrimSpace(value)
	for _, prefix := range []string{"ANALYSIS_STATE_", "ASSESSMENT_STATE_", "TRAFFIC_CLASS_", "EVIDENCE_STATUS_", "INPUT_STATE_"} {
		value = strings.TrimPrefix(value, prefix)
	}
	if value == "" {
		return "Not recorded"
	}
	return humanLabel(value)
}

func evidenceStatus(value commonv1.EvidenceStatus) string {
	if value == commonv1.EvidenceStatus_EVIDENCE_STATUS_UNSPECIFIED {
		return "Not recorded"
	}
	return humanValue(value.String())
}

func payloadUint64(payload map[string]interface{}, key string) uint64 {
	switch value := payload[key].(type) {
	case uint64:
		return value
	case uint32:
		return uint64(value)
	case int:
		if value > 0 {
			return uint64(value)
		}
	}
	return 0
}

func uniqueRows(rows [][]string) [][]string {
	seen := map[string]bool{}
	out := make([][]string, 0, len(rows))
	for _, row := range rows {
		key := strings.Join(row, "\x00")
		if !seen[key] {
			seen[key] = true
			out = append(out, row)
		}
	}
	return out
}

func fallback(value, replacement string) string {
	if strings.TrimSpace(value) == "" {
		return replacement
	}
	return value
}
func formatPercent(value float64) string { return fmt.Sprintf("%.1f%%", value*100) }
func formatTime(value time.Time) string {
	if value.IsZero() {
		return "Not recorded"
	}
	return value.UTC().Format("02 Jan 2006, 15:04:05 UTC")
}
func formatDuration(value time.Duration) string {
	if value < 0 {
		return "Not recorded"
	}
	if value < time.Second {
		return value.Round(time.Millisecond).String()
	}
	return value.Round(time.Second).String()
}
func formatUint(value uint64) string { return strconv.FormatUint(value, 10) }
func formatBytes(value uint64) string {
	if value == 0 {
		return "0 bytes"
	}
	units := []string{"bytes", "KiB", "MiB", "GiB"}
	size, unit := float64(value), 0
	for size >= 1024 && unit < len(units)-1 {
		size /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%d %s", value, units[unit])
	}
	return fmt.Sprintf("%.2f %s", size, units[unit])
}
