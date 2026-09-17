// Package security evaluates fused facts with deterministic, auditable rules.
package security

import (
	"sort"
	"strings"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

type Facts struct {
	IKEVersion, EncryptionAlgorithm, IntegrityAlgorithm, DHGroup string
	PFS, ReplayProtection                                        *bool
	SALifetimeSeconds                                            uint64
	MetadataExposure                                             bool
}

type Finding struct {
	RuleID, Title, Description, Recommendation string
	Severity                                   Severity
	EvidenceProperties                         []string
}

type Assessment struct {
	Score         int
	Grade         string
	Findings      []Finding
	ThreatMatrix  map[Severity]int
	EvaluatedRule int
	CoveragePercent int
	ScoreAvailable bool
	Controls []Control
}

type Control struct {
	RuleID string `json:"rule_id"`
	Property string `json:"property"`
	State string `json:"state"`
	Reason string `json:"reason"`
}

func Assess(facts Facts) Assessment {
	findings := make([]Finding, 0, 7)
	add := func(finding Finding) { findings = append(findings, finding) }
	ike := strings.ToUpper(strings.TrimSpace(facts.IKEVersion))
	if strings.HasPrefix(ike, "IKEV1") {
		add(Finding{RuleID: "IPSEC_IKE_001", Severity: SeverityMedium, Title: "Legacy IKEv1 in use", Description: "IKEv1 has a larger legacy attack surface than IKEv2.", Recommendation: "Migrate peers to IKEv2 after compatibility testing.", EvidenceProperties: []string{"ike.version"}})
	}
	cipher := strings.ToUpper(facts.EncryptionAlgorithm)
	if strings.Contains(cipher, "3DES") || strings.Contains(cipher, "DES") || strings.Contains(cipher, "NULL") {
		add(Finding{RuleID: "IPSEC_CIPHER_001", Severity: SeverityHigh, Title: "Weak encryption algorithm", Description: "The negotiated encryption algorithm is obsolete or provides no confidentiality.", Recommendation: "Use AES-GCM or AES-256 with an approved integrity algorithm.", EvidenceProperties: []string{"child.encryption_algorithm"}})
	}
	integrity := strings.ToUpper(facts.IntegrityAlgorithm)
	if strings.Contains(integrity, "MD5") || strings.Contains(integrity, "SHA1") || strings.Contains(integrity, "SHA-1") {
		add(Finding{RuleID: "IPSEC_INTEGRITY_001", Severity: SeverityHigh, Title: "Weak integrity algorithm", Description: "The negotiated integrity algorithm is deprecated for new deployments.", Recommendation: "Use SHA-256 or stronger, or an approved AEAD suite.", EvidenceProperties: []string{"child.integrity_algorithm"}})
	}
	dh := strings.ToUpper(facts.DHGroup)
	if containsAny(dh, "MODP768", "MODP1024", "MODP1536", "MODP_768", "MODP_1024", "MODP_1536") || dh == "GROUP1" || dh == "GROUP2" || dh == "GROUP5" || strings.HasPrefix(dh, "GROUP1-") || strings.HasPrefix(dh, "GROUP2-") || strings.HasPrefix(dh, "GROUP5-") {
		add(Finding{RuleID: "IPSEC_DH_001", Severity: SeverityHigh, Title: "Weak Diffie-Hellman group", Description: "The negotiated DH group does not provide an acceptable modern security margin.", Recommendation: "Use MODP 2048 or an approved elliptic-curve group.", EvidenceProperties: []string{"ike.dh_group"}})
	}
	if facts.PFS != nil && !*facts.PFS {
		add(Finding{RuleID: "IPSEC_PFS_001", Severity: SeverityMedium, Title: "Perfect Forward Secrecy disabled", Description: "CHILD SA keys are not protected by an additional ephemeral key exchange.", Recommendation: "Enable PFS with an approved DH group where peer compatibility permits.", EvidenceProperties: []string{"child.pfs"}})
	}
	if facts.ReplayProtection != nil && !*facts.ReplayProtection {
		add(Finding{RuleID: "IPSEC_REPLAY_001", Severity: SeverityHigh, Title: "Replay protection disabled", Description: "The verified kernel or gateway policy does not enforce anti-replay protection.", Recommendation: "Enable an appropriate replay window and monitor sequence exhaustion.", EvidenceProperties: []string{"replay.enabled", "replay.window"}})
	}
	if facts.SALifetimeSeconds > 86_400 {
		add(Finding{RuleID: "IPSEC_LIFETIME_001", Severity: SeverityMedium, Title: "Excessive SA lifetime", Description: "A long SA lifetime increases exposure if key material is compromised.", Recommendation: "Apply an organization-approved rekey lifetime of no more than 24 hours.", EvidenceProperties: []string{"child.lifetime_seconds"}})
	}
	if facts.MetadataExposure {
		add(Finding{RuleID: "IPSEC_METADATA_001", Severity: SeverityLow, Title: "Observable traffic metadata", Description: "Outer endpoints, timing, direction and traffic volume remain visible despite ESP encryption.", Recommendation: "Document this residual exposure and use traffic-flow confidentiality controls only when required.", EvidenceProperties: []string{"metadata.exposure"}})
	}
	sort.Slice(findings, func(i, j int) bool {
		if severityWeight(findings[i].Severity) != severityWeight(findings[j].Severity) {
			return severityWeight(findings[i].Severity) > severityWeight(findings[j].Severity)
		}
		return findings[i].RuleID < findings[j].RuleID
	})
	score := 100
	matrix := map[Severity]int{}
	for _, finding := range findings {
		score -= severityWeight(finding.Severity)
		matrix[finding.Severity]++
	}
	if score < 0 {
		score = 0
	}
	checks := []struct{ id, property string; known bool }{
		{"IPSEC_IKE_001", "ike.version", strings.HasPrefix(ike, "IKEV1") || strings.HasPrefix(ike, "IKEV2")},
		{"IPSEC_CIPHER_001", "child.encryption_algorithm", knownAlgorithm(cipher)},
		{"IPSEC_INTEGRITY_001", "child.integrity_algorithm", knownAlgorithm(integrity)},
		{"IPSEC_DH_001", "ike.dh_group", knownAlgorithm(dh)},
		{"IPSEC_PFS_001", "child.pfs", facts.PFS != nil},
		{"IPSEC_REPLAY_001", "replay.enabled", facts.ReplayProtection != nil},
		{"IPSEC_LIFETIME_001", "child.lifetime_seconds", facts.SALifetimeSeconds > 0},
		{"IPSEC_METADATA_001", "metadata.exposure", facts.MetadataExposure},
	}
	controls := make([]Control, 0, len(checks))
	evaluated := 0
	for _, check := range checks {
		control := Control{RuleID: check.id, Property: check.property, State: "NOT_EVALUATED", Reason: "Required evidence is unavailable or unrecognized"}
		if check.known { evaluated++; control.State = "PASS"; control.Reason = "Available evidence passed this baseline check" }
		for _, finding := range findings { if finding.RuleID == check.id { control.State = "FAIL"; control.Reason = finding.Description } }
		controls = append(controls, control)
	}
	label := grade(score)
	if evaluated == 0 { score = 0; label = "N/A" } else if evaluated < len(checks) { label = "PROVISIONAL" }
	return Assessment{Score: score, Grade: label, Findings: findings, ThreatMatrix: matrix, EvaluatedRule: evaluated, CoveragePercent: evaluated*100/len(checks), ScoreAvailable: evaluated > 0, Controls: controls}
}

func knownAlgorithm(s string) bool {
	if s == "" || strings.Contains(s,"UNKNOWN") { return false }
	return containsAny(s,"AES", "AEAD", "CHACHA20", "SHA", "MD5", "3DES", "MODP", "ECP", "CURVE25519", "CURVE448") || s=="DES" || s=="NULL" || s=="GROUP1" || s=="GROUP2" || s=="GROUP5"
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

func severityWeight(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 25
	case SeverityHigh:
		return 15
	case SeverityMedium:
		return 8
	default:
		return 3
	}
}

func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}
