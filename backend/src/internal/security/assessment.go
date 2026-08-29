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
	if containsAny(dh, "MODP768", "MODP1024", "MODP1536", "GROUP1", "GROUP2", "GROUP5") {
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
	return Assessment{Score: score, Grade: grade(score), Findings: findings, ThreatMatrix: matrix, EvaluatedRule: 8}
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
