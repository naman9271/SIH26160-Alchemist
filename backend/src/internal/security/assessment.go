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
	SALifetimeKnown                                              bool
	MetadataExposure, MetadataKnown                              bool
}

type Finding struct {
	RuleID, Title, Description, Recommendation string
	Severity                                   Severity
	EvidenceProperties                         []string
	ResourceType, ResourceID                   string
}

type Assessment struct {
	Score         int
	Grade         string
	Findings      []Finding
	ThreatMatrix  map[Severity]int
	EvaluatedRule int
	UnknownRule   int
	Coverage      int
	RuleResults   map[string]RuleResult
}

type RuleResult struct {
	Weight int
	Known  bool
	Failed bool
}

func Assess(facts Facts) Assessment {
	findings := make([]Finding, 0, 7)
	add := func(finding Finding) { findings = append(findings, finding) }
	score, evaluated, unknown := 0, 0, 0
	ruleResults := make(map[string]RuleResult, 8)
	check := func(known bool, weight int, failed bool, finding Finding) {
		ruleResults[finding.RuleID] = RuleResult{Weight: weight, Known: known, Failed: failed}
		if !known {
			unknown++
			return
		}
		evaluated++
		if failed {
			add(finding)
			return
		}
		score += weight
	}
	ike := strings.ToUpper(strings.TrimSpace(facts.IKEVersion))
	check(ike != "", 15, strings.HasPrefix(ike, "IKEV1"), Finding{RuleID: "IPSEC_IKE_001", Severity: SeverityMedium, Title: "Legacy IKEv1 in use", Description: "IKEv1 has a larger legacy attack surface than IKEv2.", Recommendation: "Migrate peers to IKEv2 after compatibility testing.", EvidenceProperties: []string{"ike.version"}})
	cipher := algorithmToken(facts.EncryptionAlgorithm)
	check(cipher != "", 25, weakCipher(cipher), Finding{RuleID: "IPSEC_CIPHER_001", Severity: SeverityHigh, Title: "Weak encryption algorithm", Description: "The negotiated encryption algorithm is obsolete or provides no confidentiality.", Recommendation: "Use AES-GCM or AES-256 with an approved integrity algorithm.", EvidenceProperties: []string{"child.encryption_algorithm"}})
	integrity := algorithmToken(facts.IntegrityAlgorithm)
	check(integrity != "", 10, weakIntegrity(integrity), Finding{RuleID: "IPSEC_INTEGRITY_001", Severity: SeverityHigh, Title: "Weak integrity algorithm", Description: "The negotiated integrity algorithm is deprecated for new deployments.", Recommendation: "Use SHA-256 or stronger, or an approved AEAD suite.", EvidenceProperties: []string{"child.integrity_algorithm"}})
	dh := algorithmToken(facts.DHGroup)
	check(dh != "", 15, weakDH(dh), Finding{RuleID: "IPSEC_DH_001", Severity: SeverityHigh, Title: "Weak Diffie-Hellman group", Description: "The negotiated DH group does not provide an acceptable modern security margin.", Recommendation: "Use MODP 2048 or an approved elliptic-curve group.", EvidenceProperties: []string{"ike.dh_group"}})
	check(facts.PFS != nil, 10, facts.PFS != nil && !*facts.PFS, Finding{RuleID: "IPSEC_PFS_001", Severity: SeverityMedium, Title: "Perfect Forward Secrecy disabled", Description: "CHILD SA keys are not protected by an additional ephemeral key exchange.", Recommendation: "Enable PFS with an approved DH group where peer compatibility permits.", EvidenceProperties: []string{"child.pfs"}})
	check(facts.ReplayProtection != nil, 10, facts.ReplayProtection != nil && !*facts.ReplayProtection, Finding{RuleID: "IPSEC_REPLAY_001", Severity: SeverityHigh, Title: "Replay protection disabled", Description: "The verified kernel or gateway policy does not enforce anti-replay protection.", Recommendation: "Enable an appropriate replay window and monitor sequence exhaustion.", EvidenceProperties: []string{"replay.enabled", "replay.window"}})
	check(facts.SALifetimeKnown, 10, facts.SALifetimeKnown && facts.SALifetimeSeconds > 86_400, Finding{RuleID: "IPSEC_LIFETIME_001", Severity: SeverityMedium, Title: "Excessive SA lifetime", Description: "A long SA lifetime increases exposure if key material is compromised.", Recommendation: "Apply an organization-approved rekey lifetime of no more than 24 hours.", EvidenceProperties: []string{"child.lifetime_seconds"}})
	check(facts.MetadataKnown, 5, facts.MetadataExposure, Finding{RuleID: "IPSEC_METADATA_001", Severity: SeverityLow, Title: "Observable traffic metadata", Description: "Outer endpoints, timing, direction and traffic volume remain visible despite ESP encryption.", Recommendation: "Document this residual exposure and use traffic-flow confidentiality controls only when required.", EvidenceProperties: []string{"metadata.exposure"}})
	sort.Slice(findings, func(i, j int) bool {
		if severityWeight(findings[i].Severity) != severityWeight(findings[j].Severity) {
			return severityWeight(findings[i].Severity) > severityWeight(findings[j].Severity)
		}
		return findings[i].RuleID < findings[j].RuleID
	})
	matrix := map[Severity]int{}
	for _, finding := range findings {
		matrix[finding.Severity]++
	}
	coverage := 0
	if evaluated+unknown > 0 {
		coverage = evaluated * 100 / (evaluated + unknown)
	}
	return Assessment{Score: score, Grade: grade(score), Findings: findings, ThreatMatrix: matrix, EvaluatedRule: evaluated, UnknownRule: unknown, Coverage: coverage, RuleResults: ruleResults}
}

func algorithmToken(value string) string {
	return strings.NewReplacer("-", "", "_", "", " ", "", "/", "").Replace(strings.ToUpper(strings.TrimSpace(value)))
}

func weakCipher(value string) bool {
	return oneOf(value, "DES", "DESCBC", "3DES", "3DESCBC", "NULL", "ENCR0", "ENCR2", "ENCR3", "IKEV1ENCR1", "IKEV1ENCR5")
}

func weakIntegrity(value string) bool {
	return oneOf(value, "MD5", "HMACMD5", "HMACMD596", "SHA1", "HMACSHA1", "HMACSHA196", "IKEV1HASH1", "IKEV1HASH2")
}

func weakDH(value string) bool {
	return oneOf(value, "DH1", "DH2", "DH5", "GROUP1", "GROUP2", "GROUP5", "MODP768", "MODP1024", "MODP1536", "GROUP1MODP768", "GROUP2MODP1024", "GROUP5MODP1536", "UNKNOWN41", "UNKNOWN42", "UNKNOWN45")
}

func oneOf(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if value == candidate {
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
