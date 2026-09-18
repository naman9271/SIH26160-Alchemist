// Package security evaluates normalized IPsec facts with an auditable policy.
package security

import (
	"sort"
	"strconv"
	"strings"
)

const (
	SIHBaselinePolicyID    = "sih-baseline-v1"
	SIHBaselinePolicyLabel = "SIH baseline compliance"
	SIHBaselineReference   = "RFC 8221; RFC 8247; RFC 9395; SIH project lifecycle limits"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

type ControlStatus string

const (
	ControlPass          ControlStatus = "PASS"
	ControlFail          ControlStatus = "FAIL"
	ControlUnknown       ControlStatus = "UNKNOWN"
	ControlNotApplicable ControlStatus = "NOT_APPLICABLE"
)

// EvidenceReference deliberately contains only sanitized fused facts.
type EvidenceReference struct {
	PropertyKey, Value   string
	EvidenceIDs, Sources []string
}

type Facts struct {
	ResourceType                                                              string
	IKEVersion, IKEEncryption, IKEIntegrity, IKEAuthentication, DHGroup       string
	ConfiguredIKEProposals, ConfiguredChildProposals                          string
	IKEEncryptionKeyBits, IKEAEADTagBits                                      uint64
	IKEEncryptionKeyKnown, IKEAEADTagKnown                                    bool
	IKELifetimeSeconds                                                        uint64
	IKELifetimeKnown                                                          bool
	EncryptionAlgorithm, IntegrityAlgorithm                                   string
	EncryptionKeyBits, AEADTagBits                                            uint64
	EncryptionKeyKnown, AEADTagKnown                                          bool
	Mode, Protocol, State, Direction                                          string
	SelectorsKnown, ConfigurationRuntimeKnown, ConfigurationRuntimeConsistent bool
	PFS, FreshExchangeObserved, ReplayProtection, ReplayESN                   *bool
	ReplayWindow                                                              uint64
	ReplayWindowKnown                                                         bool
	SALifetimeSeconds                                                         uint64
	SALifetimeKnown                                                           bool
	InstallAgeSeconds, RemainingExpirySeconds                                 uint64
	InstallAgeKnown, RemainingExpiryKnown                                     bool
	MetadataExposure, MetadataKnown                                           bool
	MetadataProtectionRequired                                                *bool
	Evidence                                                                  map[string]EvidenceReference
}

type Finding struct {
	RuleID, Title, Description, Recommendation          string
	Severity                                            Severity
	EvidenceProperties                                  []string
	Evidence                                            []EvidenceReference
	ResourceType, ResourceID, PolicyID, PolicyReference string
}

// ThreatEntry describes a supported exposure for one affected resource. It is
// deliberately not an exploitation claim: the evidence establishes a weak
// configuration or observable metadata, not that an attacker used it.
type ThreatEntry struct {
	Threat, ControlID, Status, Impact, Recommendation string
	Severity                                          Severity
	ResourceType, ResourceID                          string
	Evidence                                          []EvidenceReference
}
type ControlResult struct {
	ControlID, Category, Area, Title string
	Status                           ControlStatus
	Severity                         Severity
	Explanation, Remediation         string
	ResourceType, ResourceID         string
	EvidenceProperties               []string
	Evidence                         []EvidenceReference
	PolicyID, PolicyReference        string
	Weight                           float64
}
type RuleResult struct {
	Weight        float64
	Known, Failed bool
	Status        ControlStatus
}
type Assessment struct {
	PolicyID, PolicyLabel, PolicyReference string
	ResourceType, ResourceID               string
	// Score is populated only when at least one control was evaluated. Its
	// validity is carried by ScoreAvailable so zero never means "secure".
	Score                                                  float64
	ScoreAvailable                                         bool
	Grade                                                  string
	Findings                                               []Finding
	ThreatEntries                                          []ThreatEntry
	Controls                                               []ControlResult
	ThreatMatrix                                           map[Severity]int
	EvaluatedRule, UnknownRule, NotApplicableRule          int
	Coverage                                               float64
	CoverageAvailable, Provisional                         bool
	SecurityLowerBound, SecurityUpperBound                 float64
	BoundsAvailable, CriticalFailure, ScoreCapped          bool
	PassedWeight, FailedWeight, UnknownWeight, TotalWeight float64
	RuleResults                                            map[string]RuleResult
}
type controlDefinition struct {
	id, category, area, title, explanation, remediation string
	severity                                            Severity
	properties                                          []string
	evaluate                                            func(Facts) ControlStatus
}

const (
	categoryCryptography    = "Cryptography and suite strength"
	categoryAuthentication  = "Peer authentication"
	categoryKeyExchange     = "IKE version and key exchange"
	categoryPFS             = "Forward secrecy"
	categoryReplay          = "Replay protection"
	categoryLifecycle       = "Lifecycle"
	categorySAConfiguration = "SA configuration"
	categoryMetadata        = "Metadata exposure"
)

var categoryWeights = map[string]float64{categoryCryptography: 25, categoryAuthentication: 15, categoryKeyExchange: 15, categoryPFS: 10, categoryReplay: 10, categoryLifecycle: 10, categorySAConfiguration: 10, categoryMetadata: 5}

var baselineControls = []controlDefinition{
	{"SIH_IKE_VERSION_001", categoryKeyExchange, "Configuration compliance", "IKEv2 required", "The project baseline requires IKEv2; IKEv1 remains available for legacy analysis.", "Migrate the peer configuration to IKEv2.", SeverityMedium, []string{"ike.version"}, assessIKEVersion},
	{"SIH_IKE_SUITE_001", categoryCryptography, "Cipher-suite strength", "IKE cryptographic suite", "The complete IKE suite does not meet the baseline.", "Use AES-128/256-GCM, or AES-128/256-CBC with HMAC-SHA-256/384/512.", SeverityHigh, []string{"ike.encryption", "ike.encryption_key_length_bits", "ike.integrity", "ike.aead_tag_length_bits"}, assessIKESuite},
	{"SIH_CHILD_SUITE_001", categoryCryptography, "Cipher-suite strength", "CHILD SA cryptographic suite", "The complete ESP/AH suite does not meet the baseline.", "Use AES-128/256-GCM, or AES-128/256-CBC with HMAC-SHA-256/384/512.", SeverityHigh, []string{"child.encryption_algorithm", "child.encryption_key_length_bits", "child.integrity_algorithm", "child.aead_tag_length_bits"}, assessChildSuite},
	{"SIH_AUTH_001", categoryAuthentication, "Configuration compliance", "Authentication configuration", "The authentication method is absent, unsupported, or unsafe. Method presence does not establish PSK entropy or certificate trust.", "Use an explicitly approved PSK, certificate, signature, or EAP configuration and validate credentials separately.", SeverityHigh, []string{"ike.authentication_methods", "config.ike.authentication_class"}, assessAuthentication},
	{"SIH_IKE_POLICY_001", categoryCryptography, "Configuration compliance", "Configured IKE proposal allowlist", "One or more configured IKE proposals are weak or outside the explicit project allowlist.", "Restrict configured IKE proposals to approved AES, HMAC, PRF, and DH combinations.", SeverityHigh, []string{"config.ike.proposals"}, func(f Facts) ControlStatus { return assessConfiguredProposals(f.ConfiguredIKEProposals, true) }},
	{"SIH_CHILD_POLICY_001", categoryCryptography, "Configuration compliance", "Configured CHILD proposal allowlist", "One or more configured ESP/AH proposals are weak or outside the explicit project allowlist.", "Restrict configured CHILD proposals to AES-GCM or AES-CBC with HMAC-SHA-256/384/512 and approved PFS groups.", SeverityHigh, []string{"config.child.proposals"}, func(f Facts) ControlStatus { return assessConfiguredProposals(f.ConfiguredChildProposals, false) }},
	{"SIH_DH_001", categoryKeyExchange, "Cryptographic strength", "Approved Diffie-Hellman group", "The key-exchange group does not meet the baseline.", "Use group 14-21 or 31. Keep unrecognized identifiers unsupported until policy is updated.", SeverityHigh, []string{"ike.dh_group"}, assessDH},
	{"SIH_SA_PARAMETERS_001", categorySAConfiguration, "SA parameters", "Installed SA parameters", "Mode, protocol, selectors, state, direction, or configured/runtime consistency is incomplete or inconsistent.", "Align configured policy with installed state and verify both selector directions.", SeverityMedium, []string{"child.mode", "child.protocol", "child.state", "xfrm.direction", "child.local_traffic_selectors", "child.remote_traffic_selectors", "sa.configuration_runtime_consistent"}, assessSAParameters},
	{"SIH_IKE_LIFETIME_001", categoryLifecycle, "Key lifetime", "IKE SA lifetime", "The configured IKE lifetime exceeds the 24-hour project limit.", "Configure IKE rekey or expiry at no more than 24 hours.", SeverityMedium, []string{"ike.lifetime_seconds"}, assessIKELifetime},
	{"SIH_CHILD_LIFETIME_001", categoryLifecycle, "Key lifetime", "CHILD SA lifetime", "The configured CHILD lifetime exceeds the one-hour project limit.", "Configure CHILD rekey or expiry at no more than one hour.", SeverityMedium, []string{"child.lifetime_seconds", "child.install_age_seconds", "child.remaining_lifetime_seconds"}, assessChildLifetime},
	{"SIH_REPLAY_001", categoryReplay, "Replay protection", "Inbound anti-replay protection", "Verified inbound runtime state does not enforce an anti-replay window.", "Enable inbound anti-replay protection and monitor sequence limits; enable ESN where volume requires it.", SeverityHigh, []string{"replay.enabled", "replay.window", "replay.extended_sequence_numbers", "replay.sequence", "xfrm.direction"}, assessReplay},
	{"SIH_PFS_CONFIG_001", categoryPFS, "Forward secrecy", "Perfect Forward Secrecy configuration", "The configured CHILD policy does not request a fresh approved key exchange on rekey.", "Configure CHILD PFS with an approved group.", SeverityMedium, []string{"child.pfs", "child.pfs_group", "config.child.pfs_enabled"}, assessPFS},
	{"SIH_PFS_EXCHANGE_001", categoryPFS, "Forward secrecy", "Observed fresh CHILD key exchange", "A creation or rekey event was observed without evidence of a fresh key exchange.", "Verify the negotiated CHILD SA includes the configured PFS exchange.", SeverityMedium, []string{"child.fresh_exchange_observed", "child.exchange_dh_group"}, assessFreshExchange},
	{"SIH_METADATA_001", categoryMetadata, "Metadata exposure", "Observable IPsec metadata", "Outer endpoints, timing, packet sizes, volume, direction and possibly identities remain observable.", "Document residual exposure and apply traffic-flow confidentiality or identity protection where an explicit deployment requirement calls for it.", SeverityLow, []string{"metadata.exposure", "policy.metadata_protection_required"}, assessMetadata},
}

func Assess(f Facts) Assessment {
	r := Assessment{PolicyID: SIHBaselinePolicyID, PolicyLabel: SIHBaselinePolicyLabel, PolicyReference: SIHBaselineReference, ThreatMatrix: map[Severity]int{}, RuleResults: map[string]RuleResult{}}
	applicable := map[string][]int{}
	for _, d := range baselineControls {
		status := d.evaluate(f)
		evidence := evidenceFor(f, d.properties)
		severity := d.severity
		critical := status == ControlFail && isCriticalFailure(d.id, f)
		if critical {
			severity = SeverityCritical
			r.CriticalFailure = true
		}
		c := ControlResult{ControlID: d.id, Category: d.category, Area: d.area, Title: d.title, Status: status, Severity: severity, Explanation: d.explanation, Remediation: d.remediation, ResourceType: f.ResourceType, EvidenceProperties: append([]string(nil), d.properties...), Evidence: evidence, PolicyID: SIHBaselinePolicyID, PolicyReference: SIHBaselineReference}
		r.Controls = append(r.Controls, c)
		if status != ControlNotApplicable {
			applicable[d.category] = append(applicable[d.category], len(r.Controls)-1)
		}
	}
	for category, indices := range applicable {
		weight := categoryWeights[category] / float64(len(indices))
		for _, index := range indices {
			r.Controls[index].Weight = weight
		}
	}
	for _, c := range r.Controls {
		r.RuleResults[c.ControlID] = RuleResult{Weight: c.Weight, Status: c.Status, Known: c.Status == ControlPass || c.Status == ControlFail, Failed: c.Status == ControlFail}
		switch c.Status {
		case ControlPass:
			r.EvaluatedRule++
			r.PassedWeight += c.Weight
		case ControlFail:
			r.EvaluatedRule++
			r.FailedWeight += c.Weight
			r.ThreatMatrix[c.Severity]++
			r.Findings = append(r.Findings, Finding{RuleID: c.ControlID, Title: c.Title, Description: c.Explanation, Recommendation: c.Remediation, Severity: c.Severity, EvidenceProperties: c.EvidenceProperties, Evidence: c.Evidence, ResourceType: f.ResourceType, PolicyID: SIHBaselinePolicyID, PolicyReference: SIHBaselineReference})
		case ControlNotApplicable:
			r.NotApplicableRule++
		default:
			r.UnknownRule++
			r.UnknownWeight += c.Weight
		}
	}
	r.ThreatEntries = actionableThreats(f, r.Controls)
	sort.Slice(r.Findings, func(i, j int) bool {
		if severityWeight(r.Findings[i].Severity) != severityWeight(r.Findings[j].Severity) {
			return severityWeight(r.Findings[i].Severity) > severityWeight(r.Findings[j].Severity)
		}
		return r.Findings[i].RuleID < r.Findings[j].RuleID
	})
	r.TotalWeight = r.PassedWeight + r.FailedWeight + r.UnknownWeight
	if r.TotalWeight > 0 {
		r.CoverageAvailable = true
		r.Coverage = 100 * (r.PassedWeight + r.FailedWeight) / r.TotalWeight
		r.SecurityLowerBound = 100 * r.PassedWeight / r.TotalWeight
		r.SecurityUpperBound = 100 * (r.PassedWeight + r.UnknownWeight) / r.TotalWeight
		r.BoundsAvailable = true
	}
	if evaluated := r.PassedWeight + r.FailedWeight; evaluated > 0 {
		r.ScoreAvailable = true
		r.Score = 100 * r.PassedWeight / evaluated
		if r.CriticalFailure && r.Score > 40 {
			r.Score = 40
			r.ScoreCapped = true
		}
		r.Grade = grade(r.Score)
	} else {
		r.Grade = "UNAVAILABLE"
	}
	r.Provisional = r.UnknownWeight > 0
	return r
}

func actionableThreats(f Facts, controls []ControlResult) []ThreatEntry {
	entries := make([]ThreatEntry, 0, len(controls))
	for _, control := range controls {
		threat, impact, ok := threatDetails(control.ControlID)
		if !ok {
			continue
		}
		status := string(control.Status)
		if control.ControlID == "SIH_METADATA_001" {
			if !f.MetadataKnown || !f.MetadataExposure {
				continue
			}
			// Observable outer metadata is a supported disclosure, even where the
			// baseline does not treat it as a failed control.
			status = "OBSERVED"
		} else if control.Status != ControlFail {
			continue
		}
		entries = append(entries, ThreatEntry{Threat: threat, ControlID: control.ControlID, Status: status, Severity: control.Severity, Impact: impact, Recommendation: control.Remediation, ResourceType: f.ResourceType, Evidence: append([]EvidenceReference(nil), control.Evidence...)})
	}
	return entries
}

func threatDetails(controlID string) (string, string, bool) {
	switch controlID {
	case "SIH_IKE_SUITE_001", "SIH_CHILD_SUITE_001":
		return "Weak encryption", "The negotiated suite may provide insufficient confidentiality or integrity strength for the deployment baseline.", true
	case "SIH_IKE_VERSION_001", "SIH_IKE_POLICY_001", "SIH_CHILD_POLICY_001", "SIH_DH_001":
		return "Deprecated negotiation", "A legacy protocol, proposal, or key-exchange group may weaken the security properties of future SAs.", true
	case "SIH_AUTH_001":
		return "Authentication weakness", "Peer authentication was absent, unsupported, or outside the approved configuration baseline.", true
	case "SIH_REPLAY_001":
		return "Replay exposure", "The verified inbound SA does not enforce the required anti-replay protection.", true
	case "SIH_IKE_LIFETIME_001", "SIH_CHILD_LIFETIME_001":
		return "Excessive key lifetime", "Long-lived keys increase the exposure period if a key is compromised.", true
	case "SIH_PFS_CONFIG_001":
		return "Forward secrecy disabled", "CHILD-SA rekeying may not request a fresh key exchange.", true
	case "SIH_PFS_EXCHANGE_001":
		return "Missing fresh CHILD exchange", "The observed CHILD-SA creation or rekey lacked evidence of a fresh key exchange.", true
	case "SIH_METADATA_001":
		return "Metadata disclosure", "Outer endpoints, timing, direction, packet sizes, and volume remain observable even when ESP payloads are encrypted.", true
	default:
		return "", "", false
	}
}

func isCriticalFailure(controlID string, f Facts) bool {
	if controlID == "SIH_AUTH_001" {
		return oneOf(algorithmToken(f.IKEAuthentication), "NONE", "NULL")
	}
	if controlID == "SIH_IKE_SUITE_001" {
		return isNullCipher(f.IKEEncryption)
	}
	if controlID == "SIH_CHILD_SUITE_001" {
		return isNullCipher(f.EncryptionAlgorithm)
	}
	if controlID == "SIH_IKE_POLICY_001" {
		return strings.Contains(algorithmToken(f.ConfiguredIKEProposals), "ENCRNULL") || strings.Contains(algorithmToken(f.ConfiguredIKEProposals), "ENCR0")
	}
	if controlID == "SIH_CHILD_POLICY_001" {
		return strings.Contains(algorithmToken(f.ConfiguredChildProposals), "ENCRNULL") || strings.Contains(algorithmToken(f.ConfiguredChildProposals), "ENCR0")
	}
	return false
}

func isNullCipher(value string) bool { return oneOf(algorithmToken(value), "NULL", "ENCR0") }

func evidenceFor(f Facts, properties []string) []EvidenceReference {
	var out []EvidenceReference
	for _, p := range properties {
		if e, ok := f.Evidence[p]; ok {
			e.EvidenceIDs = append([]string(nil), e.EvidenceIDs...)
			e.Sources = append([]string(nil), e.Sources...)
			out = append(out, e)
		}
	}
	return out
}
func assessIKEVersion(f Facts) ControlStatus {
	if isChild(f.ResourceType) && f.IKEVersion == "" || f.ResourceType == "METADATA" {
		return ControlNotApplicable
	}
	v := algorithmToken(f.IKEVersion)
	if v == "" {
		return ControlUnknown
	}
	if oneOf(v, "IKEV2", "IKEV20", "2") {
		return ControlPass
	}
	if oneOf(v, "IKEV1", "IKEV10", "1") {
		return ControlFail
	}
	return ControlUnknown
}
func assessIKESuite(f Facts) ControlStatus {
	if !isIKE(f.ResourceType) && f.IKEEncryption == "" {
		return ControlNotApplicable
	}
	return assessSuite(f.IKEEncryption, f.IKEIntegrity, f.IKEEncryptionKeyBits, f.IKEEncryptionKeyKnown, f.IKEAEADTagBits, f.IKEAEADTagKnown)
}
func assessChildSuite(f Facts) ControlStatus {
	if f.ResourceType == "METADATA" {
		return ControlNotApplicable
	}
	if isIKE(f.ResourceType) && f.EncryptionAlgorithm == "" {
		return ControlNotApplicable
	}
	return assessSuite(f.EncryptionAlgorithm, f.IntegrityAlgorithm, f.EncryptionKeyBits, f.EncryptionKeyKnown, f.AEADTagBits, f.AEADTagKnown)
}
func assessSuite(cipher, integrity string, key uint64, keyKnown bool, tag uint64, tagKnown bool) ControlStatus {
	kind, embeddedKey, embeddedTag := cipherProperties(cipher)
	if kind == "" {
		return ControlUnknown
	}
	if kind == "WEAK" {
		return ControlFail
	}
	if !keyKnown && embeddedKey > 0 {
		key, keyKnown = embeddedKey, true
	}
	if !keyKnown {
		return ControlUnknown
	}
	if key != 128 && key != 256 {
		return ControlFail
	}
	if kind == "GCM" {
		if !tagKnown && embeddedTag > 0 {
			tag, tagKnown = embeddedTag, true
		}
		if !tagKnown {
			return ControlUnknown
		}
		if tag < 96 {
			return ControlFail
		}
		if integrity != "" && !oneOf(algorithmToken(integrity), "AEAD", "NONE", "INTEG0", "AUTH0") {
			return ControlFail
		}
		return ControlPass
	}
	return integrityStatus(integrity)
}
func cipherProperties(v string) (string, uint64, uint64) {
	switch algorithmToken(v) {
	case "DES", "DESCBC", "3DES", "3DESCBC", "NULL", "ENCR0", "ENCR2", "ENCR3", "IKEV1ENCR1", "IKEV1ENCR5":
		return "WEAK", 0, 0
	case "ENCR12", "AESCBC":
		return "CBC", 0, 0
	case "AES128":
		return "CBC", 128, 0
	case "AES256":
		return "CBC", 256, 0
	case "AES128CBC", "AESCBC128":
		return "CBC", 128, 0
	case "AES256CBC", "AESCBC256":
		return "CBC", 256, 0
	case "ENCR18", "AESGCM8":
		return "GCM", 0, 64
	case "ENCR19", "AESGCM12":
		return "GCM", 0, 96
	case "ENCR20", "AESGCM16":
		return "GCM", 0, 128
	case "AES128GCM8":
		return "GCM", 128, 64
	case "AES128GCM12":
		return "GCM", 128, 96
	case "AES128GCM16", "AES128GCM":
		return "GCM", 128, 128
	case "AES256GCM8":
		return "GCM", 256, 64
	case "AES256GCM12":
		return "GCM", 256, 96
	case "AES256GCM16", "AES256GCM":
		return "GCM", 256, 128
	}
	return "", 0, 0
}
func integrityStatus(v string) ControlStatus {
	t := algorithmToken(v)
	if t == "" {
		return ControlUnknown
	}
	if oneOf(t, "MD5", "HMACMD5", "HMACMD596", "SHA1", "HMACSHA1", "HMACSHA196", "AUTH1", "AUTH2", "INTEG1", "INTEG2", "IKEV1HASH1", "IKEV1HASH2") {
		return ControlFail
	}
	if oneOf(t, "SHA256", "SHA256128", "HMACSHA256", "HMACSHA256128", "SHA384", "SHA384192", "HMACSHA384", "HMACSHA384192", "SHA512", "SHA512256", "HMACSHA512", "HMACSHA512256", "AUTH12", "AUTH13", "AUTH14", "INTEG12", "INTEG13", "INTEG14") {
		return ControlPass
	}
	return ControlUnknown
}
func assessAuthentication(f Facts) ControlStatus {
	if !isIKE(f.ResourceType) && f.IKEAuthentication == "" {
		return ControlNotApplicable
	}
	raw := strings.TrimSpace(f.IKEAuthentication)
	if raw == "" {
		return ControlUnknown
	}
	for _, method := range strings.Split(raw, ",") {
		if index := strings.LastIndex(method, ":"); index >= 0 {
			method = method[index+1:]
		}
		t := algorithmToken(method)
		if oneOf(t, "NONE", "NULL") {
			return ControlFail
		}
		if !oneOf(t, "PSK", "PUBKEY", "PUBLICKEY", "RSA", "RSASIGNATURE", "ECDSA", "DIGITALSIGNATURE", "EAP") {
			return ControlUnknown
		}
	}
	return ControlPass
}
func assessConfiguredProposals(raw string, requireIKEFields bool) ControlStatus {
	if strings.TrimSpace(raw) == "" {
		return ControlNotApplicable
	}
	overall := ControlPass
	for _, proposal := range strings.Split(raw, ";") {
		fields := map[string][]string{}
		for _, field := range strings.Split(proposal, "|") {
			parts := strings.SplitN(field, "=", 2)
			if len(parts) == 2 && parts[1] != "" {
				fields[parts[0]] = strings.Split(parts[1], ",")
			}
		}
		if len(fields["encr"]) == 0 && len(fields["integ"]) == 0 {
			overall = ControlUnknown
			continue
		}
		for _, cipher := range fields["encr"] {
			kind, key, tag := cipherProperties(cipher)
			if kind == "WEAK" || kind == "GCM" && tag > 0 && tag < 96 {
				return ControlFail
			}
			if kind == "" || key == 0 {
				overall = ControlUnknown
			}
		}
		if len(fields["encr"]) > 0 {
			kind, _, _ := cipherProperties(fields["encr"][0])
			if kind != "GCM" {
				if len(fields["integ"]) == 0 {
					overall = ControlUnknown
				}
				for _, integrity := range fields["integ"] {
					status := integrityStatus(integrity)
					if status == ControlFail {
						return ControlFail
					}
					if status == ControlUnknown {
						overall = ControlUnknown
					}
				}
			}
		}
		for _, group := range fields["ke"] {
			status := assessDH(Facts{DHGroup: group})
			if status == ControlFail {
				return ControlFail
			}
			if status == ControlUnknown {
				overall = ControlUnknown
			}
		}
		if requireIKEFields {
			if len(fields["prf"]) == 0 {
				overall = ControlUnknown
			}
			for _, prf := range fields["prf"] {
				token := algorithmToken(prf)
				if oneOf(token, "PRFMD5", "MD5", "PRFSHA1", "SHA1") {
					return ControlFail
				}
				if !oneOf(token, "PRFSHA256", "PRFSHA384", "PRFSHA512", "HMACSHA256", "HMACSHA384", "HMACSHA512") {
					overall = ControlUnknown
				}
			}
		}
	}
	return overall
}
func assessDH(f Facts) ControlStatus {
	if isChild(f.ResourceType) && f.DHGroup == "" || f.ResourceType == "METADATA" {
		return ControlNotApplicable
	}
	g, ok := dhNumber(f.DHGroup)
	if !ok {
		return ControlUnknown
	}
	if (g >= 14 && g <= 21) || g == 31 {
		return ControlPass
	}
	if g == 1 || g == 2 || g == 5 {
		return ControlFail
	}
	return ControlUnknown
}
func dhNumber(v string) (int, bool) {
	t := algorithmToken(v)
	aliases := map[string]int{"MODP768": 1, "MODP1024": 2, "MODP1536": 5, "MODP2048": 14, "ECP256": 19, "ECP384": 20, "ECP521": 21, "CURVE25519": 31}
	if n, ok := aliases[t]; ok {
		return n, true
	}
	t = strings.TrimPrefix(strings.TrimPrefix(t, "GROUP"), "DH")
	n, e := strconv.Atoi(t)
	return n, e == nil
}
func assessSAParameters(f Facts) ControlStatus {
	if !isChild(f.ResourceType) && f.Mode == "" && f.Protocol == "" {
		return ControlNotApplicable
	}
	if f.Mode == "" || f.Protocol == "" || f.State == "" || f.Direction == "" || !f.SelectorsKnown {
		return ControlUnknown
	}
	if !oneOf(algorithmToken(f.Mode), "TUNNEL", "TRANSPORT") || !oneOf(algorithmToken(f.Protocol), "ESP", "AH") || !oneOf(algorithmToken(f.State), "INSTALLED", "ESTABLISHED", "UP") {
		return ControlFail
	}
	if f.ConfigurationRuntimeKnown && !f.ConfigurationRuntimeConsistent {
		return ControlFail
	}
	return ControlPass
}
func assessIKELifetime(f Facts) ControlStatus {
	if !isIKE(f.ResourceType) && !f.IKELifetimeKnown {
		return ControlNotApplicable
	}
	if !f.IKELifetimeKnown {
		return ControlUnknown
	}
	if f.IKELifetimeSeconds == 0 || f.IKELifetimeSeconds > 86400 {
		return ControlFail
	}
	return ControlPass
}
func assessChildLifetime(f Facts) ControlStatus {
	if !isChild(f.ResourceType) && !f.SALifetimeKnown {
		return ControlNotApplicable
	}
	if !f.SALifetimeKnown {
		return ControlUnknown
	}
	if f.SALifetimeSeconds == 0 || f.SALifetimeSeconds > 3600 {
		return ControlFail
	}
	return ControlPass
}
func assessReplay(f Facts) ControlStatus {
	if !isChild(f.ResourceType) && f.ReplayProtection == nil {
		return ControlNotApplicable
	}
	if oneOf(algorithmToken(f.Direction), "OUT", "OUTBOUND") {
		return ControlNotApplicable
	}
	if f.ReplayProtection == nil || !f.ReplayWindowKnown {
		return ControlUnknown
	}
	if !*f.ReplayProtection || f.ReplayWindow == 0 {
		return ControlFail
	}
	return ControlPass
}
func assessPFS(f Facts) ControlStatus {
	if !isChild(f.ResourceType) && f.PFS == nil {
		return ControlNotApplicable
	}
	if f.PFS == nil {
		return ControlUnknown
	}
	if !*f.PFS {
		return ControlFail
	}
	return ControlPass
}
func assessFreshExchange(f Facts) ControlStatus {
	if f.FreshExchangeObserved == nil {
		return ControlNotApplicable
	}
	if !*f.FreshExchangeObserved {
		return ControlFail
	}
	return ControlPass
}
func assessMetadata(f Facts) ControlStatus {
	if !f.MetadataKnown {
		if f.ResourceType != "" && f.ResourceType != "ANALYSIS" && f.ResourceType != "METADATA" {
			return ControlNotApplicable
		}
		return ControlUnknown
	}
	// ESP's normal outer metadata exposure is recorded as evidence but is not a
	// failed baseline control unless a deployment supplies a stricter policy.
	if f.MetadataProtectionRequired != nil && *f.MetadataProtectionRequired && f.MetadataExposure {
		return ControlFail
	}
	return ControlPass
}
func isIKE(v string) bool {
	u := strings.ToUpper(v)
	return strings.Contains(u, "IKE") || strings.Contains(u, "CONNECTION")
}
func isChild(v string) bool {
	u := strings.ToUpper(v)
	return strings.Contains(u, "CHILD") || strings.Contains(u, "XFRM")
}
func algorithmToken(v string) string {
	return strings.NewReplacer("-", "", "_", "", " ", "", "/", "", ".", "").Replace(strings.ToUpper(strings.TrimSpace(v)))
}
func oneOf(v string, c ...string) bool {
	for _, x := range c {
		if v == x {
			return true
		}
	}
	return false
}
func severityWeight(s Severity) int {
	switch s {
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
func grade(score float64) string {
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
