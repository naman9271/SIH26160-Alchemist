package security_test

import (
	"context"
	"testing"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	corerisk "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/risk"
	coresecurity "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/security"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	rules "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/security"
	"google.golang.org/protobuf/types/known/structpb"
)

type conclusionFixture []model.FusedConclusion

func (f conclusionFixture) FusedConclusions(context.Context, string) ([]model.FusedConclusion, error) {
	return f, nil
}

func TestAssessmentAndRiskReuseDeterministicRules(t *testing.T) {
	service := coresecurity.New(conclusionFixture{
		{ID: "c1", PropertyKey: "ike.version", Value: structpb.NewStringValue("IKEv1"), Status: commonv1.EvidenceStatus_OBSERVED, Confidence: .9},
		{ID: "c2", PropertyKey: "child.encryption_algorithm", Value: structpb.NewStringValue("3DES"), Status: commonv1.EvidenceStatus_VERIFIED_GATEWAY, Confidence: 1},
		{ID: "c3", PropertyKey: "metadata.exposure", Value: structpb.NewStringValue("observed"), Status: commonv1.EvidenceStatus_DERIVED, Confidence: .8},
	})
	record, err := service.Run(context.Background(), "analysis", rules.SIHBaselinePolicyID)
	if err != nil || record.Result.Score >= 100 || len(record.Result.Findings) < 2 {
		t.Fatalf("record=%+v err=%v", record, err)
	}
	recommendations, err := service.Recommendations(context.Background(), record.ID)
	if err != nil || len(recommendations) == 0 {
		t.Fatalf("recommendations=%+v err=%v", recommendations, err)
	}
	risk := corerisk.New(service)
	score, err := risk.Score(context.Background(), record.ID)
	if err != nil || score.Score != uint32(record.Result.Score) || score.UnknownEvidenceCount == 0 {
		t.Fatalf("score=%+v err=%v", score, err)
	}
	breakdown, err := risk.Breakdown(context.Background(), record.ID)
	if err != nil || breakdown.Cryptography.Score >= breakdown.Cryptography.Maximum {
		t.Fatalf("breakdown=%+v err=%v", breakdown, err)
	}
}

func TestIKECipherIsNotSubstitutedForMissingChildCipher(t *testing.T) {
	service := coresecurity.New(conclusionFixture{
		{ID: "c1", PropertyKey: "ike.version", Value: structpb.NewStringValue("IKEv2.0"), Status: commonv1.EvidenceStatus_OBSERVED, Confidence: .95},
		{ID: "c2", PropertyKey: "ike.encryption", Value: structpb.NewStringValue("ENCR_20"), Status: commonv1.EvidenceStatus_OBSERVED, Confidence: .95},
		{ID: "c3", PropertyKey: "ike.dh_group", Value: structpb.NewStringValue("DH_19"), Status: commonv1.EvidenceStatus_OBSERVED, Confidence: .95},
	})

	record, err := service.Run(context.Background(), "analysis-aead", rules.SIHBaselinePolicyID)
	if err != nil {
		t.Fatal(err)
	}
	if record.UnknownEvidence != 4 {
		t.Fatalf("unknown evidence = %d, want CHILD-SA cipher/integrity/PFS/replay to remain unknown", record.UnknownEvidence)
	}
	if !record.Result.ScoreAvailable || !record.Result.Provisional || record.Result.Coverage >= 50 || record.Result.SecurityLowerBound >= 50 || len(record.Result.Findings) != 0 {
		t.Fatalf("assessment = %+v, missing CHILD-SA cipher was not presented as provisional incomplete evidence", record.Result)
	}

	risk := corerisk.New(service)
	score, err := risk.Score(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if score.UnknownEvidenceCount != 4 || score.EvidenceCoverage >= 50 {
		t.Fatalf("risk score = %+v, missing evidence retained too much coverage", score)
	}
}

func TestUnavailableConfigurationNeverBecomesAPass(t *testing.T) {
	service := coresecurity.New(conclusionFixture{{ID: "ike", PropertyKey: model.PropertyIKEVersion, Value: structpb.NewStringValue("IKEv2"), Status: commonv1.EvidenceStatus_OBSERVED, Confidence: 1}})
	record, err := service.Run(context.Background(), "analysis-unknown", rules.SIHBaselinePolicyID)
	if err != nil {
		t.Fatal(err)
	}
	if record.UnknownEvidence != 5 || !record.Result.ScoreAvailable || !record.Result.Provisional || record.Result.Coverage >= 50 || record.Result.SecurityLowerBound >= 50 {
		t.Fatalf("record=%+v", record)
	}
	score, err := corerisk.New(service).Score(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if score.UnknownEvidenceCount != 5 || score.EvidenceCoverage >= 100 {
		t.Fatalf("unknown evidence was represented as a pass: %+v", score)
	}
	breakdown, err := corerisk.New(service).Breakdown(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if breakdown.Cryptography.Score != 0 || breakdown.Authentication.Score != 0 || breakdown.KeyExchange.Score != 7.5 || breakdown.KeyExchange.Maximum != 15 {
		t.Fatalf("unknown category controls received credit: %+v", breakdown)
	}
}

func TestAssessmentKeepsSecurityAssociationsSeparate(t *testing.T) {
	service := coresecurity.New(conclusionFixture{
		{ID: "a", ResourceType: "CHILD_SA", ResourceID: "strong", PropertyKey: model.PropertyChildEncryption, Value: structpb.NewStringValue("AES-GCM-16"), Status: commonv1.EvidenceStatus_VERIFIED_GATEWAY, Confidence: 1},
		{ID: "b", ResourceType: "CHILD_SA", ResourceID: "weak", PropertyKey: model.PropertyChildEncryption, Value: structpb.NewStringValue("3DES-CBC"), Status: commonv1.EvidenceStatus_VERIFIED_GATEWAY, Confidence: 1},
	})
	record, err := service.Run(context.Background(), "analysis-scoped", rules.SIHBaselinePolicyID)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Result.Findings) != 1 || record.Result.Findings[0].ResourceID != "weak" {
		t.Fatalf("SA-scoped findings = %+v", record.Result.Findings)
	}
	breakdown, err := corerisk.New(service).Breakdown(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(record.PerSAAssessments) != 2 || record.Result.ResourceID != "weak" || !record.Result.ScoreAvailable {
		t.Fatalf("deployment must headline the worst observed SA and retain separate SA scores: %+v", record)
	}
	if breakdown.Cryptography.Maximum <= 0 || breakdown.SaConfiguration == nil {
		t.Fatalf("risk breakdown omitted applicable D2 categories: %+v", breakdown)
	}
}

func TestAssessmentDefaultsToSeparateBaselineAndRetainsProvenance(t *testing.T) {
	service := coresecurity.New(conclusionFixture{{ID: "conclusion-1", PropertyKey: model.PropertyIKEDHGroup, ResourceType: "VICI_IKE_SA", ResourceID: "ike-7", Value: structpb.NewStringValue("DH_2"), Status: commonv1.EvidenceStatus_VERIFIED_GATEWAY, Confidence: 1, EvidenceIDs: []string{"evidence-9"}, WinningSources: []model.Source{model.SourceVICI}}})
	record, err := service.Run(context.Background(), "analysis-policy", "")
	if err != nil {
		t.Fatal(err)
	}
	if record.PolicyID != rules.SIHBaselinePolicyID || record.Result.PolicyLabel != "SIH baseline compliance" {
		t.Fatalf("assessment reused the fusion policy: %+v", record)
	}
	var matched bool
	for _, control := range record.Result.Controls {
		if control.ControlID != "SIH_DH_001" || control.ResourceID != "ike-7" {
			continue
		}
		matched = true
		if control.Status != rules.ControlFail || len(control.Evidence) != 1 || control.Evidence[0].Value != "DH_2" || len(control.Evidence[0].EvidenceIDs) != 1 {
			t.Fatalf("control lost status or provenance: %+v", control)
		}
	}
	if !matched {
		t.Fatal("missing SA-scoped DH control")
	}
}
