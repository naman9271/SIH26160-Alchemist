package policy_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/policy"
)

func TestListGetActiveSetActiveAndValidate(t *testing.T) {
	first := validDefinition("first")
	second := validDefinition("second")
	repository := policy.NewMemory(first, second)
	service := policy.NewService(repository, nil)
	listed, err := service.List(context.Background(), policy.ListRequest{})
	if err != nil || len(listed.Policies) != 2 || listed.Policies[0].ID != "first" {
		t.Fatalf("List() = %+v, %v", listed, err)
	}
	got, err := service.Get(context.Background(), policy.GetRequest{PolicyID: "second"})
	if err != nil || got.ID != "second" {
		t.Fatalf("Get() = %+v, %v", got, err)
	}
	active, _ := service.GetActive(context.Background())
	if active.ID != "first" {
		t.Fatalf("initial active = %q", active.ID)
	}
	changed, err := service.SetActive(context.Background(), policy.SetActiveRequest{PolicyID: "second"})
	if err != nil || changed.Policy.ID != "second" {
		t.Fatalf("SetActive() = %+v, %v", changed, err)
	}
	invalid := validDefinition("invalid")
	invalid.SourceTrust[model.SourcePacketParser] = 2
	invalid.PropertyRules["bad property"] = policy.PropertyRule{FreshnessWindow: -1}
	validation, err := service.Validate(context.Background(), policy.ValidateRequest{Policy: invalid})
	if err != nil || validation.Valid || len(validation.Issues) < 2 {
		t.Fatalf("Validate() = %+v, %v", validation, err)
	}
}

func TestReloadVersionedJSONIsAtomic(t *testing.T) {
	directory := t.TempDir()
	writePolicy(t, directory, "loaded.json", map[string]any{
		"id": "loaded-v1", "schema_version": policy.SchemaVersion, "active": true,
		"required_sources": []string{"PACKET_PARSER"}, "required_properties": []string{"ike.version"},
		"source_trust":      map[string]float64{"PACKET_PARSER": .95},
		"status_precedence": []string{"VERIFIED_GATEWAY", "OBSERVED", "DERIVED", "INFERRED", "UNKNOWN"},
		"freshness_window":  "1h", "minimum_confidence": .2, "conflict_threshold": .1, "correlation_threshold": .5,
		"property_rules": map[string]any{"ike.version": map[string]any{"source_precedence": []string{"PACKET_PARSER"}, "freshness_window": "30m", "minimum_confidence": .3}},
	})
	repository := policy.NewMemory(validDefinition("original"))
	service := policy.NewService(repository, policy.DirectoryLoader{Directory: directory})
	reloaded, err := service.Reload(context.Background(), policy.ReloadRequest{})
	if err != nil || reloaded.PoliciesLoaded != 1 || reloaded.ActivePolicyID != "loaded-v1" {
		t.Fatalf("Reload() = %+v, %v", reloaded, err)
	}
	active, _ := service.GetActive(context.Background())
	if active.ID != "loaded-v1" || active.FreshnessWindow.String() != "1h0m0s" {
		t.Fatalf("active policy = %+v", active)
	}

	writePolicy(t, directory, "invalid.json", map[string]any{"id": "broken", "schema_version": policy.SchemaVersion, "active": false, "freshness_window": "-1h"})
	_, err = service.Reload(context.Background(), policy.ReloadRequest{})
	assertPolicyKind(t, err, model.ErrorInvalidArgument)
	stillActive, _ := service.GetActive(context.Background())
	if stillActive.ID != "loaded-v1" {
		t.Fatalf("failed reload partially replaced active policy: %q", stillActive.ID)
	}
}

func TestReloadWithoutLoaderAndUnknownPolicyErrors(t *testing.T) {
	service := policy.NewService(policy.NewMemory(validDefinition("only")), nil)
	_, err := service.Reload(context.Background(), policy.ReloadRequest{})
	assertPolicyKind(t, err, model.ErrorFailedPrecondition)
	_, err = service.SetActive(context.Background(), policy.SetActiveRequest{PolicyID: "missing"})
	assertPolicyKind(t, err, model.ErrorNotFound)
}

func validDefinition(id string) policy.Definition {
	return policy.Definition{ID: id, SchemaVersion: policy.SchemaVersion, RequiredSources: []model.Source{model.SourcePacketParser},
		RequiredProperties: []string{"ike.version"}, SourceTrust: map[model.Source]float64{model.SourcePacketParser: .95},
		StatusPrecedence:  []commonv1.EvidenceStatus{commonv1.EvidenceStatus_VERIFIED_GATEWAY, commonv1.EvidenceStatus_OBSERVED, commonv1.EvidenceStatus_DERIVED, commonv1.EvidenceStatus_INFERRED, commonv1.EvidenceStatus_UNKNOWN},
		MinimumConfidence: .2, ConflictThreshold: .1, CorrelationThreshold: .5,
		PropertyRules: map[string]policy.PropertyRule{"ike.version": {SourcePrecedence: []model.Source{model.SourcePacketParser}, MinimumConfidence: .2}}}
}
func writePolicy(t *testing.T, directory, name string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
func assertPolicyKind(t *testing.T, err error, kind model.ErrorKind) {
	t.Helper()
	var fusionErr *model.Error
	if !errors.As(err, &fusionErr) || fusionErr.Kind != kind {
		t.Fatalf("error = %v, want %s", err, kind)
	}
}
