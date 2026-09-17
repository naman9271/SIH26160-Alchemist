package policy

import (
	"context"
	"testing"

	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
)

func TestDefaultPolicyUsesCanonicalEvidenceProperties(t *testing.T) {
	definition, err := NewDefault().Resolve(context.Background(), model.DefaultPolicyID)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, property := range model.SecurityConfigurationProperties {
		want[property] = true
	}
	for _, property := range definition.RequiredProperties {
		if property == "child.esp_encryption" || property == "child.integrity" {
			t.Fatalf("obsolete property in policy: %s", property)
		}
		delete(want, property)
	}
	if len(want) != 0 {
		t.Fatalf("missing canonical properties: %v", want)
	}
}
