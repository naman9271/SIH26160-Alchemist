package system

import (
	"context"
	"errors"
	"testing"

	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
)

func TestFusionSystemServiceAPIs(t *testing.T) {
	ready := StaticProbe(true, "ignored")
	capabilities := Capabilities{
		PassiveEvidence: true, VICIEvidence: true, XFRMEvidence: true,
		MLEvidence: true, SHAPEvidence: true, SecurityFindingRefs: true,
		ConflictDetection: true, ConfidenceCalculation: true, Provenance: true,
		IncrementalRecomputation: true,
	}
	service := New(Options{
		Policy: ready, EvidenceStore: ready, Correlator: ready, ConflictEngine: ready, ConfidenceEngine: ready,
		Version:      Version{EngineVersion: "1.2.3", PolicySchema: "policy.v2", BuildCommit: "abc123"},
		Capabilities: capabilities,
	})

	health, err := service.Health(context.Background())
	if err != nil || health.Status != model.HealthHealthy {
		t.Fatalf("Health() = %+v, %v", health, err)
	}
	readiness, err := service.Readiness(context.Background())
	if err != nil || !readiness.Ready || !readiness.Policy.Ready || readiness.Policy.Reason != "" {
		t.Fatalf("Readiness() = %+v, %v", readiness, err)
	}
	version, err := service.GetVersion(context.Background())
	if err != nil || version.EngineVersion != "1.2.3" || version.APISchema != APISchema || version.PolicySchema != "policy.v2" || version.BuildCommit != "abc123" {
		t.Fatalf("GetVersion() = %+v, %v", version, err)
	}
	gotCapabilities, err := service.GetCapabilities(context.Background())
	if err != nil || gotCapabilities != capabilities {
		t.Fatalf("GetCapabilities() = %+v, %v", gotCapabilities, err)
	}
}

func TestReadinessReportsEveryDependency(t *testing.T) {
	service := New(Options{
		Policy: StaticProbe(true, ""), EvidenceStore: StaticProbe(true, ""),
		ConflictEngine:   StaticProbe(false, "conflict policy invalid"),
		ConfidenceEngine: StaticProbe(true, ""),
	})
	result, err := service.Readiness(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Ready || result.Correlator.Ready || result.Correlator.Reason == "" || result.ConflictEngine.Reason != "conflict policy invalid" {
		t.Fatalf("unexpected readiness: %+v", result)
	}
}

func TestSystemMethodsHonorCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New(Options{}).Health(ctx)
	var fusionErr *model.Error
	if !errors.As(err, &fusionErr) || fusionErr.Kind != model.ErrorCancelled {
		t.Fatalf("Health(cancelled) error = %v", err)
	}
}

func TestDefaultVersionHasSchemasAndBuildValues(t *testing.T) {
	version, err := New(Options{}).GetVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if version.EngineVersion == "" || version.APISchema != APISchema || version.PolicySchema == "" || version.BuildCommit == "" {
		t.Fatalf("incomplete default version: %+v", version)
	}
}
