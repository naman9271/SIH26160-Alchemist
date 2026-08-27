package system

import (
	"context"
	"testing"
)

func TestDefaultPipelineMetricsAreDeterministicZero(t *testing.T) {
	stats, err := New(Options{}).RuntimeStats(context.Background())
	if err != nil {
		t.Fatalf("RuntimeStats: %v", err)
	}
	if stats.ActiveFlows != 0 || stats.PacketQueueDepth != 0 || stats.FeatureQueueDepth != 0 || stats.TemporaryDiskBytes != 0 {
		t.Fatalf("default pipeline metrics = %+v, want zero values", stats)
	}
}

func TestPassiveReadinessDoesNotRequireDeepTelemetry(t *testing.T) {
	readiness := Readiness{
		CaptureEngine:  ComponentReady,
		TempStorage:    ComponentReady,
		ProtocolEngine: ComponentReady,
		VICI:           ComponentUnavailable,
		XFRM:           ComponentUnavailable,
	}
	if !readiness.PassiveReady() {
		t.Fatal("passive readiness must not depend on VICI or XFRM")
	}
}
