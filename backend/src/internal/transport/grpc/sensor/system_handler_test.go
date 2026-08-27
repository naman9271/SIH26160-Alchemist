package sensor_test

import (
	"context"
	"runtime"
	"testing"
	"time"

	sensorv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/system"
	transport "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/transport/grpc/sensor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type dependencyStub struct {
	readiness    system.Readiness
	capabilities system.Capabilities
}

func (stub dependencyStub) Readiness(context.Context) (system.Readiness, error) {
	return stub.readiness, nil
}

func (stub dependencyStub) Capabilities(context.Context) (system.Capabilities, error) {
	return stub.capabilities, nil
}

type metricsStub struct{ stats system.PipelineStats }

func (stub metricsStub) PipelineStats(context.Context) (system.PipelineStats, error) {
	return stub.stats, nil
}

func TestSensorSystemAPIs(t *testing.T) {
	dependencies := dependencyStub{
		readiness: system.Readiness{
			CaptureEngine:  system.ComponentReady,
			TempStorage:    system.ComponentReady,
			ProtocolEngine: system.ComponentReady,
			VICI:           system.ComponentUnavailable,
			XFRM:           system.ComponentUnavailable,
		},
		capabilities: system.Capabilities{
			PassiveLive: true, PassivePCAP: true, DeepAssessment: true, IPv4: true, IPv6: true,
			IKEv1: true, IKEv2: true, ESP: true, AH: true, NATT: true, FeatureWindows: true, SequenceSketches: true,
		},
	}
	metrics := metricsStub{stats: system.PipelineStats{
		ActiveFlows: 41, PacketQueueDepth: 7, FeatureQueueDepth: 3, TemporaryDiskBytes: 1024,
	}}
	handler := transport.NewSystemHandler(system.New(system.Options{
		StartedAt:    time.Now().Add(-2 * time.Minute),
		Version:      system.Version{SensorVersion: "1.0.0", BuildCommit: "abc1234"},
		Dependencies: dependencies,
		Metrics:      metrics,
	}))
	ctx := context.Background()

	health, err := handler.Health(ctx, &sensorv1.HealthRequest{})
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if health.GetStatus() != sensorv1.HealthStatus_HEALTHY || health.GetTime() == nil || health.GetTime().CheckValid() != nil {
		t.Fatalf("unexpected health response: %+v", health)
	}
	if health.GetTime().AsTime().UTC().Location() != time.UTC {
		t.Fatalf("health timestamp is not UTC")
	}

	readiness, err := handler.Readiness(ctx, &sensorv1.ReadinessRequest{})
	if err != nil {
		t.Fatalf("Readiness: %v", err)
	}
	if !readiness.GetReady() {
		t.Fatal("passive sensor should be ready when VICI and XFRM are unavailable")
	}
	if readiness.GetVici() != sensorv1.ReadinessComponentState_UNAVAILABLE || readiness.GetXfrm() != sensorv1.ReadinessComponentState_UNAVAILABLE {
		t.Fatalf("unexpected deep dependency state: %+v", readiness)
	}

	version, err := handler.GetVersion(ctx, &sensorv1.GetVersionRequest{})
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if version.GetSensorVersion() != "1.0.0" || version.GetApiVersion() != "sensor.v1" || version.GetBuildCommit() != "abc1234" {
		t.Fatalf("unexpected configured version: %+v", version)
	}
	if version.GetGoVersion() != runtime.Version() || version.GetOs() != runtime.GOOS || version.GetArchitecture() != runtime.GOARCH {
		t.Fatalf("runtime version values were not determined dynamically: %+v", version)
	}

	capabilities, err := handler.GetCapabilities(ctx, &sensorv1.GetCapabilitiesRequest{})
	if err != nil {
		t.Fatalf("GetCapabilities: %v", err)
	}
	if !capabilities.GetPassiveLive() || !capabilities.GetIkev2() || !capabilities.GetSequenceSketches() || capabilities.GetVici() || capabilities.GetXfrm() {
		t.Fatalf("capabilities do not reflect dependency configuration: %+v", capabilities)
	}

	stats, err := handler.GetRuntimeStats(ctx, &sensorv1.GetRuntimeStatsRequest{})
	if err != nil {
		t.Fatalf("GetRuntimeStats: %v", err)
	}
	if stats.GetUptimeSeconds() < 119 || stats.GetRssBytes() == 0 || stats.GetGoroutines() == 0 {
		t.Fatalf("runtime stats are not based on process state: %+v", stats)
	}
	if stats.GetActiveFlows() != 41 || stats.GetPacketQueueDepth() != 7 || stats.GetFeatureQueueDepth() != 3 || stats.GetTemporaryDiskBytes() != 1024 {
		t.Fatalf("pipeline stats were not forwarded: %+v", stats)
	}
}

func TestSensorSystemServiceIsRegisteredWithFiveUnaryMethods(t *testing.T) {
	server := grpc.NewServer()
	sensorv1.RegisterSensorSystemServiceServer(server, transport.NewSystemHandler(system.New(system.Options{})))
	info := server.GetServiceInfo()["sensor.v1.SensorSystemService"]
	if len(info.Methods) != 5 {
		t.Fatalf("method count = %d, want 5", len(info.Methods))
	}
	for _, method := range info.Methods {
		if method.IsClientStream || method.IsServerStream {
			t.Fatalf("%s is not unary", method.Name)
		}
	}
}

func TestNilRequestIsInvalidArgument(t *testing.T) {
	handler := transport.NewSystemHandler(system.New(system.Options{}))
	_, err := handler.Health(context.Background(), nil)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil request code = %s, want %s", status.Code(err), codes.InvalidArgument)
	}
}
