package analysis

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	analysisv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/analysis"
	workspacev1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/workspace"
	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
	coreevents "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/events"
	coreinput "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/core/input"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/session"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/acquisition"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/capture"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/flow"
)

func TestLivePipelinePublishesSnapshotsBeforeCaptureStops(t *testing.T) {
	ctx := context.Background()
	sensor := acquisition.New(nil, nil, nil)
	input := coreinput.New(sensor)
	runtime := fusion.NewRuntime(fusion.RuntimeOptions{})
	analysisID := uuid.Must(uuid.NewV7()).String()
	run, err := runtime.Sessions.Create(ctx, session.CreateRequest{AnalysisID: analysisID, PolicyID: model.DefaultPolicyID})
	if err != nil {
		t.Fatal(err)
	}
	pipeline := &Pipeline{Sensor: sensor, Input: input, Ingest: runtime.Ingest, Fusion: runtime.Fusion, Events: coreevents.New(), LiveRefreshInterval: 5 * time.Millisecond}
	record := Record{ID: analysisID, FusionRunID: run.ID, Mode: workspacev1.AnalysisMode_PASSIVE_LIVE, Options: &analysisv1.AnalysisOptions{EnableFusion: true, EnableSecurity: false, EnableMl: false}}
	var snapshots atomic.Uint64
	done := make(chan error, 1)
	go func() {
		done <- pipeline.runLive(ctx, record, "live-session", func(analysisv1.AnalysisStage) {}, func() uint64 { return snapshots.Add(1) })
	}()

	start := time.Now().UTC()
	for index, seen := range []time.Time{start, start.Add(time.Second)} {
		packet := capture.PacketMetadata{SessionID: "live-session", Protocol: 50, SourceAddress: "192.0.2.1", DestinationAddress: "198.51.100.1", SPI: 1, Length: 128, SeenAt: seen}
		if err := sensor.Observations.Observe(ctx, packet); err != nil {
			t.Fatal(err)
		}
		if _, err := sensor.Flows.ObservePacket(ctx, flow.Packet{SessionID: packet.SessionID, Protocol: flowv1.FlowProtocol_ESP, SourceAddress: packet.SourceAddress, DestinationAddress: packet.DestinationAddress, SPI: packet.SPI, Size: packet.Length + uint64(index), SeenAt: packet.SeenAt}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for snapshots.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if snapshots.Load() == 0 {
		t.Fatal("live pipeline did not publish a snapshot while capture was active")
	}
	select {
	case err := <-done:
		t.Fatalf("live pipeline ended before capture stop: %v", err)
	default:
	}
	if err := sensor.Flows.StopForSession(ctx, "live-session"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("live pipeline did not finish after capture stop")
	}
	status, err := runtime.Fusion.GetStatus(ctx, run.ID)
	if err != nil || status.Counts.Evidence == 0 {
		t.Fatalf("live pipeline evidence=%d err=%v", status.Counts.Evidence, err)
	}
}
