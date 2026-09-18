package flow

import (
	"context"
	"math"
	"testing"
	"time"

	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
)

func TestOppositeDirectionalSPIsShareOneMLFlow(t *testing.T) {
	service := New(Config{})
	start := time.Unix(100, 0)
	firstID, err := service.ObservePacket(context.Background(), Packet{
		SessionID: "session", Protocol: flowv1.FlowProtocol_ESP,
		SourceAddress: "192.0.2.1", DestinationAddress: "198.51.100.2",
		SPI: 0x11111111, Size: 100, SeenAt: start,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := service.ObservePacket(context.Background(), Packet{
		SessionID: "session", Protocol: flowv1.FlowProtocol_ESP,
		SourceAddress: "198.51.100.2", DestinationAddress: "192.0.2.1",
		SPI: 0x22222222, Size: 200, SeenAt: start.Add(500 * time.Millisecond),
	})
	if err != nil {
		t.Fatal(err)
	}
	if firstID != secondID {
		t.Fatalf("opposite SAs split into flows %q and %q", firstID, secondID)
	}
	for _, spi := range []uint32{0x11111111, 0x22222222} {
		items, _, listErr := service.List(context.Background(), &flowv1.ListFlowsRequest{Spi: spi})
		if listErr != nil || len(items) != 1 {
			t.Fatalf("SPI %x lookup returned %d flows, error=%v", spi, len(items), listErr)
		}
	}
}

func TestFeatureWindowMatchesPythonSchemaAndUnits(t *testing.T) {
	service := New(Config{WindowDuration: 10 * time.Second, BurstGap: 100 * time.Millisecond, IdleGap: time.Second})
	start := time.Unix(100, 0)
	flowID := observe(t, service, Packet{SessionID: "session", Protocol: flowv1.FlowProtocol_ESP, SourceAddress: "a", DestinationAddress: "b", SPI: 1, Size: 100, SeenAt: start})
	observe(t, service, Packet{SessionID: "session", Protocol: flowv1.FlowProtocol_ESP, SourceAddress: "b", DestinationAddress: "a", SPI: 2, Size: 200, SeenAt: start.Add(500 * time.Millisecond)})
	if err := service.StopForSession(context.Background(), "session"); err != nil {
		t.Fatal(err)
	}
	record, err := service.Flow(context.Background(), flowID)
	if err != nil || len(record.windows) != 1 {
		t.Fatalf("windows=%v error=%v", record.windows, err)
	}
	item, err := service.Window(context.Background(), record.windows[0])
	if err != nil {
		t.Fatal(err)
	}
	feature := ToFeature(item)
	if len(feature.FeatureNames) != 23 || len(feature.FeatureValues) != 23 {
		t.Fatalf("feature vector lengths = %d/%d", len(feature.FeatureNames), len(feature.FeatureValues))
	}
	values := make(map[string]float64, len(feature.FeatureNames))
	for index, name := range feature.FeatureNames {
		values[name] = feature.FeatureValues[index]
	}
	assertNear(t, values["duration"], 0.5)
	assertNear(t, values["packet_count"], 2)
	assertNear(t, values["total_bytes"], 300)
	assertNear(t, values["packets_per_second"], 4)
	assertNear(t, values["bytes_per_second"], 600)
	assertNear(t, values["upload_packets"], 1)
	assertNear(t, values["download_packets"], 1)
	assertNear(t, values["upload_download_ratio"], 0.5)
	assertNear(t, values["mean_interarrival_time"], 0.5)
}

func TestFixedDurationWindowFinalizesOnNextPacket(t *testing.T) {
	service := New(Config{WindowDuration: 10 * time.Second})
	start := time.Unix(100, 0)
	flowID := observe(t, service, Packet{SessionID: "session", Protocol: flowv1.FlowProtocol_ESP, SourceAddress: "a", DestinationAddress: "b", Size: 100, SeenAt: start})
	observe(t, service, Packet{SessionID: "session", Protocol: flowv1.FlowProtocol_ESP, SourceAddress: "b", DestinationAddress: "a", Size: 100, SeenAt: start.Add(time.Second)})
	observe(t, service, Packet{SessionID: "session", Protocol: flowv1.FlowProtocol_ESP, SourceAddress: "a", DestinationAddress: "b", Size: 100, SeenAt: start.Add(10 * time.Second)})
	record, err := service.Flow(context.Background(), flowID)
	if err != nil || len(record.windows) != 1 {
		t.Fatalf("finalized windows=%v error=%v", record.windows, err)
	}
	window, _ := service.Window(context.Background(), record.windows[0])
	if len(window.packets) != 2 || window.reason != "WINDOW_DURATION" {
		t.Fatalf("window=%+v", window)
	}
}

func TestBlockingCaptureBackpressureIsRejected(t *testing.T) {
	service := New(Config{})
	if _, _, err := service.Subscribe(context.Background(), "session", flowv1.FeatureBackpressurePolicy_BLOCK_CAPTURE, 1); err == nil {
		t.Fatal("unsafe BLOCK_CAPTURE policy was accepted")
	}
}

func TestSinglePacketWindowIsNotPublishedForML(t *testing.T) {
	service := New(Config{})
	stream, cancel, err := service.Subscribe(context.Background(), "session", flowv1.FeatureBackpressurePolicy_DROP_FEATURE_WINDOW, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	flowID := observe(t, service, Packet{SessionID: "session", Protocol: flowv1.FlowProtocol_ESP, SourceAddress: "a", DestinationAddress: "b", Size: 100, SeenAt: time.Unix(1, 0)})
	if err := service.FinalizeFlow(context.Background(), flowID, "TEST"); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-stream:
		t.Fatalf("invalid window %q was published", id)
	default:
	}
	if warnings := service.Warnings(); len(warnings) != 1 || warnings[0].Reason != "INSUFFICIENT_WINDOW_DATA" {
		t.Fatalf("warnings=%+v", warnings)
	}
}

func TestStopForSessionDeliversFinalUsableWindowBeforeClosingStream(t *testing.T) {
	service := New(Config{})
	ctx := context.Background()
	stream, cancel, err := service.Subscribe(ctx, "session", flowv1.FeatureBackpressurePolicy_DROP_FEATURE_WINDOW, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	start := time.Now().UTC()
	observe(t, service, Packet{SessionID: "session", Protocol: flowv1.FlowProtocol_ESP, SourceAddress: "192.0.2.1", DestinationAddress: "198.51.100.1", Size: 128, SeenAt: start})
	observe(t, service, Packet{SessionID: "session", Protocol: flowv1.FlowProtocol_ESP, SourceAddress: "192.0.2.1", DestinationAddress: "198.51.100.1", Size: 128, SeenAt: start.Add(time.Second)})
	if err := service.StopForSession(ctx, "session"); err != nil {
		t.Fatal(err)
	}
	select {
	case id, ok := <-stream:
		if !ok || id == "" {
			t.Fatalf("final window was not delivered: id=%q ok=%v", id, ok)
		}
		window, err := service.Window(ctx, id)
		if err != nil || !window.IsMLReady() {
			t.Fatalf("final window readiness = %v, err=%v", window != nil && window.IsMLReady(), err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for final feature window")
	}
	if _, ok := <-stream; ok {
		t.Fatal("stream remained open after session stop")
	}
}

func observe(t *testing.T, service *Service, packet Packet) string {
	t.Helper()
	id, err := service.ObservePacket(context.Background(), packet)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func assertNear(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("got %v, want %v", got, want)
	}
}
