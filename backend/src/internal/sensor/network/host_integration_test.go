package network

import (
	"context"
	"testing"
	"time"

	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

func TestHostInterfaceDiscoveryAndCounters(t *testing.T) {
	service := New(nil, nil)
	interfaces, err := service.List(context.Background())
	if err != nil || len(interfaces) == 0 {
		t.Fatalf("host interface discovery = %v, %v", interfaces, err)
	}
	metadata, err := service.Get(context.Background(), interfaces[0].Name)
	if err != nil || metadata.Name != interfaces[0].Name || metadata.Index <= 0 {
		t.Fatalf("host interface metadata = %+v, %v", metadata, err)
	}
	first, err := service.Stats(context.Background(), metadata.Name)
	if err != nil {
		if sensorError, ok := err.(*shared.Error); ok && sensorError.Category == shared.Unavailable {
			t.Logf("host interface counters unavailable: %s", sensorError.Message)
			return
		}
		t.Fatalf("host interface counters: %v", err)
	}
	if first.RXBytesPerSecond != 0 || first.TXBytesPerSecond != 0 {
		t.Fatalf("first counter sample must have zero rates: %+v", first)
	}
	time.Sleep(15 * time.Millisecond)
	second, err := service.Stats(context.Background(), metadata.Name)
	if err != nil {
		t.Fatalf("second host interface counters: %v", err)
	}
	if second.RXBytes < first.RXBytes || second.TXBytes < first.TXBytes {
		t.Fatalf("host counters moved backwards without a reset: first=%+v second=%+v", first, second)
	}
}
