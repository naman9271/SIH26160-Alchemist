package capture

import (
	"context"
	"net"
	"testing"
	"time"

	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

func TestTCPDumpBackendAvailabilityAndPrivilegeBoundary(t *testing.T) {
	engine := NewTCPDumpEngine()
	if !engine.Available() {
		t.Log("tcpdump is not installed; live capture correctly reports UNAVAILABLE")
		return
	}
	if err := engine.ValidateFilter(context.Background(), ipsecFilter); err != nil {
		if sensorError, ok := err.(*shared.Error); ok && sensorError.Category == shared.Unavailable {
			t.Logf("BPF compilation permission/platform limitation: %s", sensorError.Message)
			return
		}
		t.Fatalf("tcpdump must compile the IPsec filter: %v", err)
	}
	if err := engine.ValidateFilter(context.Background(), "this is not valid BPF"); err == nil {
		t.Fatal("tcpdump accepted invalid BPF")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) == 0 {
		t.Logf("host interface discovery is unavailable in this sandbox: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	handle, err := engine.Start(ctx, Config{InterfaceName: interfaces[0].Name, Filter: ipsecFilter, MaxDuration: time.Second})
	if err != nil {
		if sensorError, ok := err.(*shared.Error); ok && sensorError.Category == shared.Unavailable {
			t.Logf("live capture permission/platform limitation: %s", sensorError.Message)
			return
		}
		t.Fatalf("start tcpdump backend: %v", err)
	}
	if err := handle.Stop(ctx); err != nil {
		t.Fatalf("stop tcpdump backend: %v", err)
	}
}
