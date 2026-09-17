package analysis

import (
	"testing"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	viciv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/vici"
	xfrmv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/xfrm"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/ingest"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestTelemetryMappersExportSanitizedFusionEvidence(t *testing.T) {
	now := timestamppb.New(time.Now().UTC())
	viciItems := VICIEvidence(&viciv1.GatewaySnapshot{SnapshotTimestamp: now, IkeSas: []*viciv1.IkeSa{{Name: "ike", UniqueId: 1, IkeVersion: "IKEv2", State: "ESTABLISHED", EncryptionAlgorithm: "AES_GCM_16", DhGroup: "CURVE_25519"}}, ChildSas: []*viciv1.ChildSa{{Name: "child", UniqueId: 2, SpiIn: 1, SpiOut: 2, Protocol: "ESP", Mode: "TUNNEL", EncryptionAlgorithm: "AES_GCM_16", PacketsIn: 4, BytesIn: 8}}})
	if !hasEvidence(viciItems, "ike.version") || !hasEvidence(viciItems, "child.mode") || !hasEvidence(viciItems, "child.encryption_algorithm") || !hasEvidence(viciItems, "child.packets_in") {
		t.Fatalf("VICI evidence missing expected fields: %#v", viciItems)
	}
	if hasEvidence(viciItems, "child.esp_encryption") || hasEvidence(viciItems, "child.integrity") || !allStatus(viciItems, commonv1.EvidenceStatus_VERIFIED_GATEWAY) {
		t.Fatalf("VICI evidence violated canonical gateway contract: %#v", viciItems)
	}
	xfrmItems := XFRMEvidence(&xfrmv1.KernelSnapshot{SnapshotTimestamp: now, States: []*xfrmv1.XfrmState{{Source: "192.0.2.1", Destination: "198.51.100.1", Protocol: "ESP", Spi: 7, Mode: "TUNNEL", EncryptionAlgorithm: "cbc(aes)", ReplayWindow: 32, Packets: 4, Bytes: 32}}, Policies: []*xfrmv1.XfrmPolicy{{Reqid: 1, Direction: "OUT", SourceSelector: "10.0.0.0/24", DestinationSelector: "10.1.0.0/24", Mode: "TUNNEL", Protocol: "ESP"}}})
	if !hasEvidence(xfrmItems, "esp.state") || !hasEvidence(xfrmItems, "replay.window") || !hasEvidence(xfrmItems, "xfrm.policy.destination_selector") {
		t.Fatalf("XFRM evidence missing expected fields: %#v", xfrmItems)
	}
}
func hasEvidence(items []ingest.EvidenceInput, key string) bool {
	for _, item := range items {
		if item.PropertyKey == key {
			return true
		}
	}
	return false
}

func allStatus(items []ingest.EvidenceInput, status commonv1.EvidenceStatus) bool {
	for _, item := range items {
		if item.Status != status {
			return false
		}
	}
	return true
}
