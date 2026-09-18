package analysis

import (
	"testing"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	viciv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/vici"
	xfrmv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/xfrm"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/ingest"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/capture"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestTelemetryMappersExportSanitizedFusionEvidence(t *testing.T) {
	now := timestamppb.New(time.Now().UTC())
	child := &viciv1.ChildSa{Name: "child", UniqueId: 2, Reqid: 9, SpiIn: 1, SpiOut: 2, Protocol: "ESP", Mode: "TUNNEL", EncryptionAlgorithm: "AES_GCM_16", PacketsIn: 4, BytesIn: 8}
	viciItems := VICIEvidence(&viciv1.GatewaySnapshot{SnapshotTimestamp: now, IkeSas: []*viciv1.IkeSa{{Name: "ike", UniqueId: 1, IkeVersion: "IKEv2", State: "ESTABLISHED", LocalHost: "192.0.2.1", RemoteHost: "198.51.100.1", InitiatorSpi: "a", ResponderSpi: "b", EncryptionAlgorithm: "AES_GCM_16", DhGroup: "CURVE_25519", AssociatedChildSas: []*viciv1.ChildSa{child}}}})
	if !hasEvidence(viciItems, "ike.version") || !hasEvidence(viciItems, "child.mode") || !hasEvidence(viciItems, "child.encryption_algorithm") || !hasEvidence(viciItems, "child.packets_in") {
		t.Fatalf("VICI evidence missing expected fields: %#v", viciItems)
	}
	if hasEvidence(viciItems, "child.esp_encryption") || hasEvidence(viciItems, "child.integrity") || !allStatus(viciItems, commonv1.EvidenceStatus_VERIFIED_GATEWAY) {
		t.Fatalf("VICI evidence violated canonical gateway contract: %#v", viciItems)
	}
	for _, item := range viciItems {
		if item.SourceReference == "" || item.Metadata["evidence_reference"] == "" || item.Metadata["uncertainty_reason"] == "" {
			t.Fatalf("gateway evidence lacks provenance: %#v", item)
		}
	}
	childMode := evidenceFor(viciItems, "child.mode")
	if childMode.SourceReference == "" || childMode.Metadata["parent_ike_resource_id"] == "" || childMode.Metadata["esp_directional_wire_in"] == "" || childMode.Metadata["suite_disposition"] != "installed" {
		t.Fatalf("VICI CHILD provenance/correlation metadata missing: %#v", childMode)
	}
	xfrmItems := XFRMEvidence(&xfrmv1.KernelSnapshot{SnapshotTimestamp: now, States: []*xfrmv1.XfrmState{{Source: "192.0.2.1", Destination: "198.51.100.1", Protocol: "ESP", Spi: 7, Mode: "TUNNEL", EncryptionAlgorithm: "cbc(aes)", ReplayWindow: 32, Packets: 4, Bytes: 32}}, Policies: []*xfrmv1.XfrmPolicy{{Reqid: 1, Direction: "OUT", SourceSelector: "10.0.0.0/24", DestinationSelector: "10.1.0.0/24", Mode: "TUNNEL", Protocol: "ESP"}}})
	if !hasEvidence(xfrmItems, "esp.state") || !hasEvidence(xfrmItems, "replay.window") || !hasEvidence(xfrmItems, "xfrm.policy.destination_selector") {
		t.Fatalf("XFRM evidence missing expected fields: %#v", xfrmItems)
	}
	if item := evidenceFor(xfrmItems, "esp.spi"); item.SourceReference == "" || item.Metadata["esp_directional_wire"] == "" {
		t.Fatalf("XFRM directional identity/provenance missing: %#v", item)
	}
}

func TestPacketEvidenceNeverPromotesAnOfferToNegotiatedCrypto(t *testing.T) {
	offer := capture.PacketMetadata{SessionID: "s", IKE: true, IKEVersion: "IKEv2", IKEProposals: []capture.IKEProposal{{Number: 1, ProtocolID: 1, Transforms: []capture.IKETransform{{Type: 1, ID: 12, Name: "AES-CBC-128", KeyLengthBits: 128}}}}, SeenAt: time.Now()}
	if hasEvidence(packetEvidence(offer), "ike.encryption") {
		t.Fatal("offered IKE transform was published as negotiated")
	}
	selected := offer
	selected.IKEProposals = append([]capture.IKEProposal(nil), offer.IKEProposals...)
	selected.IKEProposals[0].Selected = true
	selectedEvidence := packetEvidence(selected)
	if !hasEvidence(selectedEvidence, "ike.encryption") {
		t.Fatal("selected IKE transform was not published")
	}
	if item := evidenceFor(selectedEvidence, "ike.encryption"); item.Metadata["transform_id"] != "12" || item.Metadata["key_length_bits"] != "128" || item.Metadata["proposal_disposition"] != "selected" {
		t.Fatalf("wire transform identifiers were not retained: %#v", item)
	}
}

func TestPacketEvidenceKeepsUnknownSelectedTransformUnsupported(t *testing.T) {
	packet := capture.PacketMetadata{
		SessionID: "s", IKE: true, IKEVersion: "IKEv2", IKEInitiatorSPI: 1,
		IKEProposals: []capture.IKEProposal{{Number: 1, ProtocolID: 1, Selected: true, Transforms: []capture.IKETransform{{Type: 1, ID: 65000, Name: "UNKNOWN-1-65000"}}}},
		SeenAt:       time.Now(),
	}
	items := packetEvidence(packet)
	if hasEvidence(items, "ike.encryption") {
		t.Fatal("unknown transform was promoted to a negotiated encryption algorithm")
	}
	unknown := evidenceFor(items, "ike.unsupported_transform")
	if unknown.PropertyKey == "" || unknown.Metadata["transform_id"] != "65000" || unknown.Metadata["transform_supported"] != "false" || unknown.Metadata["uncertainty_reason"] != "UNSUPPORTED_TRANSFORM_IDENTIFIER" {
		t.Fatalf("unknown transform provenance was not retained: %#v", unknown)
	}
}

func TestPassiveSALifecycleKeepsDirectionalAssociationsSeparate(t *testing.T) {
	start := time.Unix(100, 0).UTC()
	packets := []capture.PacketMetadata{
		{SessionID: "capture-1", Protocol: 50, SourceAddress: "192.0.2.1", DestinationAddress: "198.51.100.1", SPI: 1, ESPSequence: 100, SeenAt: start},
		{SessionID: "capture-1", Protocol: 50, SourceAddress: "192.0.2.1", DestinationAddress: "198.51.100.1", SPI: 1, ESPSequence: 101, SeenAt: start.Add(time.Second)},
		{SessionID: "capture-1", Protocol: 50, SourceAddress: "192.0.2.1", DestinationAddress: "198.51.100.1", SPI: 1, ESPSequence: 1, SeenAt: start.Add(2 * time.Second)},
		{SessionID: "capture-1", Protocol: 50, SourceAddress: "192.0.2.1", DestinationAddress: "198.51.100.1", SPI: 2, ESPSequence: 1, SeenAt: start.Add(2 * time.Second)},
	}
	packets = annotatePassiveSAEpochs(packets)
	items := passiveSALifecycleEvidence(packets)
	if countEvidence(items, "sa.first_observed_at") != 3 || countEvidence(items, "sa.last_observed_at") != 3 || countEvidence(items, "sa.possible_rekey_of") != 2 {
		t.Fatalf("passive lifecycle evidence = %#v", items)
	}
	if packets[0].SALifetimeEpoch != 1 || packets[2].SALifetimeEpoch != 2 || packets[0].CurrentSAEpoch || !packets[2].CurrentSAEpoch {
		t.Fatalf("ESP lifetime epochs were not separated: %#v", packets)
	}
	rekey := evidenceFor(items, "sa.possible_rekey_of")
	if rekey.Status != commonv1.EvidenceStatus_DERIVED || rekey.Metadata["uncertainty_reason"] != "PASSIVE_SPI_CHANGE_REQUIRES_GATEWAY_CORROBORATION" {
		t.Fatalf("passive rekey was overclaimed: %#v", rekey)
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

func evidenceFor(items []ingest.EvidenceInput, key string) ingest.EvidenceInput {
	for _, item := range items {
		if item.PropertyKey == key {
			return item
		}
	}
	return ingest.EvidenceInput{}
}

func countEvidence(items []ingest.EvidenceInput, key string) int {
	count := 0
	for _, item := range items {
		if item.PropertyKey == key {
			count++
		}
	}
	return count
}

func allStatus(items []ingest.EvidenceInput, status commonv1.EvidenceStatus) bool {
	for _, item := range items {
		if item.Status != status {
			return false
		}
	}
	return true
}
