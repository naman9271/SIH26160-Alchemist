package vici

import (
	"strings"
	"testing"
	"time"

	govici "github.com/strongswan/govici/vici"
)

func message(values map[string]any) *govici.Message {
	result := govici.NewMessage()
	for key, value := range values {
		_ = result.Set(key, value)
	}
	return result
}

func TestDecodeNestedIKEAndChildState(t *testing.T) {
	child := message(map[string]any{
		"uniqueid": "22", "reqid": "7", "mode": "tunnel", "protocol": "esp",
		"spi-in": "c0ffee01", "spi-out": "0x01020304", "encr-alg": "AES_GCM_16",
		"encr-keysize": "256", "dh-group": "CURVE_25519", "esn": "yes",
		"install-time": "30", "rekey-time": "120", "life-time": "180",
	})
	children := message(map[string]any{"net": child})
	ikeMessage := message(map[string]any{
		"uniqueid": "11", "version": "2", "encr-alg": "AES_CBC", "encr-keysize": "256",
		"integ-alg": "HMAC_SHA2_256_128", "integ-keysize": "256", "child-sas": children,
	})
	observed := time.Date(2026, 9, 18, 10, 0, 0, 0, time.UTC)
	ike := decodeIkeAt("office", ikeMessage, observed)
	if ike.GetIkeVersion() != "IKEv2" || ike.GetEncryptionKeySize() != 256 || ike.GetIntegrityKeySize() != 256 {
		t.Fatalf("unexpected IKE decode: %+v", ike)
	}
	if len(ike.GetAssociatedChildSas()) != 1 {
		t.Fatalf("child count = %d, want 1", len(ike.GetAssociatedChildSas()))
	}
	decoded := ike.GetAssociatedChildSas()[0]
	if decoded.GetSpiIn() != 0xc0ffee01 || decoded.GetSpiOut() != 0x01020304 || !decoded.GetExtendedSequenceNumbers() {
		t.Fatalf("unexpected CHILD decode: %+v", decoded)
	}
	if got := decoded.GetInstallTime().AsTime(); !got.Equal(observed.Add(-30 * time.Second)) {
		t.Fatalf("install time = %s", got)
	}
	if decoded.GetRekeyTime() != 120 || decoded.GetLifeTime() != 180 {
		t.Fatalf("remaining durations were not preserved: %+v", decoded)
	}
}

func TestDecodeConnectionSeparatesConfiguredPFS(t *testing.T) {
	proposal := message(map[string]any{"encr": []string{"aes256gcm16"}, "ke": []string{"curve25519"}})
	proposals := message(map[string]any{"1": proposal})
	child := message(map[string]any{"mode": "tunnel", "rekey_time": "3600", "esp_proposals": proposals})
	children := message(map[string]any{"net": child})
	auth := message(map[string]any{"class": "pubkey", "id": "gateway.example"})
	connection := decodeConnection("office", message(map[string]any{
		"version": "2", "local_addrs": []string{"10.0.0.1"}, "remote_addrs": []string{"10.0.0.2"},
		"local-1": auth, "children": children,
	}))
	if len(connection.GetAuthentication()) != 1 || connection.GetAuthentication()[0].GetAuthClass() != "pubkey" {
		t.Fatalf("nested authentication was not decoded: %+v", connection)
	}
	configured := connection.GetConfiguredChildren()
	if len(configured) != 1 || strings.Join(configured[0].GetConfiguredPfsGroups(), ",") != "curve25519" {
		t.Fatalf("configured CHILD PFS was not decoded: %+v", configured)
	}
}

func TestCertificateDecoderDoesNotReturnRawCertificate(t *testing.T) {
	raw := "private-looking-binary-value"
	certificate := decodeCertificate(message(map[string]any{"type": "X509", "data": raw}))
	if certificate.GetFingerprint() == "" {
		t.Fatal("expected a sanitized fingerprint")
	}
	if strings.Contains(certificate.String(), raw) {
		t.Fatal("raw certificate data crossed the adapter boundary")
	}
}
