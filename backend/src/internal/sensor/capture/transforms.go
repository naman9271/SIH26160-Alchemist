package capture

import (
	"encoding/binary"
	"fmt"
)

// RegistryVersion pins the reviewed subset of IANA's IKEv2 transform registry.
// Unrecognized transforms retain their numeric ID and never imply a safe suite.
const RegistryVersion = "iana-ikev2-2026-09-17.v1"

type IKETransform struct {
	Type uint8 `json:"type"`
	ID uint16 `json:"id"`
	KeyBits uint16 `json:"key_bits,omitempty"`
	Name string `json:"name"`
}
type IKEProposal struct {
	Number uint8 `json:"number"`
	Protocol uint8 `json:"protocol"`
	SPI string `json:"spi,omitempty"`
	Transforms []IKETransform `json:"transforms"`
}

func transformLabel(kind uint8, id, bits uint16) string {
	names := map[uint8]map[uint16]string{
		1: {1:"DES-IV64", 2:"DES", 3:"3DES", 11:"NULL", 12:"AES-CBC", 13:"AES-CTR", 18:"AES-GCM-8", 19:"AES-GCM-12", 20:"AES-GCM-16", 28:"CHACHA20-POLY1305"},
		2: {1:"PRF-HMAC-MD5", 2:"PRF-HMAC-SHA1", 5:"PRF-HMAC-SHA256", 6:"PRF-HMAC-SHA384", 7:"PRF-HMAC-SHA512"},
		3: {0:"NONE", 1:"HMAC-MD5-96", 2:"HMAC-SHA1-96", 12:"HMAC-SHA256-128", 13:"HMAC-SHA384-192", 14:"HMAC-SHA512-256"},
		4: {0:"NONE", 1:"MODP768", 2:"MODP1024", 5:"MODP1536", 14:"MODP2048", 15:"MODP3072", 16:"MODP4096", 17:"MODP6144", 18:"MODP8192", 19:"ECP256", 20:"ECP384", 21:"ECP521", 31:"CURVE25519", 32:"CURVE448"},
		5: {0:"NO-ESN", 1:"ESN"},
	}
	name, ok := names[kind][id]
	if !ok { return fmt.Sprintf("UNKNOWN-TRANSFORM-%d-%d", kind, id) }
	if bits > 0 { name = fmt.Sprintf("%s-%d", name, bits) }
	return name
}

func parseTransform(part []byte) (IKETransform, bool) {
	t := IKETransform{Type:part[4], ID:binary.BigEndian.Uint16(part[6:8])}
	attributes := part[8:]
	for len(attributes) > 0 {
		if len(attributes) < 4 { return t, false }
		kind, value := binary.BigEndian.Uint16(attributes[:2]), binary.BigEndian.Uint16(attributes[2:4])
		attributes = attributes[4:]
		if kind&0x8000 == 0 {
			if int(value) > len(attributes) { return t, false }
			if kind == 14 { if value != 2 { return t, false }; t.KeyBits = binary.BigEndian.Uint16(attributes[:2]) }
			attributes = attributes[value:]
		} else if kind&0x7fff == 14 { t.KeyBits = value }
	}
	t.Name = transformLabel(t.Type, t.ID, t.KeyBits)
	return t, true
}
