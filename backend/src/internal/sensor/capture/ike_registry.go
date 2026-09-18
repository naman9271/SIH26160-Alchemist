package capture

import (
	"encoding/binary"
	"fmt"
)

// IKETransform is a non-secret transform descriptor taken from a clear-text
// IKE SA payload.  Name is stable presentation data; ID and KeyLengthBits
// preserve the wire evidence for future registry revisions.
type IKETransform struct {
	Type          uint8
	ID            uint16
	Name          string
	KeyLengthBits uint16
}

// IKEProposal preserves proposal boundaries.  IKEv2 responses select one
// proposal; requests are offers and must never be treated as negotiated facts.
type IKEProposal struct {
	Number     uint8
	ProtocolID uint8
	SPI        string
	Selected   bool
	Transforms []IKETransform
}

func ikeTransformName(kind uint8, id uint16, keyLength uint16) string {
	name := ""
	switch kind {
	case 1:
		name = map[uint16]string{1: "DES-IV64", 2: "DES", 3: "3DES", 4: "RC5", 5: "IDEA", 6: "CAST", 7: "BLOWFISH", 8: "3IDEA", 9: "DES-IV32", 11: "NULL", 12: "AES-CBC", 13: "AES-CTR", 14: "AES-CCM-8", 15: "AES-CCM-12", 16: "AES-CCM-16", 18: "AES-GCM-8", 19: "AES-GCM-12", 20: "AES-GCM-16", 23: "CAMELLIA-CBC", 24: "CAMELLIA-CTR", 25: "CAMELLIA-CCM-8", 26: "CAMELLIA-CCM-12", 27: "CAMELLIA-CCM-16", 28: "CHACHA20-POLY1305"}[id]
	case 2:
		name = map[uint16]string{1: "PRF-HMAC-MD5", 2: "PRF-HMAC-SHA1", 3: "PRF-HMAC-TIGER", 4: "PRF-AES128-XCBC", 5: "PRF-HMAC-SHA2-256", 6: "PRF-HMAC-SHA2-384", 7: "PRF-HMAC-SHA2-512", 8: "PRF-AES128-CMAC", 9: "PRF-HMAC-STREEBOG-512"}[id]
	case 3:
		name = map[uint16]string{0: "NONE", 1: "HMAC-MD5-96", 2: "HMAC-SHA1-96", 3: "DES-MAC", 4: "KPDK-MD5", 5: "AES-XCBC-96", 6: "HMAC-MD5-128", 7: "HMAC-SHA1-160", 8: "AES-CMAC-96", 9: "AES-128-GMAC", 10: "AES-192-GMAC", 11: "AES-256-GMAC", 12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192", 14: "HMAC-SHA2-512-256"}[id]
	case 4:
		name = map[uint16]string{1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048", 15: "MODP-3072", 16: "MODP-4096", 17: "MODP-6144", 18: "MODP-8192", 19: "ECP-256", 20: "ECP-384", 21: "ECP-521", 31: "CURVE25519", 32: "CURVE448"}[id]
	case 5:
		name = map[uint16]string{0: "NO-ESN", 1: "ESN"}[id]
	}
	if name == "" {
		return fmt.Sprintf("UNKNOWN-%d-%d", kind, id)
	}
	if kind == 1 && keyLength != 0 && variableKeyLengthTransform(id) {
		return fmt.Sprintf("%s-%d", name, keyLength)
	}
	return name
}

func variableKeyLengthTransform(id uint16) bool {
	switch id {
	case 6, 7, 12, 13, 14, 15, 16, 18, 19, 20, 23, 24, 25, 26, 27:
		return true
	default:
		return false
	}
}

func proposalTransform(attributes []byte, kind uint8, id uint16) IKETransform {
	transform := IKETransform{Type: kind, ID: id}
	for len(attributes) >= 4 {
		typeAndFlag, value := binary.BigEndian.Uint16(attributes[:2]), binary.BigEndian.Uint16(attributes[2:4])
		attributeType := typeAndFlag & 0x7fff
		if typeAndFlag&0x8000 == 0 {
			length := int(value)
			if length > len(attributes)-4 {
				break
			}
			attributes = attributes[4+length:]
			continue
		}
		if attributeType == 14 {
			transform.KeyLengthBits = value
		} // IKEv2 KEY_LENGTH
		attributes = attributes[4:]
	}
	transform.Name = ikeTransformName(kind, id, transform.KeyLengthBits)
	return transform
}

func validTransformAttributes(attributes []byte) bool {
	for len(attributes) > 0 {
		if len(attributes) < 4 {
			return false
		}
		typeAndFlag, value := binary.BigEndian.Uint16(attributes[:2]), binary.BigEndian.Uint16(attributes[2:4])
		if typeAndFlag&0x8000 != 0 {
			attributes = attributes[4:]
			continue
		}
		length := int(value)
		if length > len(attributes)-4 {
			return false
		}
		attributes = attributes[4+length:]
	}
	return true
}
