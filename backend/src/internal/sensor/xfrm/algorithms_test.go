package xfrm

import "testing"

func TestAEADKeyLengthsRemoveAlgorithmSalt(t *testing.T) {
	tests := []struct {
		name string
		raw  int
		key  uint32
		salt uint32
	}{
		{"rfc4106(gcm(aes))", 20, 128, 32},
		{"rfc4106(gcm(aes))", 36, 256, 32},
		{"rfc4309(ccm(aes))", 19, 128, 24},
		{"rfc7539esp(chacha20,poly1305)", 36, 256, 32},
		{"unknown-aead", 16, 128, 0},
	}
	for _, test := range tests {
		key, salt := aeadKeyLengths(test.name, test.raw)
		if key != test.key || salt != test.salt {
			t.Fatalf("%s: got key=%d salt=%d, want key=%d salt=%d", test.name, key, salt, test.key, test.salt)
		}
	}
}
