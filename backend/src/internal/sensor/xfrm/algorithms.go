package xfrm

import "strings"

// aeadKeyLengths converts the Linux XFRM representation (cipher key plus
// algorithm salt) into the cryptographic key length analysts expect.
func aeadKeyLengths(name string, rawBytes int) (keyBits, saltBits uint32) {
	saltBytes := 0
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "rfc4106"), strings.Contains(lower, "rfc4543"), strings.Contains(lower, "rfc7539"):
		saltBytes = 4
	case strings.Contains(lower, "rfc4309"):
		saltBytes = 3
	}
	if rawBytes < saltBytes {
		return uint32(rawBytes * 8), 0
	}
	return uint32((rawBytes - saltBytes) * 8), uint32(saltBytes * 8)
}
