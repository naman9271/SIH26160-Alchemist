//go:build !linux

package system

// Non-Linux platforms do not expose procfs. Go's OS-obtained memory total is
// the portable fallback until a platform-native process metrics provider is
// supplied.
func residentBytes(fallback uint64) uint64 { return fallback }
