//go:build linux

package system

import (
	"os"
	"strconv"
	"strings"
)

// residentBytes reads the Linux kernel's current process RSS. The fallback
// retains a useful runtime memory measurement if procfs is unavailable.
func residentBytes(fallback uint64) uint64 {
	contents, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return fallback
	}
	fields := strings.Fields(string(contents))
	if len(fields) < 2 {
		return fallback
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return fallback
	}
	return pages * uint64(os.Getpagesize())
}
