//go:build linux

package network

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

type hostCounterReader struct{}

func (hostCounterReader) ReadCounters(ctx context.Context, name string) (Counters, error) {
	if err := contextError(ctx); err != nil {
		return Counters{}, err
	}
	read := func(direction, metric string) (uint64, error) {
		value, err := os.ReadFile(filepath.Join("/sys/class/net", name, "statistics", direction+"_"+metric))
		if err != nil {
			return 0, err
		}
		return strconv.ParseUint(strings.TrimSpace(string(value)), 10, 64)
	}
	rxPackets, err := read("rx", "packets")
	if err != nil {
		return Counters{}, counterError(name, err)
	}
	txPackets, err := read("tx", "packets")
	if err != nil {
		return Counters{}, counterError(name, err)
	}
	rxBytes, err := read("rx", "bytes")
	if err != nil {
		return Counters{}, counterError(name, err)
	}
	txBytes, err := read("tx", "bytes")
	if err != nil {
		return Counters{}, counterError(name, err)
	}
	return Counters{RXPackets: rxPackets, TXPackets: txPackets, RXBytes: rxBytes, TXBytes: txBytes}, nil
}

func counterError(name string, err error) error {
	return shared.NewError(shared.Unavailable, "", fmt.Sprintf("interface counters are unavailable for %s: %v", name, err))
}
