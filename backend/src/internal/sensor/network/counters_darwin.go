//go:build darwin

package network

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

type hostCounterReader struct{}

func (hostCounterReader) ReadCounters(ctx context.Context, name string) (Counters, error) {
	if err := contextError(ctx); err != nil {
		return Counters{}, err
	}
	output, err := exec.CommandContext(ctx, "netstat", "-ibn").Output()
	if err != nil {
		return Counters{}, shared.NewError(shared.Unavailable, "", "interface counters are unavailable")
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[0] != name || !strings.HasPrefix(fields[2], "<Link#") {
			continue
		}
		values := []int{4, 6, 7, 9}
		parsed := make([]uint64, len(values))
		valid := true
		for i, index := range values {
			parsed[i], err = strconv.ParseUint(fields[index], 10, 64)
			if err != nil {
				valid = false
				break
			}
		}
		if valid {
			return Counters{RXPackets: parsed[0], RXBytes: parsed[1], TXPackets: parsed[2], TXBytes: parsed[3]}, nil
		}
	}
	return Counters{}, shared.NewError(shared.Unavailable, "", fmt.Sprintf("interface counters are unavailable for %s", name))
}
