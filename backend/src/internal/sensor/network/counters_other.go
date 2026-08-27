//go:build !linux && !darwin

package network

import (
	"context"
	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

type hostCounterReader struct{}

func (hostCounterReader) ReadCounters(context.Context, string) (Counters, error) {
	return Counters{}, shared.NewError(shared.Unavailable, "", "interface counters are not supported on this operating system")
}
