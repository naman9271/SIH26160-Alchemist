// Package network provides host network-interface discovery and counters.
package network

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	shared "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/domain/sensor"
)

type Interface struct {
	Name             string
	Index            int32
	MACAddress       string
	Addresses        []string
	Up               bool
	Loopback         bool
	CaptureSupported bool
}

type Counters struct {
	RXPackets uint64
	TXPackets uint64
	RXBytes   uint64
	TXBytes   uint64
}

type Stats struct {
	Counters
	RXBytesPerSecond float64
	TXBytesPerSecond float64
}

type CounterReader interface {
	ReadCounters(context.Context, string) (Counters, error)
}

type CaptureSupport interface{ Available() bool }

type sample struct {
	counters Counters
	at       time.Time
}

type Service struct {
	reader  CounterReader
	support CaptureSupport
	mu      sync.Mutex
	samples map[string]sample
}

func New(reader CounterReader, support CaptureSupport) *Service {
	if reader == nil {
		reader = hostCounterReader{}
	}
	return &Service{reader: reader, support: support, samples: make(map[string]sample)}
}

func (s *Service) List(ctx context.Context) ([]Interface, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, shared.NewError(shared.Unavailable, "", "host interfaces are unavailable")
	}
	items := make([]Interface, 0, len(interfaces))
	for _, iface := range interfaces {
		item, err := s.toInterface(iface)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func (s *Service) Get(ctx context.Context, name string) (Interface, error) {
	if err := contextError(ctx); err != nil {
		return Interface{}, err
	}
	if strings.TrimSpace(name) == "" {
		return Interface{}, shared.NewError(shared.InvalidArgument, "", "interface_name is required")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return Interface{}, shared.NewError(shared.NotFound, shared.InterfaceNotFound, "network interface was not found")
	}
	return s.toInterface(*iface)
}

func (s *Service) Stats(ctx context.Context, name string) (Stats, error) {
	if _, err := s.Get(ctx, name); err != nil {
		return Stats{}, err
	}
	counters, err := s.reader.ReadCounters(ctx, name)
	if err != nil {
		return Stats{}, err
	}
	now := time.Now()
	stats := Stats{Counters: counters}
	s.mu.Lock()
	previous, found := s.samples[name]
	s.samples[name] = sample{counters: counters, at: now}
	s.mu.Unlock()
	if !found || !now.After(previous.at) || counters.RXBytes < previous.counters.RXBytes || counters.TXBytes < previous.counters.TXBytes {
		return stats, nil
	}
	elapsed := now.Sub(previous.at).Seconds()
	stats.RXBytesPerSecond = float64(counters.RXBytes-previous.counters.RXBytes) / elapsed
	stats.TXBytesPerSecond = float64(counters.TXBytes-previous.counters.TXBytes) / elapsed
	return stats, nil
}

func (s *Service) toInterface(iface net.Interface) (Interface, error) {
	addresses, err := iface.Addrs()
	if err != nil {
		return Interface{}, shared.NewError(shared.Unavailable, "", "interface addresses are unavailable")
	}
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, address.String())
	}
	loopback := iface.Flags&net.FlagLoopback != 0
	up := iface.Flags&net.FlagUp != 0
	available := s.support != nil && s.support.Available()
	return Interface{Name: iface.Name, Index: int32(iface.Index), MACAddress: iface.HardwareAddr.String(), Addresses: values, Up: up, Loopback: loopback, CaptureSupported: available && up && !loopback}, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return shared.NewError(shared.InvalidArgument, "", "context is required")
	}
	return ctx.Err()
}
