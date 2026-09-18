// Package observation retains payload-free protocol observations produced by
// the shared capture pipeline. It is intentionally bounded and never stores
// packet payloads or key material.
package observation

import (
	"context"
	"sort"
	"sync"

	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/capture"
)

// Service is the bridge between packet acquisition and Core evidence export.
type Service struct {
	mu        sync.RWMutex
	bySession map[string]*sessionRecords
	maximum   int
}

type sessionRecords struct {
	firstSequence uint64
	nextSequence  uint64
	dropped       uint64
	items         []record
}
type record struct {
	sequence uint64
	packet   capture.PacketMetadata
}

// Config bounds retained packet metadata. The capture path processes records
// incrementally, so live analysis does not depend on retaining an entire run.
type Config struct{ MaxRecordsPerSession int }

const defaultMaxRecordsPerSession = 20_000

func New(config ...Config) *Service {
	maximum := defaultMaxRecordsPerSession
	if len(config) > 0 && config[0].MaxRecordsPerSession > 0 {
		maximum = config[0].MaxRecordsPerSession
	}
	return &Service{bySession: make(map[string]*sessionRecords), maximum: maximum}
}

func (s *Service) Observe(_ context.Context, packet capture.PacketMetadata) error {
	if s == nil || packet.SessionID == "" {
		return nil
	}
	s.mu.Lock()
	items := s.bySession[packet.SessionID]
	if items == nil {
		items = &sessionRecords{firstSequence: 1, nextSequence: 1}
		s.bySession[packet.SessionID] = items
	}
	items.items = append(items.items, record{sequence: items.nextSequence, packet: packet})
	items.nextSequence++
	if len(items.items) > s.maximum {
		items.items = items.items[1:]
		items.firstSequence++
		items.dropped++
	}
	s.mu.Unlock()
	return nil
}

func (s *Service) List(_ context.Context, sessionID string) []capture.PacketMetadata {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	stored := s.bySession[sessionID]
	items := make([]capture.PacketMetadata, 0)
	if stored != nil {
		for _, item := range stored.items {
			items = append(items, item.packet)
		}
	}
	s.mu.RUnlock()
	sort.SliceStable(items, func(i, j int) bool { return items[i].SeenAt.Before(items[j].SeenAt) })
	return items
}

// ListSince returns payload-free observations newer than afterSequence. If the
// caller fell behind bounded retention, missed is non-zero and the returned
// records begin at the earliest still-retained sequence.
func (s *Service) ListSince(_ context.Context, sessionID string, afterSequence uint64) (items []capture.PacketMetadata, nextSequence, missed uint64) {
	if s == nil {
		return nil, afterSequence, 0
	}
	s.mu.RLock()
	stored := s.bySession[sessionID]
	if stored == nil {
		s.mu.RUnlock()
		return nil, afterSequence, 0
	}
	first := stored.firstSequence
	next := stored.nextSequence
	if afterSequence+1 < first {
		missed = first - (afterSequence + 1)
		afterSequence = first - 1
	}
	items = make([]capture.PacketMetadata, 0, len(stored.items))
	for _, item := range stored.items {
		if item.sequence > afterSequence {
			items = append(items, item.packet)
		}
	}
	s.mu.RUnlock()
	sort.SliceStable(items, func(i, j int) bool { return items[i].SeenAt.Before(items[j].SeenAt) })
	return items, next - 1, missed
}

type RetentionStats struct {
	Retained uint64 `json:"retained"`
	Dropped  uint64 `json:"dropped_packet_metadata"`
}

func (s *Service) RetentionStats(sessionID string) RetentionStats {
	if s == nil {
		return RetentionStats{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	stored := s.bySession[sessionID]
	if stored == nil {
		return RetentionStats{}
	}
	return RetentionStats{Retained: uint64(len(stored.items)), Dropped: stored.dropped}
}

func (s *Service) Reset(_ context.Context, sessionID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.bySession, sessionID)
	s.mu.Unlock()
}
