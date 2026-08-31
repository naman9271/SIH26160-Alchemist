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
	bySession map[string][]capture.PacketMetadata
}

func New() *Service { return &Service{bySession: make(map[string][]capture.PacketMetadata)} }

func (s *Service) Observe(_ context.Context, packet capture.PacketMetadata) error {
	if s == nil || packet.SessionID == "" {
		return nil
	}
	s.mu.Lock()
	s.bySession[packet.SessionID] = append(s.bySession[packet.SessionID], packet)
	s.mu.Unlock()
	return nil
}

func (s *Service) List(_ context.Context, sessionID string) []capture.PacketMetadata {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	items := append([]capture.PacketMetadata(nil), s.bySession[sessionID]...)
	s.mu.RUnlock()
	sort.SliceStable(items, func(i, j int) bool { return items[i].SeenAt.Before(items[j].SeenAt) })
	return items
}

func (s *Service) Reset(_ context.Context, sessionID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.bySession, sessionID)
	s.mu.Unlock()
}
