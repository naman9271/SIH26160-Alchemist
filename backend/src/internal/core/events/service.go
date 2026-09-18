// Package events owns Core-originated events that do not originate in Fusion.
package events

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	eventv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/event"
)

type Event struct {
	ID         string
	Sequence   uint64
	AnalysisID string
	Category   eventv1.CoreEventCategory
	OccurredAt time.Time
	Payload    map[string]any
}
type Service struct {
	mu             sync.Mutex
	next           uint64
	subscribers    map[uint64]chan Event
	nextSubscriber uint64
	buffer         int
}

func New() *Service { return &Service{subscribers: map[uint64]chan Event{}, buffer: 256} }
func (s *Service) SetBufferSize(size uint32) {
	if s == nil || size == 0 {
		return
	}
	s.mu.Lock()
	s.buffer = int(size)
	s.mu.Unlock()
}
func (s *Service) Publish(ctx context.Context, analysisID string, category eventv1.CoreEventCategory) {
	s.PublishPayload(ctx, analysisID, category, nil)
}

// PublishPayload uses the established Core event stream for small, sanitized
// result metadata such as a monotonic snapshot version. It never carries packet
// bodies, XFRM key material, or gateway credentials.
func (s *Service) PublishPayload(_ context.Context, analysisID string, category eventv1.CoreEventCategory, payload map[string]any) {
	if s == nil {
		return
	}
	id, _ := uuid.NewV7()
	s.mu.Lock()
	s.next++
	event := Event{ID: id.String(), Sequence: s.next, AnalysisID: analysisID, Category: category, OccurredAt: time.Now().UTC(), Payload: clonePayload(payload)}
	for _, ch := range s.subscribers {
		select {
		case ch <- event:
		default:
		}
	}
	s.mu.Unlock()
}

func clonePayload(value map[string]any) map[string]any {
	if len(value) == 0 {
		return nil
	}
	result := make(map[string]any, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}
func (s *Service) Subscribe(ctx context.Context) (<-chan Event, func()) {
	s.mu.Lock()
	buffer := s.buffer
	s.mu.Unlock()
	ch := make(chan Event, buffer)
	s.mu.Lock()
	s.nextSubscriber++
	id := s.nextSubscriber
	s.subscribers[id] = ch
	s.mu.Unlock()
	cancel := func() {
		s.mu.Lock()
		if current, ok := s.subscribers[id]; ok {
			delete(s.subscribers, id)
			close(current)
		}
		s.mu.Unlock()
	}
	go func() { <-ctx.Done(); cancel() }()
	return ch, cancel
}
