// Package event implements the internal server-streaming FusionEventService.
package event

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
)

const defaultHistoryLimit = 10_000
const defaultSubscriberBuffer = 256

type SubscribeRequest struct {
	FusionRunID   string
	Types         []model.EventType
	AfterSequence uint64
}

type Subscription struct {
	Events <-chan model.FusionEvent
	Errors <-chan error
}

type HistoryRequest struct {
	FusionRunID  string
	PropertyKey  string
	ConclusionID string
}

type subscriber struct {
	runID  string
	types  map[model.EventType]struct{}
	events chan model.FusionEvent
	errors chan error
}

type Service struct {
	mu             sync.RWMutex
	nextSequence   uint64
	nextSubscriber uint64
	history        map[string][]model.FusionEvent
	subscribers    map[uint64]*subscriber
	historyLimit   int
	now            func() time.Time
	newID          func() (string, error)
}

func New(historyLimit int) *Service {
	if historyLimit <= 0 {
		historyLimit = defaultHistoryLimit
	}
	return &Service{history: make(map[string][]model.FusionEvent), subscribers: make(map[uint64]*subscriber),
		historyLimit: historyLimit, now: func() time.Time { return time.Now().UTC() }, newID: model.NewFusionEventID}
}

func (s *Service) Publish(ctx context.Context, event model.FusionEvent) error {
	if err := model.ContextError(ctx); err != nil {
		return err
	}
	if s == nil {
		return model.NewError(model.ErrorInternal, "Fusion event service is not configured")
	}
	if err := model.ValidateRunID(event.FusionRunID); err != nil {
		return err
	}
	if !event.Type.Valid() {
		return model.NewError(model.ErrorInvalidArgument, "Fusion event type is invalid")
	}
	if event.ID == "" {
		id, err := s.newID()
		if err != nil {
			return &model.Error{Kind: model.ErrorInternal, Message: "could not generate Fusion event ID", Cause: err}
		}
		event.ID = id
	} else if err := model.ValidateFusionEventID(event.ID); err != nil {
		return err
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = s.now().UTC()
	} else {
		event.OccurredAt = event.OccurredAt.UTC()
	}

	s.mu.Lock()
	s.nextSequence++
	event.Sequence = s.nextSequence
	event = event.Clone()
	history := append(s.history[event.FusionRunID], event)
	if len(history) > s.historyLimit {
		history = append([]model.FusionEvent(nil), history[len(history)-s.historyLimit:]...)
	}
	s.history[event.FusionRunID] = history
	for id, candidate := range s.subscribers {
		if !matches(candidate, event) {
			continue
		}
		select {
		case candidate.events <- event.Clone():
		default:
			candidate.errors <- model.NewError(model.ErrorResourceExhausted, "Fusion event subscriber could not keep up")
			close(candidate.events)
			close(candidate.errors)
			delete(s.subscribers, id)
		}
	}
	s.mu.Unlock()
	return nil
}

func (s *Service) Subscribe(ctx context.Context, request SubscribeRequest) (Subscription, error) {
	if err := model.ContextError(ctx); err != nil {
		return Subscription{}, err
	}
	if s == nil {
		return Subscription{}, model.NewError(model.ErrorInternal, "Fusion event service is not configured")
	}
	request.FusionRunID = strings.TrimSpace(request.FusionRunID)
	if err := model.ValidateRunID(request.FusionRunID); err != nil {
		return Subscription{}, err
	}
	types := make(map[model.EventType]struct{}, len(request.Types))
	for _, eventType := range request.Types {
		if !eventType.Valid() {
			return Subscription{}, model.NewError(model.ErrorInvalidArgument, "Fusion event type filter is invalid")
		}
		types[eventType] = struct{}{}
	}
	candidate := &subscriber{runID: request.FusionRunID, types: types, events: make(chan model.FusionEvent, s.historyLimit+defaultSubscriberBuffer), errors: make(chan error, 1)}
	s.mu.Lock()
	for _, item := range s.history[request.FusionRunID] {
		if item.Sequence > request.AfterSequence && matches(candidate, item) {
			candidate.events <- item.Clone()
		}
	}
	s.nextSubscriber++
	id := s.nextSubscriber
	s.subscribers[id] = candidate
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		s.mu.Lock()
		if current, exists := s.subscribers[id]; exists {
			delete(s.subscribers, id)
			close(current.events)
			close(current.errors)
		}
		s.mu.Unlock()
	}()
	return Subscription{Events: candidate.events, Errors: candidate.errors}, nil
}

func (s *Service) History(ctx context.Context, request HistoryRequest) ([]model.FusionEvent, error) {
	if err := model.ContextError(ctx); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, model.NewError(model.ErrorInternal, "Fusion event service is not configured")
	}
	if err := model.ValidateRunID(request.FusionRunID); err != nil {
		return nil, err
	}
	request.PropertyKey, request.ConclusionID = strings.TrimSpace(request.PropertyKey), strings.TrimSpace(request.ConclusionID)
	if request.ConclusionID != "" {
		if err := model.ValidateConclusionID(request.ConclusionID); err != nil {
			return nil, err
		}
	}
	s.mu.RLock()
	result := make([]model.FusionEvent, 0)
	for _, item := range s.history[request.FusionRunID] {
		if request.PropertyKey != "" && item.PropertyKey != request.PropertyKey {
			continue
		}
		if request.ConclusionID != "" && item.ConclusionID != request.ConclusionID {
			continue
		}
		result = append(result, item.Clone())
	}
	s.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].Sequence < result[j].Sequence })
	return result, nil
}

func matches(candidate *subscriber, event model.FusionEvent) bool {
	if candidate.runID != event.FusionRunID {
		return false
	}
	if len(candidate.types) == 0 {
		return true
	}
	_, exists := candidate.types[event.Type]
	return exists
}
