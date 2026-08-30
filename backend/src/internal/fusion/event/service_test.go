package event_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/event"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
)

func runID(t *testing.T) string {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}

func TestSubscribeReplaysFiltersStreamsAndCancels(t *testing.T) {
	service := event.New(100)
	run := runID(t)
	if err := service.Publish(context.Background(), model.FusionEvent{FusionRunID: run, Type: model.EventEvidenceAdded, PropertyKey: "child.mode"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	subscription, err := service.Subscribe(ctx, event.SubscribeRequest{FusionRunID: run, Types: []model.EventType{model.EventEvidenceAdded}})
	if err != nil {
		t.Fatal(err)
	}
	first := <-subscription.Events
	if first.Type != model.EventEvidenceAdded || first.Sequence != 1 {
		t.Fatalf("replayed event = %+v", first)
	}
	if parsed, parseErr := uuid.Parse(first.ID); parseErr != nil || parsed.Version() != 7 {
		t.Fatalf("event ID is not UUIDv7: %q, %v", first.ID, parseErr)
	}
	if err = service.Publish(context.Background(), model.FusionEvent{FusionRunID: run, Type: model.EventConflictDetected}); err != nil {
		t.Fatal(err)
	}
	if err = service.Publish(context.Background(), model.FusionEvent{FusionRunID: run, Type: model.EventEvidenceAdded, PropertyKey: "ike.version"}); err != nil {
		t.Fatal(err)
	}
	select {
	case streamed := <-subscription.Events:
		if streamed.Sequence != 3 || streamed.PropertyKey != "ike.version" {
			t.Fatalf("streamed event = %+v", streamed)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for streamed event")
	}
	cancel()
	select {
	case _, open := <-subscription.Events:
		if open {
			t.Fatal("event stream remained open after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("event stream did not close after cancellation")
	}
}

func TestConcurrentPublishHasUniqueMonotonicSequences(t *testing.T) {
	service := event.New(100)
	run := runID(t)
	const publishers = 32
	var group sync.WaitGroup
	errorsByPublisher := make(chan error, publishers)
	for range publishers {
		group.Add(1)
		go func() {
			defer group.Done()
			errorsByPublisher <- service.Publish(context.Background(), model.FusionEvent{FusionRunID: run, Type: model.EventEvidenceAdded})
		}()
	}
	group.Wait()
	close(errorsByPublisher)
	for err := range errorsByPublisher {
		if err != nil {
			t.Fatal(err)
		}
	}
	history, err := service.History(context.Background(), event.HistoryRequest{FusionRunID: run})
	if err != nil || len(history) != publishers {
		t.Fatalf("History() count = %d, %v", len(history), err)
	}
	for index, item := range history {
		if item.Sequence != uint64(index+1) {
			t.Fatalf("sequence[%d] = %d", index, item.Sequence)
		}
	}
}

func TestSubscribeValidation(t *testing.T) {
	service := event.New(1)
	_, err := service.Subscribe(context.Background(), event.SubscribeRequest{FusionRunID: "bad"})
	assertKind(t, err, model.ErrorInvalidArgument)
	_, err = service.Subscribe(context.Background(), event.SubscribeRequest{FusionRunID: runID(t), Types: []model.EventType{"BAD"}})
	assertKind(t, err, model.ErrorInvalidArgument)
}

func assertKind(t *testing.T, err error, kind model.ErrorKind) {
	t.Helper()
	var fusionErr *model.Error
	if !errors.As(err, &fusionErr) || fusionErr.Kind != kind {
		t.Fatalf("error = %v, want %s", err, kind)
	}
}
