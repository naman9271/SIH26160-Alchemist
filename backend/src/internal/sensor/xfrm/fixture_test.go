package xfrm

import (
	"context"
	"testing"
	"time"

	xfrmv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/xfrm"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFixtureValidationAndCloneIsolation(t *testing.T) {
	if _, err := NewFixture(&xfrmv1.KernelSnapshot{}); err == nil {
		t.Fatal("invalid fixture was accepted")
	}
	fixture, err := NewFixture(&xfrmv1.KernelSnapshot{SchemaVersion: FixtureSchemaVersion, SnapshotTimestamp: timestamppb.New(time.Now()), States: []*xfrmv1.XfrmState{{Destination: "198.51.100.1", Spi: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := fixture.States(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first[0].Destination = "mutated"
	second, _ := fixture.States(context.Background())
	if second[0].Destination != "198.51.100.1" {
		t.Fatalf("fixture returned shared mutable data: %q", second[0].Destination)
	}
}
