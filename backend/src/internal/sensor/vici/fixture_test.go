package vici

import (
	"context"
	"testing"
	"time"

	viciv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/vici"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFixtureValidationAndCloneIsolation(t *testing.T) {
	if _, err := NewFixture(&viciv1.GatewaySnapshot{}); err == nil {
		t.Fatal("invalid fixture was accepted")
	}
	fixture, err := NewFixture(&viciv1.GatewaySnapshot{SchemaVersion: FixtureSchemaVersion, SnapshotTimestamp: timestamppb.New(time.Now()), IkeSas: []*viciv1.IkeSa{{Name: "ike", UniqueId: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := fixture.IkeSas(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	first[0].Name = "mutated"
	second, _ := fixture.IkeSas(context.Background(), "")
	if second[0].Name != "ike" {
		t.Fatalf("fixture returned shared mutable data: %q", second[0].Name)
	}
}
