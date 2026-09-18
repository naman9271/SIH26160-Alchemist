package vici

import (
	"context"
	"testing"
	"time"

	viciv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/vici"
	govici "github.com/strongswan/govici/vici"
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

func TestRealChildDecoderTreatsInstallAndLifetimeValuesAsDurations(t *testing.T) {
	message := govici.NewMessage()
	_ = message.Set("install-time", "120")
	_ = message.Set("rekey-time", "30")
	_ = message.Set("life-time", "60")
	observedAt := time.Unix(1_700_000_000, 0).UTC()
	child := decodeChildAt("child", message, observedAt)
	if !child.GetInstallTime().AsTime().Equal(observedAt.Add(-120 * time.Second)) {
		t.Fatalf("install time = %s", child.GetInstallTime().AsTime())
	}
	if child.GetRekeyTime() != 30 || child.GetLifeTime() != 60 {
		t.Fatalf("remaining durations = rekey %d lifetime %d", child.GetRekeyTime(), child.GetLifeTime())
	}
}

func TestUnimplementedRealVICIViewsReturnUnavailable(t *testing.T) {
	backend := NewRealBackend(time.Second)
	if values, err := backend.Policies(context.Background(), ""); err == nil || values != nil {
		t.Fatalf("policies = %+v, err = %v", values, err)
	}
	if events, err := backend.Events(context.Background(), "", 1); err == nil || events != nil {
		t.Fatalf("events = %+v, err = %v", events, err)
	}
}
