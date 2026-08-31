package protocolread

import (
	"context"
	"testing"
	"time"

	commonv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/common/v1"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/model"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/fusion/query"
	"github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/acquisition"
	"google.golang.org/protobuf/types/known/structpb"
)

type resolver string

func (r resolver) FusionRunID(context.Context, string) (string, error) { return string(r), nil }

type evidence struct{ items []model.EvidenceItem }

func (e evidence) List(_ context.Context, request query.ListRequest) (query.ListResponse, error) {
	return query.ListResponse{Evidence: e.items}, nil
}

func TestSummaryAndEvidenceExposeNormalizedValues(t *testing.T) {
	now := time.Now().UTC()
	service := New(resolver("run"), evidence{items: []model.EvidenceItem{
		{ID: "e1", PropertyKey: "ike.version", Value: structpb.NewStringValue("IKEv2"), Status: commonv1.EvidenceStatus_OBSERVED, Confidence: 1, ObservedAt: now, ResourceType: "IKE_SA"},
		{ID: "e2", PropertyKey: "child.protocol", Value: structpb.NewStringValue("ESP"), Status: commonv1.EvidenceStatus_DERIVED, Confidence: .9, ObservedAt: now, ResourceType: "CHILD_SA"},
	}}, acquisition.Services{})
	summary, err := service.Summary(context.Background(), "analysis")
	if err != nil || !summary.IpsecDetected || summary.IkeVersion != "IKEv2" || summary.DataProtocol != "ESP" {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	items, _, err := service.Evidence(context.Background(), "analysis", query.Filter{}, 100, "")
	if err != nil || len(items) != 2 || items[0].Value != "IKEv2" {
		t.Fatalf("evidence=%+v err=%v", items, err)
	}
}
