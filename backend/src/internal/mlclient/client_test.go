package mlclient

import (
	"context"
	"strings"
	"testing"
	"time"

	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
	mlv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/ml/v1"
	flow "github.com/naman9271/SIH26160---Team-Alchemist/src/internal/sensor/flow"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type fakeClient struct {
	request  *mlv1.FlowFeatures
	response *mlv1.PredictionResult
	err      error
}

func (f *fakeClient) PredictTraffic(ctx context.Context, request *mlv1.FlowFeatures, _ ...grpc.CallOption) (*mlv1.PredictionResult, error) {
	f.request = request
	return f.response, f.err
}
func (f *fakeClient) HealthCheck(context.Context, *emptypb.Empty, ...grpc.CallOption) (*mlv1.HealthStatus, error) {
	return nil, nil
}

func validWindow() *flowv1.FeatureWindow {
	values := []float64{1, 4, 400, 4, 400, 100, 1, 99, 101, 99, 100, 100, 101, .25, .1, 2, 2, 200, 200, 1, 2, 2, 0}
	return &flowv1.FeatureWindow{FlowId: "flow-1", Finalized: true, FeatureSchemaVersion: flow.FeatureSchemaVersion, FeatureNames: append([]string(nil), flow.FeatureNames...), FeatureValues: values}
}

func TestRequestFromWindowMapsOnlyValidatedFeatures(t *testing.T) {
	request, err := RequestFromWindow(validWindow())
	if err != nil {
		t.Fatal(err)
	}
	if request.GetFlowId() != "flow-1" || request.GetPacketCount() != 4 || request.GetUploadBytes() != 200 || request.GetMeanPacketSize() != 100 {
		t.Fatalf("unexpected request: %+v", request)
	}
}

func TestRequestFromWindowRejectsSchemaDriftAndInvalidRelationships(t *testing.T) {
	for _, mutate := range []func(*flowv1.FeatureWindow){
		func(w *flowv1.FeatureWindow) { w.FeatureNames[0] = "source_ip" },
		func(w *flowv1.FeatureWindow) { w.FeatureValues[15] = 3 },
		func(w *flowv1.FeatureWindow) { w.Finalized = false },
	} {
		window := validWindow()
		mutate(window)
		if _, err := RequestFromWindow(window); err == nil {
			t.Fatal("expected invalid window to be rejected")
		}
	}
}

func TestPredictValidatesServiceResponse(t *testing.T) {
	client := &fakeClient{response: &mlv1.PredictionResult{FlowId: "flow-1", ModelVersion: "model-v1", Confidence: .8, PredictedClass: mlv1.TrafficClass_TRAFFIC_CLASS_WEB}}
	adapter, err := New(client, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	result, err := adapter.Predict(context.Background(), validWindow())
	if err != nil {
		t.Fatal(err)
	}
	if result.GetPredictedClass() != mlv1.TrafficClass_TRAFFIC_CLASS_WEB || client.request == nil {
		t.Fatalf("unexpected result=%+v request=%+v", result, client.request)
	}

	client.response.IsUnknown = true
	if _, err := adapter.Predict(context.Background(), validWindow()); err == nil || !strings.Contains(err.Error(), "UNKNOWN") {
		t.Fatalf("expected UNKNOWN consistency error, got %v", err)
	}
}
