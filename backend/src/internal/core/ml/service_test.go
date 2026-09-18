package ml

import (
	"testing"

	mlv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/core/v1/ml"
	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
	worker "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/ml/v1"
)

func TestClassifierTrafficAcceptsOnlyEncryptedDataFlows(t *testing.T) {
	tests := []struct {
		name     string
		protocol flowv1.FlowProtocol
		want     bool
	}{
		{name: "ESP", protocol: flowv1.FlowProtocol_ESP, want: true},
		{name: "UDP encapsulated ESP", protocol: flowv1.FlowProtocol_NAT_T, want: true},
		{name: "IKE", protocol: flowv1.FlowProtocol_IKE, want: false},
		{name: "AH", protocol: flowv1.FlowProtocol_AH, want: false},
		{name: "other", protocol: flowv1.FlowProtocol_OTHER, want: false},
		{name: "unspecified", protocol: flowv1.FlowProtocol_FLOW_PROTOCOL_UNSPECIFIED, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isClassifierTraffic(test.protocol); got != test.want {
				t.Fatalf("isClassifierTraffic(%s) = %t, want %t", test.protocol, got, test.want)
			}
		})
	}
}

func TestStoreResultUsesCoreAPITrafficClassNames(t *testing.T) {
	service := &Service{jobs: map[string]*job{
		"inference-1": {
			id:           "inference-1",
			state:        "RUNNING",
			predictions:  map[string]*mlv1.TrafficPrediction{},
			explanations: map[string]*mlv1.PredictionExplanation{},
		},
	}}
	service.storeResult("inference-1", &worker.PredictionResult{
		FlowId:         "flow-1",
		PredictedClass: worker.TrafficClass_TRAFFIC_CLASS_WEB,
		Confidence:     .91,
		ModelVersion:   "model-v1",
		TopPredictions: []*worker.ClassPrediction{
			{TrafficClass: worker.TrafficClass_TRAFFIC_CLASS_WEB, Confidence: .91},
			{TrafficClass: worker.TrafficClass_TRAFFIC_CLASS_VIDEO, Confidence: .06},
		},
	}, false)

	stored := service.jobs["inference-1"].predictions["inference-1:flow-1"]
	if stored == nil {
		t.Fatal("prediction was not stored")
	}
	if stored.GetTrafficClass() != "WEB" {
		t.Fatalf("traffic_class = %q, want WEB", stored.GetTrafficClass())
	}
	if _, ok := stored.GetClassProbabilities()["VIDEO"]; !ok {
		t.Fatalf("class probabilities use worker enum names: %+v", stored.GetClassProbabilities())
	}
	if _, ok := stored.GetClassProbabilities()["TRAFFIC_CLASS_VIDEO"]; ok {
		t.Fatalf("class probabilities leaked worker enum prefix: %+v", stored.GetClassProbabilities())
	}
	if stored.GetConfidenceCalibrationStatus() != "CALIBRATED" || stored.GetAbstentionReason() != "NOT_ABSTAINED" {
		t.Fatalf("prediction did not expose calibration and abstention state: %+v", stored)
	}
}

func TestUnknownPredictionExplainsItsAbstention(t *testing.T) {
	prediction, _ := predictionResult("inference-2", &worker.PredictionResult{FlowId: "flow-2", PredictedClass: worker.TrafficClass_TRAFFIC_CLASS_UNKNOWN, IsUnknown: true}, false)
	if prediction == nil || prediction.GetAbstentionReason() == "" || prediction.GetAbstentionReason() == "NOT_ABSTAINED" || prediction.GetConfidenceCalibrationStatus() != "CALIBRATED" {
		t.Fatalf("UNKNOWN did not retain its calibrated abstention explanation: %+v", prediction)
	}
}
