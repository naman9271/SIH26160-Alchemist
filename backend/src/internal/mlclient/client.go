// Package mlclient safely adapts finalized sensor feature windows to the
// reusable Python traffic-classifier gRPC contract.
package mlclient

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	flowv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/api/proto/sensor/v1/flow"
	mlv1 "github.com/naman9271/SIH26160---Team-Alchemist/gen/go/ml/v1"
	"google.golang.org/grpc/metadata"
)

const featureSchemaVersion = "flow.v2"

var expectedFeatureNames = []string{
	"duration", "packet_count", "total_bytes", "packets_per_second",
	"bytes_per_second", "mean_packet_size", "std_packet_size",
	"min_packet_size", "max_packet_size", "p25_packet_size",
	"median_packet_size", "p75_packet_size", "p95_packet_size",
	"mean_interarrival_time", "std_interarrival_time", "upload_packets",
	"download_packets", "upload_bytes", "download_bytes",
	"upload_download_ratio", "burst_count", "mean_burst_size",
	"idle_time_ratio",
}

// Client invokes one already-configured ML gRPC client with bounded requests.
type Client struct {
	client  mlv1.TrafficClassifierClient
	timeout time.Duration
}

// New returns a client adapter. A non-positive timeout is rejected at the
// request boundary rather than silently creating unbounded ML calls.
func New(client mlv1.TrafficClassifierClient, timeout time.Duration) (*Client, error) {
	if client == nil {
		return nil, fmt.Errorf("ML gRPC client is required")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("ML request timeout must be positive")
	}
	return &Client{client: client, timeout: timeout}, nil
}

// Predict validates a finalized flow.v2 window, translates every required
// metadata feature, and applies a deadline when the caller has not supplied a
// shorter one. It never submits identifiers, addresses, SPI, or protocol facts.
func (c *Client) Predict(ctx context.Context, window *flowv1.FeatureWindow) (*mlv1.PredictionResult, error) {
	return c.predict(ctx, window, false)
}

// PredictWithExplanations requests the worker's optional SHAP-style
// attributions without changing the feature schema or sending identifiers.
func (c *Client) PredictWithExplanations(ctx context.Context, window *flowv1.FeatureWindow) (*mlv1.PredictionResult, error) {
	return c.predict(ctx, window, true)
}

func (c *Client) predict(ctx context.Context, window *flowv1.FeatureWindow, explanations bool) (*mlv1.PredictionResult, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("ML client is not configured")
	}
	request, err := RequestFromWindow(window)
	if err != nil {
		return nil, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if explanations {
		requestCtx = metadata.AppendToOutgoingContext(requestCtx, "x-include-explanations", "true")
	}
	result, err := c.client.PredictTraffic(requestCtx, request)
	if err != nil {
		return nil, err
	}
	if err := validateResponse(result); err != nil {
		return nil, err
	}
	return result, nil
}

// RequestFromWindow maps the exact sensor feature schema to FlowFeatures.
// The explicit schema check prevents a changed producer from silently shifting
// fields or passing a configuration/identifier value into the classifier.
func RequestFromWindow(window *flowv1.FeatureWindow) (*mlv1.FlowFeatures, error) {
	if window == nil {
		return nil, fmt.Errorf("feature window is required")
	}
	if strings.TrimSpace(window.GetFlowId()) == "" {
		return nil, fmt.Errorf("feature window flow_id is required")
	}
	if !window.GetFinalized() {
		return nil, fmt.Errorf("feature window %q must be finalized before ML inference", window.GetFlowId())
	}
	if window.GetFeatureSchemaVersion() != featureSchemaVersion {
		return nil, fmt.Errorf("unsupported feature schema %q", window.GetFeatureSchemaVersion())
	}
	values, err := exactFeatureValues(window)
	if err != nil {
		return nil, err
	}
	integer := func(name string) (*int64, error) {
		value := values[name]
		if value < 0 || value > float64(math.MaxInt64) || math.Trunc(value) != value {
			return nil, fmt.Errorf("feature %q must be a non-negative int64", name)
		}
		parsed := int64(value)
		return &parsed, nil
	}
	packetCount, err := integer("packet_count")
	if err != nil {
		return nil, err
	}
	totalBytes, err := integer("total_bytes")
	if err != nil {
		return nil, err
	}
	uploadPackets, err := integer("upload_packets")
	if err != nil {
		return nil, err
	}
	downloadPackets, err := integer("download_packets")
	if err != nil {
		return nil, err
	}
	uploadBytes, err := integer("upload_bytes")
	if err != nil {
		return nil, err
	}
	downloadBytes, err := integer("download_bytes")
	if err != nil {
		return nil, err
	}
	burstCount, err := integer("burst_count")
	if err != nil {
		return nil, err
	}
	if values["duration"] <= 0 || values["packet_count"] < 1 {
		return nil, fmt.Errorf("duration must be positive and packet_count must be at least one")
	}
	if values["upload_packets"]+values["download_packets"] != values["packet_count"] || values["upload_bytes"]+values["download_bytes"] != values["total_bytes"] {
		return nil, fmt.Errorf("directional feature totals must match packet_count and total_bytes")
	}
	if values["idle_time_ratio"] < 0 || values["idle_time_ratio"] > 1 {
		return nil, fmt.Errorf("idle_time_ratio must be within [0, 1]")
	}
	if !orderedPercentiles(values) {
		return nil, fmt.Errorf("packet-size percentiles must be ordered")
	}
	flowID := window.GetFlowId()
	return &mlv1.FlowFeatures{
		FlowId: &flowID, Duration: number(values["duration"]), PacketCount: packetCount, TotalBytes: totalBytes,
		PacketsPerSecond: number(values["packets_per_second"]), BytesPerSecond: number(values["bytes_per_second"]),
		MeanPacketSize: number(values["mean_packet_size"]), StdPacketSize: number(values["std_packet_size"]),
		MinPacketSize: number(values["min_packet_size"]), MaxPacketSize: number(values["max_packet_size"]),
		P25PacketSize: number(values["p25_packet_size"]), MedianPacketSize: number(values["median_packet_size"]),
		P75PacketSize: number(values["p75_packet_size"]), P95PacketSize: number(values["p95_packet_size"]),
		MeanInterarrivalTime: number(values["mean_interarrival_time"]), StdInterarrivalTime: number(values["std_interarrival_time"]),
		UploadPackets: uploadPackets, DownloadPackets: downloadPackets, UploadBytes: uploadBytes, DownloadBytes: downloadBytes,
		UploadDownloadRatio: number(values["upload_download_ratio"]), BurstCount: burstCount,
		MeanBurstSize: number(values["mean_burst_size"]), IdleTimeRatio: number(values["idle_time_ratio"]),
	}, nil
}

func exactFeatureValues(window *flowv1.FeatureWindow) (map[string]float64, error) {
	if len(window.GetFeatureNames()) != len(expectedFeatureNames) || len(window.GetFeatureValues()) != len(expectedFeatureNames) {
		return nil, fmt.Errorf("feature window must contain exactly %d named values", len(expectedFeatureNames))
	}
	values := make(map[string]float64, len(expectedFeatureNames))
	for index, name := range expectedFeatureNames {
		if window.GetFeatureNames()[index] != name {
			return nil, fmt.Errorf("unexpected feature at index %d: got %q, want %q", index, window.GetFeatureNames()[index], name)
		}
		value := window.GetFeatureValues()[index]
		if !finite(value) || value < 0 {
			return nil, fmt.Errorf("feature %q must be finite and non-negative", name)
		}
		values[name] = value
	}
	return values, nil
}

func orderedPercentiles(values map[string]float64) bool {
	ordered := []string{"min_packet_size", "p25_packet_size", "median_packet_size", "p75_packet_size", "p95_packet_size", "max_packet_size"}
	for index := 1; index < len(ordered); index++ {
		if values[ordered[index-1]] > values[ordered[index]] {
			return false
		}
	}
	return true
}

func number(value float64) *float64 { return &value }

func validateResponse(result *mlv1.PredictionResult) error {
	if result == nil || strings.TrimSpace(result.GetFlowId()) == "" || strings.TrimSpace(result.GetModelVersion()) == "" {
		return fmt.Errorf("ML service returned an incomplete prediction")
	}
	if !finite(result.GetConfidence()) || result.GetConfidence() < 0 || result.GetConfidence() > 1 || !finite(result.GetInferenceTimeMs()) || result.GetInferenceTimeMs() < 0 {
		return fmt.Errorf("ML service returned invalid confidence or inference time")
	}
	if result.GetIsUnknown() != (result.GetPredictedClass() == mlv1.TrafficClass_TRAFFIC_CLASS_UNKNOWN) {
		return fmt.Errorf("ML service returned inconsistent UNKNOWN state")
	}
	return nil
}

func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }
