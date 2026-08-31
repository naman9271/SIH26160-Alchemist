# Go ↔ Python ML Service Integration

This guide describes the current inference contract between the Go IPsec backend and the Python ML service. The ML service classifies encrypted traffic from flow-level metadata only. It does not decrypt ESP payloads and must not be used for IPsec/IKE security analysis.

## Endpoint and lifecycle

The default endpoint is `127.0.0.1:50051` over insecure gRPC. Configure the bind address and port in `backend/ml-service/config/model.yaml`:

```yaml
grpc:
  host: 127.0.0.1
  port: 50051
  request_timeout_seconds: 5.0
```

Start the Python service after a trained model and calibrated UNKNOWN threshold are available:

```bash
cd backend/ml-service
python -m src.grpc_server
```

The selected model loads once during server startup. The service never trains, preprocesses datasets, or reloads a model during an RPC. Restart it to use a new model version.

Before sending traffic, the Go backend should call `HealthCheck`. Continue only when `status` is `SERVING_STATUS_SERVING` and `model_loaded` is `true`.

## Protobuf API

The source of truth is [traffic_classifier.proto](../proto/ml/v1/traffic_classifier.proto). Its package is `sih.ipsec.ml.v1` and its Go package is:

```text
github.com/naman9271/SIH26160---Team-Alchemist/backend/gen/ml/v1;mlv1
```

Generate Go stubs from the repository root when backend integration begins:

```bash
protoc -I backend/ml-service/proto \
  --go_out=. --go_opt=module=github.com/naman9271/SIH26160---Team-Alchemist \
  --go-grpc_out=. --go-grpc_opt=module=github.com/naman9271/SIH26160---Team-Alchemist \
  backend/ml-service/proto/ml/v1/traffic_classifier.proto
```

Available RPCs:

```proto
rpc PredictTraffic(FlowFeatures) returns (PredictionResult);
rpc HealthCheck(google.protobuf.Empty) returns (HealthStatus);
```

`FlowFeatures` uses proto3 `optional` fields so the service can distinguish an omitted field from an explicit zero. This does **not** mean the current model accepts missing values: every field listed below is required by the Python `FlowFeatures` schema.

## Required flow features

The backend must calculate these values over the same one-direction-paired flow/window policy used for training. All timing values are seconds; packet-size and byte values are bytes.

| Group | Required protobuf fields |
| --- | --- |
| Identity | `flow_id` — opaque, stable per flow/window; it is returned unchanged and is not a model feature. |
| Window volume | `duration` (> 0), `packet_count` (≥ 1), `total_bytes` (≥ 0). |
| Rates | `packets_per_second` (≥ 0), `bytes_per_second` (≥ 0). |
| Packet size | `mean_packet_size`, `std_packet_size`, `min_packet_size`, `max_packet_size`, `p25_packet_size`, `median_packet_size`, `p75_packet_size`, `p95_packet_size` (all ≥ 0). Percentiles must be ordered from min through max. |
| Interarrival | `mean_interarrival_time`, `std_interarrival_time` (both ≥ 0). |
| Directional volume | `upload_packets`, `download_packets`, `upload_bytes`, `download_bytes` (all ≥ 0). Packet counts must sum to `packet_count`; byte counts must sum to `total_bytes`. |
| Directionality | `upload_download_ratio` (≥ 0). Use the same zero-download convention used when training; do not send infinity or NaN. |
| Burst/idle | `burst_count` (≥ 0), `mean_burst_size` (≥ 0), `idle_time_ratio` (0–1). Compute these using the configured burst and idle gap policy. |

All numeric values must be finite. The API currently has no optional model-input features. If the Go backend cannot derive a required value safely, it must not invent one; omit the request or use a separately trained model whose schema supports that feature set.

For the current offline extractor, `feature_extraction` in `model.yaml` defines the window duration, burst gap, and idle gap. Go must use an agreed equivalent policy before its feature vectors are expected to match model behavior.

## Go call pattern

Use a bounded context for every call and reuse the gRPC connection/client rather than dialing per flow.

```go
conn, err := grpc.DialContext(
    context.Background(),
    "127.0.0.1:50051",
    grpc.WithTransportCredentials(insecure.NewCredentials()),
)
if err != nil {
    return err
}
defer conn.Close()

client := mlv1.NewTrafficClassifierClient(conn)
ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
defer cancel()

result, err := client.PredictTraffic(ctx, &mlv1.FlowFeatures{
    FlowId:               "sa-42/window-00017",
    Duration:             proto.Float64(10.0),
    PacketCount:          proto.Int64(120),
    TotalBytes:           proto.Int64(141624),
    PacketsPerSecond:     proto.Float64(12.0),
    BytesPerSecond:       proto.Float64(14162.4),
    MeanPacketSize:       proto.Float64(1180.2),
    StdPacketSize:        proto.Float64(210.3),
    MinPacketSize:        proto.Float64(60),
    MaxPacketSize:        proto.Float64(1514),
    P25PacketSize:        proto.Float64(1120),
    MedianPacketSize:     proto.Float64(1200),
    P75PacketSize:        proto.Float64(1400),
    P95PacketSize:        proto.Float64(1514),
    MeanInterarrivalTime: proto.Float64(0.084),
    StdInterarrivalTime:  proto.Float64(0.031),
    UploadPackets:        proto.Int64(52),
    DownloadPackets:      proto.Int64(68),
    UploadBytes:          proto.Int64(61370),
    DownloadBytes:        proto.Int64(80254),
    UploadDownloadRatio:  proto.Float64(0.7647),
    BurstCount:           proto.Int64(9),
    MeanBurstSize:        proto.Float64(13.33),
    IdleTimeRatio:        proto.Float64(0.12),
})
```

The exact Go optional-field representation depends on the generated `protoc-gen-go` version. Set every required field explicitly; do not rely on protobuf scalar defaults.

## Sample request and response

The same request in protobuf JSON form is:

```json
{
  "flowId": "sa-42/window-00017",
  "duration": 10.0,
  "packetCount": "120",
  "totalBytes": "141624",
  "packetsPerSecond": 12.0,
  "bytesPerSecond": 14162.4,
  "meanPacketSize": 1180.2,
  "stdPacketSize": 210.3,
  "minPacketSize": 60.0,
  "maxPacketSize": 1514.0,
  "p25PacketSize": 1120.0,
  "medianPacketSize": 1200.0,
  "p75PacketSize": 1400.0,
  "p95PacketSize": 1514.0,
  "meanInterarrivalTime": 0.084,
  "stdInterarrivalTime": 0.031,
  "uploadPackets": "52",
  "downloadPackets": "68",
  "uploadBytes": "61370",
  "downloadBytes": "80254",
  "uploadDownloadRatio": 0.7647,
  "burstCount": "9",
  "meanBurstSize": 13.33,
  "idleTimeRatio": 0.12
}
```

Example response:

```json
{
  "flowId": "sa-42/window-00017",
  "predictedClass": "TRAFFIC_CLASS_VIDEO",
  "confidence": 0.84,
  "isUnknown": false,
  "topPredictions": [
    {"trafficClass": "TRAFFIC_CLASS_VIDEO", "confidence": 0.84},
    {"trafficClass": "TRAFFIC_CLASS_WEB", "confidence": 0.10},
    {"trafficClass": "TRAFFIC_CLASS_VOIP", "confidence": 0.06}
  ],
  "modelVersion": "traffic-classifier-abc123def456",
  "topExplanations": [],
  "inferenceTimeMs": 3.7
}
```

`PredictionResult` always contains `flow_id`, `predicted_class`, `confidence`, `is_unknown`, up to three `top_predictions`, `model_version`, `top_explanations`, and `inference_time_ms`.

## Timeout and error behavior

Use a client deadline of about **2 seconds** for ordinary metadata-only classification. Keep it at or below the server's configured `grpc.request_timeout_seconds` (default: 5 seconds). If SHAP explanations are requested, allow a larger bounded deadline appropriate for deployment measurements; explanations are intentionally slower than normal inference.

| gRPC status | Meaning | Go behavior |
| --- | --- | --- |
| `INVALID_ARGUMENT` | A required feature was omitted, non-finite, out of range, or violates a cross-field rule. | Correct the feature extractor; do not retry unchanged input. |
| `DEADLINE_EXCEEDED` | Client or server inference deadline elapsed. | Treat classification as unavailable for that window; optionally retry a later independent window. |
| `UNAVAILABLE` | The service is shutting down or the connection is unavailable. | Retry with bounded backoff after health checking. |
| `INTERNAL` | Model prediction or explanation failed unexpectedly. | Log the flow ID and model version if available; do not reinterpret this as a traffic class. |

On startup failure—for example, no model or no calibrated UNKNOWN threshold—the Python process does not serve RPCs. This is intentional fail-closed behavior.

## UNKNOWN and confidence semantics

The model predicts only known classes: `web`, `video`, `voip`, `email`, `file_transfer`, `messaging`, and `icmp`. It calculates confidence as the largest model class probability across those known classes.

If that confidence is below the configured, calibration-selected threshold, the response has:

```text
predicted_class = TRAFFIC_CLASS_UNKNOWN
is_unknown = true
```

`top_predictions` still contains the leading known-class probabilities, ordered from highest to lowest. Do not treat the first top prediction as the final class when `is_unknown` is true.

Confidence-threshold rejection is a baseline open-set method. It is not proof that traffic is novel, benign, malicious, encrypted, or decrypted, and it cannot perfectly detect every unfamiliar application. The backend should retain the confidence, UNKNOWN state, and model version with its own event record.

For this MVP, a window/capture is assumed to have one dominant known application traffic type. Do not claim that opaque site-to-site ESP metadata perfectly separates several simultaneous inner applications.

## Optional SHAP explanations

Explanations are disabled by default to keep normal inference fast. They are available only if `grpc.explanations_enabled: true` on the Python server and the Go call sends metadata:

```go
ctx := metadata.AppendToOutgoingContext(ctx, "x-include-explanations", "true")
```

At most five compact items are returned; the service never returns a raw SHAP matrix:

```json
{
  "feature": "mean_packet_size",
  "displayName": "Average Packet Size",
  "value": 1180.2,
  "impact": 0.31,
  "direction": "EXPLANATION_DIRECTION_SUPPORTS_PREDICTION"
}
```

`impact` is signed for the selected known class: positive supports the class, negative opposes it, and zero is neutral. It is an explanation of the model decision, not a protocol or security verdict.

## Model version behavior

`model_version` comes from persisted model metadata and is fixed for a running Python process. Go should include it in logs, alerts, and stored classification results. A version change occurs only after a model artifact is replaced and the ML service is restarted. Do not compare confidence values across model versions as though they came from the same calibrated model.

## Keep these responsibilities in Go

The Go backend remains the authority for networking, IPsec/IKE parsing, and security assessment. Do not send these values to the current ML model as features unless a future model contract explicitly adds and validates them:

- ESP payload bytes, decrypted inner payloads, packet contents, or packet-derived application strings.
- IKE version, exchange state, cipher suite, integrity algorithm, SPI, DH group, PFS, nonces, key material, authentication material, certificates, or identities.
- Security Association state, replay-window data, rekey/lifetime state, tunnel policy, routing, firewall decisions, or security findings.
- Source/destination IP addresses, ports, MAC addresses, filenames, capture paths, timestamps, flow IDs, dataset source, original dataset labels, or other identifiers. Endpoints may be used internally by Go only to aggregate a bidirectional flow/window; they are not ML features.
- VPN/Tor status, malware-family labels, or protocol labels as a proxy for traffic class.

Go should independently report protocol facts and security posture. The ML service should receive only the validated aggregate flow metadata described above and return only a traffic-classification result.
