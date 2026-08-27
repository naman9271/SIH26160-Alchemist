# ML Frontend Contract

This document defines the ML classification fields that the Go backend should eventually expose to the Next.js frontend. The frontend must receive them through a Go-owned API; it must not connect directly to the Python ML gRPC service.

Values represent one classified flow/window. The frontend should display the `model_version` alongside stored or historical results so users can distinguish outputs produced by different models.

## Primary UI

Use these fields in the main classification card, flow list, and alert summaries.

| Field | Type | Example | Display label | Description |
| --- | --- | --- | --- | --- |
| `predicted_class` | string enum | `"video"` | Traffic class | Final ML classification: `web`, `video`, `voip`, `email`, `file_transfer`, `messaging`, `icmp`, or `UNKNOWN`. |
| `confidence` | number, `0–1` | `0.84` | Confidence | Largest known-class model probability. Display as `84%` while retaining the raw value for API consumers. |
| `is_unknown` | boolean | `false` | Unknown traffic | `true` when confidence falls below the calibrated rejection threshold. Show an UNKNOWN state instead of treating the leading known candidate as final. |
| `top_predictions` | array of `TopPrediction` | `[{"traffic_class":"video","confidence":0.84}]` | Top predictions | Up to three known-class candidates in descending confidence order. These remain useful context when `is_unknown` is true. |
| `anomaly_status` | `"normal"`, `"suspicious"`, or `null` | `"suspicious"` | Anomaly status | Experimental statistical-behavior result. Return `null` or omit it when anomaly detection is disabled; never infer it from UNKNOWN. |

### `TopPrediction`

| Field | Type | Example | Display label | Description |
| --- | --- | --- | --- | --- |
| `traffic_class` | string enum | `"web"` | Candidate class | One known traffic class candidate. It is not the final decision when `is_unknown` is true. |
| `confidence` | number, `0–1` | `0.10` | Candidate confidence | Model probability for that candidate class. Display as a percentage. |

## Flow details

Show these values in an expandable flow-detail panel. Units must be rendered consistently; values are metadata-derived and do not expose decrypted payload content.

| Field | Type | Example | Display label | Description |
| --- | --- | --- | --- | --- |
| `duration` | number, seconds | `10.0` | Flow duration | Time covered by the classified flow/window. |
| `packet_count` | integer | `120` | Packets | Total packets observed in the window. |
| `total_bytes` | integer, bytes | `141624` | Total traffic | Total observed packet bytes in the window. Format as bytes, KiB, or MiB for display. |
| `packets_per_second` | number | `12.0` | Packets/sec | Average packet rate across the window. |
| `bytes_per_second` | number, bytes/sec | `14162.4` | Throughput | Average byte rate across the window. Format with a bytes-per-second unit. |
| `mean_packet_size` | number, bytes | `1180.2` | Average packet size | Mean observed packet size. |
| `upload_bytes` | integer, bytes | `61370` | Upload traffic | Bytes in the configured initiator-to-responder direction. |
| `download_bytes` | integer, bytes | `80254` | Download traffic | Bytes in the responder-to-initiator direction. |
| `upload_download_ratio` | number, ≥ 0 | `0.7647` | Upload/download ratio | Upload bytes divided by download bytes, using the training-compatible zero-download convention. |

## Explainability

Only request and render explanations when the Go backend has explicitly enabled them. They may add latency and are not protocol or security findings.

| Field | Type | Example | Display label | Description |
| --- | --- | --- | --- | --- |
| `top_explanations` | array of `FeatureExplanation` | `[{"feature":"mean_packet_size","impact":0.31}]` | Why this result | Up to five highest-impact SHAP feature contributions for the selected known-class prediction. Never expose a raw SHAP matrix. |

### `FeatureExplanation`

| Field | Type | Example | Display label | Description |
| --- | --- | --- | --- | --- |
| `feature` | string | `"mean_packet_size"` | Feature key | Stable technical feature identifier. Use for analytics and test selectors, not as the preferred user-facing label. |
| `display_name` | string | `"Average Packet Size"` | Feature | Readable feature label supplied by the ML service. |
| `value` | number | `1180.2` | Observed value | Feature value used by the model after its input preparation. Apply the unit associated with the feature. |
| `impact` | signed number | `0.31` | Model impact | Signed SHAP contribution for the selected known class. Higher absolute values are more influential. |
| `direction` | string enum | `"supports_prediction"` | Effect | `supports_prediction`, `opposes_prediction`, or `neutral`. Use color and icon treatment, but do not represent it as a security severity. |

When `is_unknown` is `true`, label explanations as “why the leading known candidate was considered,” not “why this traffic is UNKNOWN.” UNKNOWN is a confidence-threshold rejection outcome.

## Advanced fields

Keep these in an advanced/details section, diagnostics drawer, or export. They are useful for support and observability but should not dominate the primary user experience.

| Field | Type | Example | Display label | Description |
| --- | --- | --- | --- | --- |
| `model_version` | string | `"traffic-classifier-abc123def456"` | Model version | Persisted model identifier. Include it in exports and historical records. |
| `inference_time_ms` | number, milliseconds | `3.7` | ML inference time | Time spent validating and running one ML prediction, including an enabled explanation. It is not end-to-end page or network latency. |
| `std_packet_size` | number, bytes | `210.3` | Packet size variation | Population standard deviation of packet size. |
| `min_packet_size` | number, bytes | `60.0` | Minimum packet size | Smallest observed packet size. |
| `max_packet_size` | number, bytes | `1514.0` | Maximum packet size | Largest observed packet size. |
| `p25_packet_size` | number, bytes | `1120.0` | 25th percentile packet size | Packet size at the lower quartile. |
| `median_packet_size` | number, bytes | `1200.0` | Median packet size | Middle observed packet size. |
| `p75_packet_size` | number, bytes | `1400.0` | 75th percentile packet size | Packet size at the upper quartile. |
| `p95_packet_size` | number, bytes | `1514.0` | 95th percentile packet size | High-end packet size percentile. |
| `mean_interarrival_time` | number, seconds | `0.084` | Average interarrival time | Mean time between observed packets. |
| `std_interarrival_time` | number, seconds | `0.031` | Interarrival variation | Variation in time between observed packets. |
| `upload_packets` | integer | `52` | Upload packets | Packet count in the configured initiator-to-responder direction. |
| `download_packets` | integer | `68` | Download packets | Packet count in the responder-to-initiator direction. |
| `burst_count` | integer | `9` | Bursts | Number of bursts under the configured burst-gap policy. |
| `mean_burst_size` | number | `13.33` | Average burst size | Average packets per burst. |
| `idle_time_ratio` | number, `0–1` | `0.12` | Idle time | Fraction of window duration classified as idle under the configured idle-gap policy. Display as `12%`. |

## Recommended backend response shape

The Go backend may expose a JSON response similar to this, preserving the ML fields while adding Go-owned identifiers separately:

```json
{
  "flow_id": "sa-42/window-00017",
  "predicted_class": "video",
  "confidence": 0.84,
  "is_unknown": false,
  "top_predictions": [
    {"traffic_class": "video", "confidence": 0.84},
    {"traffic_class": "web", "confidence": 0.10},
    {"traffic_class": "voip", "confidence": 0.06}
  ],
  "anomaly_status": null,
  "duration": 10.0,
  "packet_count": 120,
  "total_bytes": 141624,
  "packets_per_second": 12.0,
  "bytes_per_second": 14162.4,
  "mean_packet_size": 1180.2,
  "upload_bytes": 61370,
  "download_bytes": 80254,
  "upload_download_ratio": 0.7647,
  "top_explanations": [],
  "model_version": "traffic-classifier-abc123def456",
  "inference_time_ms": 3.7
}
```

The Go backend should keep protocol facts, security findings, IKE/IPsec configuration, source/destination identifiers, and raw packet/payload data in separate backend-owned fields. They are not ML classification features and should not be implied by this frontend contract.
