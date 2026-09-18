# ML Service

Python 3.11+ component for encrypted traffic classification in the SIH IPsec VPN security analyzer.

## Responsibility

The service classifies traffic using flow-level metadata that remains observable around encrypted ESP traffic. It does not decrypt ESP payloads and does not evaluate IKE or cryptographic configuration. Protocol facts—including IKE version, cipher, SPI, DH group, and PFS—belong to the Go/backend analysis layer.

Initial classes are:

`web`, `video`, `voip`, `email`, `file_transfer`, `messaging`, and `icmp`.

The current synthetic WebSocket captures support the `messaging` label only. They do not validate WhatsApp recognition. A WhatsApp-specific claim requires separately labelled, authorized real captures and an independent evaluation.

Predictions return `UNKNOWN` when confidence is below the configured threshold. Responses include the predicted class, confidence, unknown status, top predictions, model version, inference time, and optional explainability details.

## Current IPsec-lab training run

The checked-in corpus metadata defines 175 known-class captures with source-declared train/validation/locked-test partitions (105/35/35), plus 25 OOD and 30 anomaly captures. Raw captures are immutable. Build reproducible local artifacts with:

The large PCAP files are kept in the dedicated `ipsec-pcap-lab` dataset repository, not this deployable application repository. Restore its `pcaps/` tree under `data/external/ipsec-pcap-lab/` only for retraining.

```bash
python -m src.preprocess --dataset ipsec-pcap-lab
python -m src.prepare_evaluation_data
python -m src.validate_features
python -m src.build_dataset --minimum-samples-per-class 20 --max-records-per-group 1
python -m src.train
python -m src.leakage_audit
python -m src.evaluate
python -m src.calibrate_unknown
python -m src.anomaly.train
```

The group cap keeps one representative window per capture so long captures cannot dominate. The resulting table has 25 captures per class and excludes duration plus all identifiers, labels, addresses, timestamps, filenames, dataset identity, and IPsec configuration fields from model inputs.

The current selected Random Forest scored 1.00 macro F1 on the 35-capture lab test. This is internal prototype evidence from one generator environment. Because that test generation predates the present threshold-selection process, `src.evaluate` marks it as non-final until a new disjoint test corpus carries `locked_test_generation=post-threshold-v2`. UNKNOWN calibration now divides OOD capture groups into separate calibration and final-evaluation partitions. The experimental Isolation Forest reached 0.918 anomaly F1 on its 65-capture lab evaluation. Exact generated results live under `artifacts/`.

## UNKNOWN calibration

UNKNOWN detection uses maximum model class probability as a rejection baseline. Configure candidate thresholds and OOD Parquet inputs in `config/model.yaml`, then run:

```bash
python -m src.calibrate_unknown
```

The command evaluates several thresholds against the group-safe known validation partition and the OOD calibration partition. OOD capture groups assigned to final evaluation never participate in threshold selection; their rejection rate is reported after the threshold is fixed. It writes calibration metrics to `artifacts/unknown_calibration.json`, then stores the selected threshold in both `config/model.yaml` and model metadata. It never retrains the classifier.

This confidence-threshold approach is a baseline open-set method, not perfect unknown detection. Unseen traffic can still receive high confidence, and known traffic can be rejected. Recalibrate with representative deployment OOD captures before production use.

## Experimental anomaly detection

Anomaly detection is a separate Isolation Forest baseline for identifying flow behavior that is statistically unusual relative to normal-reference traffic. It does not replace or modify traffic classification:

- `UNKNOWN` means the classifier cannot confidently assign a supported traffic class.
- `suspicious` means the flow's statistical behavior is unusual according to the anomaly model.

Neither result implies the other. Train and evaluate the anomaly model independently:

```bash
python -m src.anomaly.train
```

This writes `models/isolation_forest.joblib`, `models/anomaly_metadata.json`, and `artifacts/anomaly_metrics.json`. Held-out normal groups provide a false-positive estimate. For detection precision, recall, F1, and a confusion matrix, configure a separate Parquet file containing the exact model features and a boolean `is_anomaly` label. The labeled evaluation data is never used for fitting.

After successful training, set `anomaly_detection.enabled: true` in `config/model.yaml` and score one `FlowFeatures` JSON document with:

```bash
python -m src.anomaly.predict --input sample.json
```

The returned `anomaly_score` is a clipped 0–1 normalization of the Isolation Forest score based on reference-data quantiles; it is not a calibrated probability. The status boundary remains the fitted Isolation Forest decision threshold.

## Offline capture inference

Analyze a PCAP or PCAPNG using metadata-only flow windows:

```bash
python -m src.analyze_pcap --pcap capture.pcap
```

Add `--explain` for top-five SHAP contributions per prediction. Window duration, burst gap, and idle gap are configured under `feature_extraction` in `config/model.yaml` and can be overridden through CLI flags. The command does not decrypt or inspect packet payloads.

## gRPC inference

Start the inference-only server after a model and UNKNOWN threshold have been calibrated:

```bash
python -m src.grpc_server
```

The reusable API is defined in `proto/ml/v1/traffic_classifier.proto`; its `go_package` targets the repository's Go module. Host, port, worker count, request timeout, graceful-shutdown period, and whether explanations are allowed are configured in `config/model.yaml`. Clients opt into allowed explanations by sending gRPC metadata `x-include-explanations: true`.

Regenerate Python stubs after changing the protobuf definition:

```bash
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/ml/v1/traffic_classifier.proto
```

## Docker inference image

The Docker image is inference-only: it includes the selected trained model, model metadata, training-selection metadata, and the gRPC-serving code. It excludes public datasets, training captures, processed datasets, tests, notebooks, and training code.

Before building, place the selected model (`models/random_forest.joblib` or `models/xgboost.joblib`), `models/model_metadata.json`, and `artifacts/training_metrics.json` in the service directory. The configured UNKNOWN threshold must also be calibrated in `config/model.yaml`.

From the repository root:

```bash
docker build -t sih-ml-service:local ./backend/ml-service
docker run --rm -p 50051:50051 \
  -e ML_GRPC_PORT=50051 \
  sih-ml-service:local
```

The container runs as a non-root `app` user and listens on `0.0.0.0`. Override the published service port with `ML_GRPC_PORT` and, when needed, its bind address with `ML_GRPC_HOST`:

```bash
docker run --rm -p 60051:60051 \
  -e ML_GRPC_PORT=60051 \
  sih-ml-service:local
```

Go sends validated flow-level features to the Python gRPC service. The service is inference-only and never trains a model while serving requests.

## Public-data and IPsec limitation

Public datasets are supplementary training material; VPN-labeled public traffic is not automatically equivalent to traffic observed around an IPsec ESP tunnel. Final model selection, UNKNOWN calibration, anomaly evaluation, and leakage checks require team-generated strongSwan/IPsec captures with known dominant application traffic.

The model classifies only metadata and traffic patterns. It never decrypts or inspects encrypted payload contents. Mixed inner applications inside one opaque site-to-site tunnel are reported as the dominant ten-second window behaviour or `UNKNOWN`. The result is not a recovery of every simultaneous inner application. When opposite ESP directions cannot be paired reliably, the API marks the result as an `aggregate_endpoint_channel_estimate`.

## MVP limitation

The first training captures/windows should contain one dominant known application traffic type. Metadata from an opaque site-to-site ESP tunnel cannot be assumed to perfectly separate multiple simultaneous inner applications.

## Layout

```text
backend/ml-service/
├── src/                 # Production ML and future inference service code
├── tests/               # pytest tests
├── data/raw/            # Original inputs; not committed by default
├── data/processed/      # Prepared feature data
├── models/              # Model artifacts and metadata
└── notebooks/           # Optional exploratory analysis
```

## Development

Create a Python 3.11+ virtual environment and install the pinned top-level dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
pytest
```

Dataset locations, model locations, and confidence thresholds must come from configuration; do not embed local paths or thresholds in code.
