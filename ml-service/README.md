# ML Service

Python 3.11+ component for encrypted traffic classification in the SIH IPsec VPN security analyzer.

## Responsibility

The service classifies traffic using flow-level metadata that remains observable around encrypted ESP traffic. It does not decrypt ESP payloads and does not evaluate IKE or cryptographic configuration. Protocol facts—including IKE version, cipher, SPI, DH group, and PFS—belong to the Go/backend analysis layer.

Initial classes are:

`web`, `video`, `voip`, `email`, `file_transfer`, `messaging`, and `icmp`.

Predictions must be able to return `UNKNOWN` when confidence is below the configured threshold. Responses are planned to include the predicted class, confidence, unknown status, top predictions, and explainability details.

## UNKNOWN calibration

UNKNOWN detection uses maximum model class probability as a rejection baseline. Configure candidate thresholds and OOD Parquet inputs in `config/model.yaml`, then run:

```bash
python -m src.calibrate_unknown
```

The command evaluates several thresholds against the group-safe known holdout and eligible held-out-class or unseen-source traffic. It writes calibration metrics to `artifacts/unknown_calibration.json`, then stores the selected threshold in both `config/model.yaml` and model metadata. It never retrains the classifier.

This confidence-threshold approach is a baseline open-set method, not perfect unknown detection. Unseen traffic can still receive high confidence, and known traffic can be rejected. Recalibrate with representative deployment OOD captures before production use.

The planned integration is gRPC: Go will send flow-level features to Python. The ML pipeline and gRPC server are intentionally not implemented yet.

## MVP limitation

The first training captures/windows should contain one dominant known application traffic type. Metadata from an opaque site-to-site ESP tunnel cannot be assumed to perfectly separate multiple simultaneous inner applications.

## Layout

```text
ml-service/
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
