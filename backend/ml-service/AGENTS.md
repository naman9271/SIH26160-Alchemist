# ML Service Agent Guide

## Scope

`backend/ml-service/` contains the Python ML component for the SIH IPsec VPN security analyzer. Python is used only for ML. The Go backend remains responsible for networking, packet handling, IPsec/IKE protocol facts, and security assessment logic.

The initial ML use case is classification of encrypted traffic from flow-level metadata. It must not attempt to decrypt ESP payloads or infer protocol facts such as IKE version, cipher, SPI, DH group, or PFS.

## Initial contract

The first classifier may predict:

`web`, `video`, `voip`, `email`, `file_transfer`, `messaging`, and `icmp`.

It must also support `UNKNOWN` when confidence is insufficient. Experimental anomaly detection is a separate component and must not alter or replace classifier output. The eventual service boundary is gRPC: Go sends flow-level features to Python, and Python returns the predicted class, confidence, unknown status, top predictions, and explainability information.

For the MVP, each training capture/window is assumed to contain one dominant known application traffic type. Do not claim that opaque site-to-site ESP metadata can perfectly separate multiple simultaneous inner applications.

## Engineering rules

- Target Python 3.11+ and use type hints for new Python code.
- Keep training code separate from inference code; do not mix model fitting with serving paths.
- Prefer small, production-quality modules over framework-heavy abstractions.
- Use structured configuration files or environment-backed settings for dataset paths, model paths, and confidence thresholds. Never hardcode those values in source code.
- Use the standard `logging` module; do not use print statements for service or training diagnostics.
- Add pytest coverage for new behavior and keep tests deterministic.
- Keep raw data, processed data, and model artifacts in their designated directories. Do not commit datasets or generated model binaries unless explicitly requested.
- Do not add databases, queues, Kubernetes manifests, or other infrastructure inside this directory.
- Preserve the Go/Python boundary. Changes to `backend/` or `frontend/` are outside this component's scope unless explicitly requested.

## Directory intent

- `src/`: ML source and, later, gRPC inference code.
- `tests/`: unit and contract tests.
- `data/raw/`: source captures or extracted metadata; treat as immutable inputs.
- `data/processed/`: reproducible feature datasets prepared for training.
- `models/`: versioned model artifacts and metadata.
- `notebooks/`: exploratory work only; production logic belongs in `src/`.

## Validation expectations

Before handing off implementation work, run the focused pytest suite and any configured formatting, linting, or type-checking commands. For model changes, document the dataset/configuration used, class coverage, confidence/UNKNOWN behavior, and evaluation results.
