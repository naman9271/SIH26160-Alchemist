# ML validation protocol

## Purpose

An available ML worker proves that the integration and persisted model work. It
does **not** prove that the model is accurate for arbitrary VPN deployments.
Validate the classifier against independently captured, labelled traffic before
making accuracy claims in a submission.

## Supported labels

`web`, `video`, `voip`, `email`, `file_transfer`, `messaging`, and `icmp`.
`UNKNOWN` is a confidence-threshold rejection outcome, not a trained class.

## Required evaluation set

For every capture, retain:

- a stable capture SHA-256 and licence/provenance;
- the dominant expected application class;
- independent capture group/topology, not many windows from one PCAP;
- IPsec configuration, traffic generator, timestamp, and tool versions;
- known OOD traffic such as DNS-heavy, remote desktop, database, gaming, or
  another unsupported application.

Do not use private traffic, credentials, payloads, or reusable VPN keys.

## Reproducible checks

Use Python 3.11 and the full ML dependencies:

```bash
cd backend/ml-service
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest
python -m src.validate_features
python -m src.leakage_audit
python -m src.evaluate
python -m src.calibrate_unknown
```

Record macro F1, per-class precision/recall, confusion matrix, UNKNOWN false-
unknown rate on known traffic, OOD rejection rate, model version, and threshold.
The existing artifacts are lab results only; review them alongside the dataset
provenance before citing them.

## Dashboard acceptance check

For each labelled classic PCAP, upload it with **ML classification** enabled.
Compare the displayed class and confidence with the ground truth. A low-
confidence `UNKNOWN` is an expected abstention. A confident but incorrect class
is an error to record and investigate. Never use a single ESP capture as an
accuracy claim.
