# Dataset Leakage and Source Memorization Audit

## Recommended fixes

- Generate and validate processed public datasets before building the supervised dataset.
- Build training_dataset.parquet only from features approved by feature_validation.json.
- Train both classifiers, then rerun this audit without changing the leakage thresholds.

Status: **blocked**

## Findings

- No empirical leakage claim can be made because trained model artifacts are unavailable.

## Missing artifacts

- `/Users/dakshpathak/Desktop/SIH_IPSec/SIH26160---Team-Alchemist/ml-service/data/processed/training_dataset.parquet`
- `/Users/dakshpathak/Desktop/SIH_IPSec/SIH26160---Team-Alchemist/ml-service/models/model_metadata.json`
- `/Users/dakshpathak/Desktop/SIH_IPSec/SIH26160---Team-Alchemist/ml-service/artifacts/training_metrics.json`

No experiment results are reported because doing so would fabricate evidence.
