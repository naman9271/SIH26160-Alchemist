# Encrypted traffic classifier model card

## Intended use

The model estimates the dominant traffic category of an IPsec ESP flow window from observable metadata. Supported labels are web, video, VoIP, email, file transfer, messaging, and ICMP. It can return `UNKNOWN` when maximum class probability falls below the configured threshold.

The model does not decrypt ESP, identify a user, prove a specific application, recover simultaneous inner flows, or determine IKE and CHILD-SA cryptography. The synthetic WebSocket workload supports the generic `messaging` class and does not validate WhatsApp recognition.

## Inputs

Features include packet-size statistics, timing, direction, burst behavior, packet counts, and byte rates. Identifiers, addresses, filenames, labels, timestamps, dataset identity, and VPN profile settings remain audit metadata and never enter model features.

## Dataset

The frozen lab snapshot contains 239 captures:

| Role | Captures | Use |
| --- | ---: | --- |
| Known traffic | 175 | Supervised model development and internal evaluation |
| OOD traffic | 25 | UNKNOWN calibration and final OOD evaluation |
| Anomaly traffic | 30 | Separate anomaly detector evaluation |
| Protocol validation | 5 | Parser and profile checks, excluded from fitting |
| Archived provenance | 4 | Excluded from fitting |

The known corpus has 25 captures per supported class across five original VPN profiles. Current active profiles P06-P08 are not part of the checked-in training corpus.

## Split policy

The current source divides groups into four disjoint roles:

- training for fitting candidate models;
- validation for candidate and model-family selection;
- calibration for UNKNOWN threshold selection;
- locked test for final known-class evaluation.

OOD capture groups are deterministically divided between threshold calibration and final OOD evaluation. Any model or report generated before this four-way policy is prototype evidence and must be regenerated before final metric claims.

## Checked-in result and its limit

The checked-in Random Forest artifact reports 100% closed-set accuracy and macro F1 on 35 internal test captures, five per class. The data comes from one controlled generator environment. The result does not establish field accuracy, cross-network generalization, application identity, or performance after abstention. The evaluator marks this locked test as non-final until a new post-threshold corpus is collected.

## Required release metrics

A submission-ready model release must publish:

- per-class precision, recall, F1, and support;
- confusion matrix and probability calibration metrics;
- known-traffic rejection rate after fixing the UNKNOWN threshold;
- final OOD rejection rate from groups excluded from threshold selection;
- model, dataset, feature-schema, and code hashes;
- results from an independently collected environment;
- error analysis for mixed and unsupported workloads.

## Ethical and operational considerations

Traffic predictions are probabilistic metadata estimates. Reports must display confidence and the UNKNOWN state, and must not present a label as proof of a person's activity. Captures may expose endpoint and timing metadata; operators remain responsible for authorization, minimization, retention, and access control.
