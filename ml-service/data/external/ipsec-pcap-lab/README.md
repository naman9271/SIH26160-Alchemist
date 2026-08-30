# IPsec PCAP lab dataset snapshot

This directory contains the retained metadata and frozen manifest for a validated
data snapshot imported from the separate
[`ipsec-pcap-lab`](https://github.com/naman9271/ipsec-pcap-lab) repository at
source commit `c0cf256`. The reproducible Docker/strongSwan testbed, generators,
validation scripts, and large PCAP files remain in that repository; they are
intentionally not duplicated here or included in inference deployments.

The captures contain only outer-side IPsec traffic. The ML pipeline extracts
flow metadata from ESP or UDP/4500-encapsulated ESP and does not decrypt payloads.

## Restoring captures for retraining

The manifest describes 239 classic Ethernet PCAPs referenced by `metadata.csv`.
To retrain, check out source commit `c0cf256` in the dedicated dataset repository
and restore its `pcaps/` directory beside this file. Do not commit the restored
captures to the main application repository.

The external snapshot contains:

| Dataset role | Captures | Intended use |
|---|---:|---|
| `train_known` | 175 | Seven supported application classes across P01-P05 and R01-R05 |
| `ood_eval` | 25 | UNKNOWN/OOD calibration only |
| `anomaly_eval` | 30 | Isolation Forest evaluation only |
| `protocol_validation` | 5 | Go-side IKE/IPsec protocol validation only |
| `archived_provenance` | 4 | Preserved history; excluded from training and evaluation |

The seven known classes are `web`, `video`, `voip`, `email`, `file_transfer`,
`messaging`, and `icmp`. Each class has five profiles and five runs. For known
records, R01-R03 are training captures, R04 is validation, and R05 is the locked
test capture.

OOD coverage consists of DNS, interactive SSH, gaming-style UDP, database, and
remote-desktop traffic across P01-P05. Anomaly coverage consists of ten captures
each for ICMP flood, UDP flood, and beacon-then-burst behavior.

## Integrity

`dataset-manifest-v1.0.csv` is the frozen, machine-readable index. It contains
one row per metadata record and records each capture's path, SHA-256, role,
label, profile, run, split, packet count, observed span, file size, and capture
timestamps.

The source repository's strict validator passed before this manifest was
generated. At import time:

- all 239 manifest paths existed;
- all common PCAPs matched the source byte-for-byte;
- no manifest-referenced capture was missing;
- no unreferenced PCAP remained in the validated source snapshot.

## Important usage rules

- `dataset_role` is authoritative. Only `train_known` may enter supervised
  classifier training.
- `ood_eval`, `anomaly_eval`, `protocol_validation`, and
  `archived_provenance` must never be treated as application training classes.
- `canonical_label=IGNORE` means exclusion from supervised classification.
- Dataset identity, filenames, sample IDs, profile IDs, run IDs, addresses,
  cryptographic settings, and protocol facts are audit metadata, not ML inputs.
- Protocol facts such as IKE version, cipher, DH group, PFS, SPI, and operating
  mode remain Go/backend responsibilities.

## Known limitations

The capture count is balanced, but the number of extracted 10-second windows is
not: web produces far fewer windows than messaging or VoIP because observed
traffic duration is class-dependent. Training must cap complete windows per
capture and perform leakage analysis; a future capture revision should use a
common sustained traffic duration.

This snapshot uses PSK authentication and forced UDP encapsulation where noted.
It does not claim real NAT traversal, certificate authentication, SA rekey,
key-lifetime expiry, replay-protection validation, AH, or normal non-IPsec
negative captures. Messaging is synthetic bidirectional WebSocket traffic, not
an assertion that the model specifically recognizes WhatsApp.
