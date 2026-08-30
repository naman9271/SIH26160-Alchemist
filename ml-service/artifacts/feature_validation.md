# Processed Feature Validation

Generated: 2026-08-30T18:37:01.188235+00:00

Processed Parquet files inspected: 3

## ipsec-pcap-lab-anomaly-evaluation.parquet

- Rows: 65
- Class distribution: `{"IGNORE": 30, "email": 5, "file_transfer": 5, "icmp": 5, "messaging": 5, "video": 5, "voip": 5, "web": 5}`
- Dataset-source distribution: `{"ipsec-pcap-lab": 65}`
- Duplicates: `{"exact_duplicate_count": 0, "feature_and_label_duplicate_count": 0}`
- Potential leakage: Metadata columns are excluded from model features: canonical_label, capture_id, dataset_source, original_label, source_record_id, split_group_id; Unexpected, unvetted columns must not be model features: anomaly_type, dataset_role, is_anomaly; High feature/label correlations require provenance review before model use.

### Feature checks

| Feature | Type | Missing % | Range | Constant | NaN/Inf |
| --- | --- | ---: | --- | --- | --- |
| duration | double | 0.0 | 0.6338388919830322 to 9.995725870132446 | False | 0/0 |
| packet_count | int64 | 0.0 | 30.0 to 30168.0 | False | 0/0 |
| total_bytes | int64 | 0.0 | 7600.0 to 37482144.0 | False | 0/0 |
| packets_per_second | double | 0.0 | 3.0546918445469244 to 4032.221988490106 | False | 0/0 |
| bytes_per_second | double | 0.0 | 791.1022683376663 to 5009822.501079041 | False | 0/0 |
| mean_packet_size | double | 0.0 | 154.40677966101694 to 1445.9131857345403 | False | 0/0 |
| std_packet_size | double | 0.0 | 0.0 to 667.6526751039714 | False | 0/0 |
| min_packet_size | double | 0.0 | 98.0 to 1366.0 | False | 0/0 |
| max_packet_size | double | 0.0 | 214.0 to 1514.0 | False | 0/0 |
| p25_packet_size | double | 0.0 | 130.0 to 1514.0 | False | 0/0 |
| median_packet_size | double | 0.0 | 130.0 to 1514.0 | False | 0/0 |
| p75_packet_size | double | 0.0 | 130.0 to 1514.0 | False | 0/0 |
| p95_packet_size | double | 0.0 | 214.0 to 1514.0 | False | 0/0 |
| mean_interarrival_time | double | 0.0 | 0.0002480104398169445 to 0.33865372065840094 | False | 0/0 |
| std_interarrival_time | double | 0.0 | 0.002902756397220583 to 0.4722247439641185 | False | 0/0 |
| upload_packets | int64 | 0.0 | 19.0 to 5868.0 | False | 0/0 |
| download_packets | int64 | 0.0 | 11.0 to 24300.0 | False | 0/0 |
| upload_bytes | int64 | 0.0 | 3320.0 to 4259546.0 | False | 0/0 |
| download_bytes | int64 | 0.0 | 4208.0 to 36672024.0 | False | 0/0 |
| upload_download_ratio | double | 0.0 | 0.0038963024534415373 to 48.57996509795091 | False | 0/0 |
| burst_count | int64 | 0.0 | 1.0 to 79.0 | False | 0/0 |
| mean_burst_size | double | 0.0 | 2.0 to 30168.0 | False | 0/0 |
| idle_time_ratio | double | 0.0 | 0.0 to 0.9122785415080401 | False | 0/0 |

### Suspicious feature/label correlations

`[{"class": "web", "correlation": -0.951743, "feature": "duration"}, {"class": "email", "correlation": 0.987085, "feature": "upload_bytes"}]`

## ipsec-pcap-lab-ood.parquet

- Rows: 25
- Class distribution: `{"IGNORE": 25}`
- Dataset-source distribution: `{"ipsec-pcap-lab": 25}`
- Duplicates: `{"exact_duplicate_count": 0, "feature_and_label_duplicate_count": 0}`
- Potential leakage: Metadata columns are excluded from model features: canonical_label, capture_id, dataset_source, original_label, source_record_id, split_group_id; Unexpected, unvetted columns must not be model features: anomaly_type, dataset_role, is_anomaly

### Feature checks

| Feature | Type | Missing % | Range | Constant | NaN/Inf |
| --- | --- | ---: | --- | --- | --- |
| duration | double | 0.0 | 9.674612045288086 to 9.998539924621582 | False | 0/0 |
| packet_count | int64 | 0.0 | 28.0 to 130.0 | False | 0/0 |
| total_bytes | int64 | 0.0 | 3064.0 to 39260.0 | False | 0/0 |
| packets_per_second | double | 0.0 | 2.893973066158489 to 13.04169682369369 | False | 0/0 |
| bytes_per_second | double | 0.0 | 316.7052059200955 to 3938.592440755494 | False | 0/0 |
| mean_packet_size | double | 0.0 | 109.42857142857143 to 879.0526315789474 | False | 0/0 |
| std_packet_size | double | 0.0 | 8.0 to 172.0555215419569 | False | 0/0 |
| min_packet_size | double | 0.0 | 98.0 to 666.0 | False | 0/0 |
| max_packet_size | double | 0.0 | 130.0 to 1018.0 | False | 0/0 |
| p25_packet_size | double | 0.0 | 98.0 to 666.0 | False | 0/0 |
| median_packet_size | double | 0.0 | 98.0 to 1018.0 | False | 0/0 |
| p75_packet_size | double | 0.0 | 130.0 to 1018.0 | False | 0/0 |
| p95_packet_size | double | 0.0 | 130.0 to 1018.0 | False | 0/0 |
| mean_interarrival_time | double | 0.0 | 0.07727153541505799 to 0.3583437071906196 | False | 0/0 |
| std_interarrival_time | double | 0.0 | 0.07776391623162661 to 0.47827537583131 | False | 0/0 |
| upload_packets | int64 | 0.0 | 18.0 to 65.0 | False | 0/0 |
| download_packets | int64 | 0.0 | 10.0 to 65.0 | False | 0/0 |
| upload_bytes | int64 | 0.0 | 1764.0 to 23414.0 | False | 0/0 |
| download_bytes | int64 | 0.0 | 1300.0 to 21190.0 | False | 0/0 |
| upload_download_ratio | double | 0.0 | 0.852760736196319 to 2.3740394600207684 | False | 0/0 |
| burst_count | int64 | 0.0 | 9.0 to 65.0 | False | 0/0 |
| mean_burst_size | double | 0.0 | 1.5555555555555556 to 4.333333333333333 | False | 0/0 |
| idle_time_ratio | double | 0.0 | 0.0 to 0.8717690587996156 | False | 0/0 |

## ipsec-pcap-lab.parquet

- Rows: 591
- Class distribution: `{"email": 45, "file_transfer": 59, "icmp": 47, "messaging": 199, "video": 64, "voip": 149, "web": 28}`
- Dataset-source distribution: `{"ipsec-pcap-lab": 591}`
- Duplicates: `{"exact_duplicate_count": 0, "feature_and_label_duplicate_count": 0}`
- Potential leakage: Metadata columns are excluded from model features: canonical_label, capture_id, dataset_source, excluded_leakage_columns, flow_id, original_label, source_record_id, split_group_id; Adapters flagged possible source leakage: IPsec/IKE configuration ground truth, capture checksum, flow_id, outer source/destination addresses, sample_id and capture filename, traffic generator name, traffic_class label; Unexpected, unvetted columns must not be model features: declared_split

### Feature checks

| Feature | Type | Missing % | Range | Constant | NaN/Inf |
| --- | --- | ---: | --- | --- | --- |
| duration | double | 0.0 | 8.702278137207031e-05 to 9.99992299079895 | False | 0/0 |
| packet_count | int64 | 0.0 | 2.0 to 30168.0 | False | 0/0 |
| total_bytes | int64 | 0.0 | 260.0 to 37482144.0 | False | 0/0 |
| packets_per_second | double | 0.0 | 3.333334028721001 to 22982.487671232877 | False | 0/0 |
| bytes_per_second | double | 0.0 | 540.0001126528022 to 21765960.472505093 | False | 0/0 |
| mean_packet_size | double | 0.0 | 130.0 to 1486.4581779435268 | False | 0/0 |
| std_packet_size | double | 0.0 | 0.0 to 686.5617370223956 | False | 0/0 |
| min_packet_size | double | 0.0 | 130.0 to 1322.0 | False | 0/0 |
| max_packet_size | double | 0.0 | 130.0 to 1514.0 | False | 0/0 |
| p25_packet_size | double | 0.0 | 130.0 to 1514.0 | False | 0/0 |
| median_packet_size | double | 0.0 | 130.0 to 1514.0 | False | 0/0 |
| p75_packet_size | double | 0.0 | 130.0 to 1514.0 | False | 0/0 |
| p95_packet_size | double | 0.0 | 130.0 to 1514.0 | False | 0/0 |
| mean_interarrival_time | double | 0.0 | 7.803719720722716e-05 to 0.3096773547510947 | False | 0/0 |
| std_interarrival_time | double | 0.0 | 0.0 to 0.3721243433283505 | False | 0/0 |
| upload_packets | int64 | 0.0 | 1.0 to 5868.0 | False | 0/0 |
| download_packets | int64 | 0.0 | 1.0 to 24300.0 | False | 0/0 |
| upload_bytes | int64 | 0.0 | 130.0 to 6374662.0 | False | 0/0 |
| download_bytes | int64 | 0.0 | 130.0 to 36672024.0 | False | 0/0 |
| upload_download_ratio | double | 0.0 | 0.001203967720094102 to 61.79347071081269 | False | 0/0 |
| burst_count | int64 | 0.0 | 1.0 to 79.0 | False | 0/0 |
| mean_burst_size | double | 0.0 | 1.1666666666666667 to 30168.0 | False | 0/0 |
| idle_time_ratio | double | 0.0 | 0.0 to 0.9732885456204504 | False | 0/0 |

## Cross-dataset checks

- Features with non-null values in only one dataset: none

### Unit compatibility
- `duration` (seconds): common-schema unit; review source conversion provenance before combining
- `packet_count` (packets): common-schema unit; review source conversion provenance before combining
- `total_bytes` (bytes): common-schema unit; review source conversion provenance before combining
- `packets_per_second` (packets/second): common-schema unit; review source conversion provenance before combining
- `bytes_per_second` (bytes/second): common-schema unit; review source conversion provenance before combining
- `mean_packet_size` (bytes): common-schema unit; review source conversion provenance before combining
- `std_packet_size` (bytes): common-schema unit; review source conversion provenance before combining
- `min_packet_size` (bytes): common-schema unit; review source conversion provenance before combining
- `max_packet_size` (bytes): common-schema unit; review source conversion provenance before combining
- `p25_packet_size` (bytes): common-schema unit; review source conversion provenance before combining
- `median_packet_size` (bytes): common-schema unit; review source conversion provenance before combining
- `p75_packet_size` (bytes): common-schema unit; review source conversion provenance before combining
- `p95_packet_size` (bytes): common-schema unit; review source conversion provenance before combining
- `mean_interarrival_time` (seconds): common-schema unit; review source conversion provenance before combining
- `std_interarrival_time` (seconds): common-schema unit; review source conversion provenance before combining
- `upload_packets` (packets): common-schema unit; review source conversion provenance before combining
- `download_packets` (packets): common-schema unit; review source conversion provenance before combining
- `upload_bytes` (bytes): common-schema unit; review source conversion provenance before combining
- `download_bytes` (bytes): common-schema unit; review source conversion provenance before combining
- `upload_download_ratio` (ratio): common-schema unit; review source conversion provenance before combining
- `burst_count` (bursts): common-schema unit; review source conversion provenance before combining
- `mean_burst_size` (packets/burst): common-schema unit; review source conversion provenance before combining
- `idle_time_ratio` (ratio): common-schema unit; review source conversion provenance before combining

## Recommendations

1. Safe across public datasets: burst_count, bytes_per_second, download_bytes, download_packets, idle_time_ratio, max_packet_size, mean_burst_size, mean_interarrival_time, mean_packet_size, median_packet_size, min_packet_size, p25_packet_size, p75_packet_size, p95_packet_size, packet_count, packets_per_second, std_interarrival_time, std_packet_size, total_bytes, upload_download_ratio, upload_packets
2. Usable only for our own IPsec dataset: none
3. Drop: canonical_label, capture_id, dataset_source, excluded_leakage_columns, flow_id, original_label, source_record_id, split_group_id

Recommendations are audit gates, not training results. Apply group-aware splits and confirm source-unit provenance before combining any future datasets.
