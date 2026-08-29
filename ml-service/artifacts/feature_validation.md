# Processed Feature Validation

Generated: 2026-08-29T10:09:02.109741+00:00

Processed Parquet files inspected: 1

## ipsec-pcap-lab.parquet

- Rows: 64
- Class distribution: `{"file_transfer": 15, "icmp": 15, "video": 26, "web": 8}`
- Dataset-source distribution: `{"ipsec-pcap-lab": 64}`
- Duplicates: `{"exact_duplicate_count": 0, "feature_and_label_duplicate_count": 0}`
- Potential leakage: Metadata columns are excluded from model features: canonical_label, capture_id, dataset_source, excluded_leakage_columns, flow_id, original_label, source_record_id, split_group_id; Adapters flagged possible source leakage: IPsec/IKE configuration ground truth, capture checksum, flow_id, outer source/destination addresses, sample_id and capture filename, traffic generator name, traffic_class label

### Feature checks

| Feature | Type | Missing % | Range | Constant | NaN/Inf |
| --- | --- | ---: | --- | --- | --- |
| duration | double | 0.0 | 0.00010800361633300781 to 9.999422073364258 | False | 0/0 |
| packet_count | int64 | 0.0 | 2.0 to 15952.0 | False | 0/0 |
| total_bytes | int64 | 0.0 | 260.0 to 22866096.0 | False | 0/0 |
| packets_per_second | double | 0.0 | 3.333334028721001 to 18517.898454746137 | False | 0/0 |
| bytes_per_second | double | 0.0 | 540.0001126528022 to 11204759.617951691 | False | 0/0 |
| mean_packet_size | double | 0.0 | 130.0 to 1486.3207157604954 | False | 0/0 |
| std_packet_size | double | 0.0 | 0.0 to 686.5617370223956 | False | 0/0 |
| min_packet_size | double | 0.0 | 130.0 to 214.0 | False | 0/0 |
| max_packet_size | double | 0.0 | 130.0 to 1514.0 | False | 0/0 |
| p25_packet_size | double | 0.0 | 130.0 to 1514.0 | False | 0/0 |
| median_packet_size | double | 0.0 | 130.0 to 1514.0 | False | 0/0 |
| p75_packet_size | double | 0.0 | 130.0 to 1514.0 | False | 0/0 |
| p95_packet_size | double | 0.0 | 130.0 to 1514.0 | False | 0/0 |
| mean_interarrival_time | double | 0.0 | 7.803719720722716e-05 to 0.3096773547510947 | False | 0/0 |
| std_interarrival_time | double | 0.0 | 0.0 to 0.3196967281054168 | False | 0/0 |
| upload_packets | int64 | 0.0 | 1.0 to 1898.0 | False | 0/0 |
| download_packets | int64 | 0.0 | 1.0 to 15053.0 | False | 0/0 |
| upload_bytes | int64 | 0.0 | 130.0 to 348796.0 | False | 0/0 |
| download_bytes | int64 | 0.0 | 130.0 to 22701886.0 | False | 0/0 |
| upload_download_ratio | double | 0.0 | 0.001203967720094102 to 1.0 | False | 0/0 |
| burst_count | int64 | 0.0 | 1.0 to 49.0 | False | 0/0 |
| mean_burst_size | double | 0.0 | 2.0 to 673.8333333333334 | False | 0/0 |
| idle_time_ratio | double | 0.0 | 0.0 to 0.9732885456204504 | False | 0/0 |

## Cross-dataset checks

- Features with non-null values in only one dataset: {"burst_count": ["ipsec-pcap-lab"], "bytes_per_second": ["ipsec-pcap-lab"], "download_bytes": ["ipsec-pcap-lab"], "download_packets": ["ipsec-pcap-lab"], "duration": ["ipsec-pcap-lab"], "idle_time_ratio": ["ipsec-pcap-lab"], "max_packet_size": ["ipsec-pcap-lab"], "mean_burst_size": ["ipsec-pcap-lab"], "mean_interarrival_time": ["ipsec-pcap-lab"], "mean_packet_size": ["ipsec-pcap-lab"], "median_packet_size": ["ipsec-pcap-lab"], "min_packet_size": ["ipsec-pcap-lab"], "p25_packet_size": ["ipsec-pcap-lab"], "p75_packet_size": ["ipsec-pcap-lab"], "p95_packet_size": ["ipsec-pcap-lab"], "packet_count": ["ipsec-pcap-lab"], "packets_per_second": ["ipsec-pcap-lab"], "std_interarrival_time": ["ipsec-pcap-lab"], "std_packet_size": ["ipsec-pcap-lab"], "total_bytes": ["ipsec-pcap-lab"], "upload_bytes": ["ipsec-pcap-lab"], "upload_download_ratio": ["ipsec-pcap-lab"], "upload_packets": ["ipsec-pcap-lab"]}

### Unit compatibility
- `duration` (seconds): only one processed dataset has values; cross-dataset compatibility untested
- `packet_count` (packets): only one processed dataset has values; cross-dataset compatibility untested
- `total_bytes` (bytes): only one processed dataset has values; cross-dataset compatibility untested
- `packets_per_second` (packets/second): only one processed dataset has values; cross-dataset compatibility untested
- `bytes_per_second` (bytes/second): only one processed dataset has values; cross-dataset compatibility untested
- `mean_packet_size` (bytes): only one processed dataset has values; cross-dataset compatibility untested
- `std_packet_size` (bytes): only one processed dataset has values; cross-dataset compatibility untested
- `min_packet_size` (bytes): only one processed dataset has values; cross-dataset compatibility untested
- `max_packet_size` (bytes): only one processed dataset has values; cross-dataset compatibility untested
- `p25_packet_size` (bytes): only one processed dataset has values; cross-dataset compatibility untested
- `median_packet_size` (bytes): only one processed dataset has values; cross-dataset compatibility untested
- `p75_packet_size` (bytes): only one processed dataset has values; cross-dataset compatibility untested
- `p95_packet_size` (bytes): only one processed dataset has values; cross-dataset compatibility untested
- `mean_interarrival_time` (seconds): only one processed dataset has values; cross-dataset compatibility untested
- `std_interarrival_time` (seconds): only one processed dataset has values; cross-dataset compatibility untested
- `upload_packets` (packets): only one processed dataset has values; cross-dataset compatibility untested
- `download_packets` (packets): only one processed dataset has values; cross-dataset compatibility untested
- `upload_bytes` (bytes): only one processed dataset has values; cross-dataset compatibility untested
- `download_bytes` (bytes): only one processed dataset has values; cross-dataset compatibility untested
- `upload_download_ratio` (ratio): only one processed dataset has values; cross-dataset compatibility untested
- `burst_count` (bursts): only one processed dataset has values; cross-dataset compatibility untested
- `mean_burst_size` (packets/burst): only one processed dataset has values; cross-dataset compatibility untested
- `idle_time_ratio` (ratio): only one processed dataset has values; cross-dataset compatibility untested

## Recommendations

1. Safe across public datasets: none
2. Usable only for our own IPsec dataset: burst_count, bytes_per_second, download_bytes, download_packets, duration, idle_time_ratio, max_packet_size, mean_burst_size, mean_interarrival_time, mean_packet_size, median_packet_size, min_packet_size, p25_packet_size, p75_packet_size, p95_packet_size, packet_count, packets_per_second, std_interarrival_time, std_packet_size, total_bytes, upload_bytes, upload_download_ratio, upload_packets
3. Drop: canonical_label, capture_id, dataset_source, excluded_leakage_columns, flow_id, original_label, source_record_id, split_group_id

Recommendations are audit gates, not training results. Apply group-aware splits and confirm source-unit provenance before combining any future datasets.
