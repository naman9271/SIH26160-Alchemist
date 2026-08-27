# Processed Feature Validation

Generated: 2026-08-27T11:20:14.766236+00:00

Processed Parquet files inspected: 0

No processed Parquet files are currently present. Numeric feature recommendations are therefore not empirically validated.

## Cross-dataset checks

- Features with non-null values in only one dataset: none

### Unit compatibility
- `duration` (seconds): no processed values available for unit validation
- `packet_count` (packets): no processed values available for unit validation
- `total_bytes` (bytes): no processed values available for unit validation
- `packets_per_second` (packets/second): no processed values available for unit validation
- `bytes_per_second` (bytes/second): no processed values available for unit validation
- `mean_packet_size` (bytes): no processed values available for unit validation
- `std_packet_size` (bytes): no processed values available for unit validation
- `min_packet_size` (bytes): no processed values available for unit validation
- `max_packet_size` (bytes): no processed values available for unit validation
- `p25_packet_size` (bytes): no processed values available for unit validation
- `median_packet_size` (bytes): no processed values available for unit validation
- `p75_packet_size` (bytes): no processed values available for unit validation
- `p95_packet_size` (bytes): no processed values available for unit validation
- `mean_interarrival_time` (seconds): no processed values available for unit validation
- `std_interarrival_time` (seconds): no processed values available for unit validation
- `upload_packets` (packets): no processed values available for unit validation
- `download_packets` (packets): no processed values available for unit validation
- `upload_bytes` (bytes): no processed values available for unit validation
- `download_bytes` (bytes): no processed values available for unit validation
- `upload_download_ratio` (ratio): no processed values available for unit validation
- `burst_count` (bursts): no processed values available for unit validation
- `mean_burst_size` (packets/burst): no processed values available for unit validation
- `idle_time_ratio` (ratio): no processed values available for unit validation

## Recommendations

1. Safe across public datasets: none
2. Usable only for our own IPsec dataset: burst_count, idle_time_ratio, mean_burst_size
3. Drop: canonical_label, capture_id, dataset_source, excluded_leakage_columns, flow_id, original_label, source_record_id, split_group_id

No processed Parquet files were found; no numeric feature is empirically approved.
