# Dataset Leakage and Source Memorization Audit

## Recommended fixes

- Repeat evaluation with held-out capture environments and independently collected IPsec traffic.
- Review units and capture tooling for suspicious features; drop them only after confirming the ablation result.

Status: **complete**

## Findings

- Grouped test accuracy is unusually high and requires source-level confirmation.
- Dominant features need artifact checks or encode measured source differences: mean_burst_size, mean_interarrival_time, packets_per_second, std_packet_size, upload_download_ratio

## 1. Normal grouped test evaluation

`{"accuracy": 1.0, "confusion_matrix": [[5, 0, 0, 0, 0, 0, 0], [0, 5, 0, 0, 0, 0, 0], [0, 0, 5, 0, 0, 0, 0], [0, 0, 0, 5, 0, 0, 0], [0, 0, 0, 0, 5, 0, 0], [0, 0, 0, 0, 0, 5, 0], [0, 0, 0, 0, 0, 0, 5]], "confusion_matrix_labels": ["email", "file_transfer", "icmp", "messaging", "video", "voip", "web"], "macro_f1": 1.0, "per_class": {"email": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "file_transfer": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "icmp": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "messaging": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "video": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "voip": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "web": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}}, "weighted_f1": 1.0}`

## 2. Leave-one-source-out evaluation

`{"ipsec-pcap-lab": {"incompatible_classes": ["email", "file_transfer", "icmp", "messaging", "video", "voip", "web"], "reason": "Fewer than two compatible training classes or no compatible test rows.", "status": "skipped"}}`

## 3. Feature importance and source association

Importance: `[{"feature": "upload_download_ratio", "importance": 0.12979664}, {"feature": "mean_burst_size", "importance": 0.09435763}, {"feature": "packets_per_second", "importance": 0.08373017}, {"feature": "std_packet_size", "importance": 0.08250845}, {"feature": "mean_interarrival_time", "importance": 0.07707429}, {"feature": "median_packet_size", "importance": 0.07550578}, {"feature": "mean_packet_size", "importance": 0.07374333}, {"feature": "download_packets", "importance": 0.05028032}, {"feature": "total_bytes", "importance": 0.04432606}, {"feature": "download_bytes", "importance": 0.0427392}, {"feature": "upload_packets", "importance": 0.03992315}, {"feature": "bytes_per_second", "importance": 0.03921904}, {"feature": "std_interarrival_time", "importance": 0.02834512}, {"feature": "packet_count", "importance": 0.0259728}, {"feature": "max_packet_size", "importance": 0.02431561}, {"feature": "burst_count", "importance": 0.02351224}, {"feature": "p25_packet_size", "importance": 0.02090406}, {"feature": "idle_time_ratio", "importance": 0.01689517}, {"feature": "p95_packet_size", "importance": 0.01459951}, {"feature": "p75_packet_size", "importance": 0.00920853}, {"feature": "min_packet_size", "importance": 0.00304287}]`

Source association: `[{"feature": "burst_count", "source_eta_squared": 0.0}, {"feature": "bytes_per_second", "source_eta_squared": 0.0}, {"feature": "download_bytes", "source_eta_squared": 0.0}, {"feature": "download_packets", "source_eta_squared": 0.0}, {"feature": "idle_time_ratio", "source_eta_squared": 0.0}, {"feature": "max_packet_size", "source_eta_squared": 0.0}, {"feature": "mean_burst_size", "source_eta_squared": 0.0}, {"feature": "mean_interarrival_time", "source_eta_squared": 0.0}, {"feature": "mean_packet_size", "source_eta_squared": 0.0}, {"feature": "median_packet_size", "source_eta_squared": 0.0}, {"feature": "min_packet_size", "source_eta_squared": 0.0}, {"feature": "p25_packet_size", "source_eta_squared": 0.0}, {"feature": "p75_packet_size", "source_eta_squared": 0.0}, {"feature": "p95_packet_size", "source_eta_squared": 0.0}, {"feature": "packet_count", "source_eta_squared": 0.0}, {"feature": "packets_per_second", "source_eta_squared": 0.0}, {"feature": "std_interarrival_time", "source_eta_squared": 0.0}, {"feature": "std_packet_size", "source_eta_squared": 0.0}, {"feature": "total_bytes", "source_eta_squared": 0.0}, {"feature": "upload_download_ratio", "source_eta_squared": 0.0}, {"feature": "upload_packets", "source_eta_squared": 0.0}]`

Source predictability: `{"reason": "Only one dataset source is present.", "status": "skipped"}`

## 4. Suspicious-feature ablation

`{"removed_features": ["mean_burst_size", "mean_interarrival_time", "packets_per_second", "std_packet_size", "upload_download_ratio"], "retained_feature_order": ["burst_count", "bytes_per_second", "download_bytes", "download_packets", "idle_time_ratio", "max_packet_size", "mean_packet_size", "median_packet_size", "min_packet_size", "p25_packet_size", "p75_packet_size", "p95_packet_size", "packet_count", "std_interarrival_time", "total_bytes", "upload_packets"], "status": "complete", "test_metrics": {"accuracy": 1.0, "confusion_matrix": [[5, 0, 0, 0, 0, 0, 0], [0, 5, 0, 0, 0, 0, 0], [0, 0, 5, 0, 0, 0, 0], [0, 0, 0, 5, 0, 0, 0], [0, 0, 0, 0, 5, 0, 0], [0, 0, 0, 0, 0, 5, 0], [0, 0, 0, 0, 0, 0, 5]], "confusion_matrix_labels": ["email", "file_transfer", "icmp", "messaging", "video", "voip", "web"], "macro_f1": 1.0, "per_class": {"email": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "file_transfer": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "icmp": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "messaging": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "video": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "voip": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "web": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}}, "weighted_f1": 1.0}}`

## 5. Per-source and per-class performance

Per source: `{"ipsec-pcap-lab": {"accuracy": 1.0, "confusion_matrix": [[5, 0, 0, 0, 0, 0, 0], [0, 5, 0, 0, 0, 0, 0], [0, 0, 5, 0, 0, 0, 0], [0, 0, 0, 5, 0, 0, 0], [0, 0, 0, 0, 5, 0, 0], [0, 0, 0, 0, 0, 5, 0], [0, 0, 0, 0, 0, 0, 5]], "confusion_matrix_labels": ["email", "file_transfer", "icmp", "messaging", "video", "voip", "web"], "macro_f1": 1.0, "per_class": {"email": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "file_transfer": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "icmp": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "messaging": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "video": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "voip": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "web": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}}, "weighted_f1": 1.0}}`

Per class: `{"email": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "file_transfer": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "icmp": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "messaging": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "video": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "voip": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}, "web": {"f1": 1.0, "precision": 1.0, "recall": 1.0, "support": 5}}`

## Label/source association

Normalized mutual information: 0.0
